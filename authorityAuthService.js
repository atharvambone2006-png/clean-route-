import crypto from 'crypto';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import db from '../db/index.js';
import * as authService from './authService.js';

dotenv.config();

const JWT_SECRET = process.env.AUTHORITY_JWT_SECRET || 'cleanroute-authority-jwt-secret-key-2026!';

// Sliding-window rate limit store for Authority Registration
const regRateLimitStore = new Map();
const REG_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const REG_MAX_ATTEMPTS = 5; // Max 5 registration attempts per IP per 15 minutes

export function checkRegistrationRateLimit(clientIP) {
    const now = Date.now();
    const key = `reg_${clientIP}`;
    const record = regRateLimitStore.get(key) || { attempts: [], lockoutUntil: 0 };

    if (record.lockoutUntil > now) {
        const remainingSeconds = Math.ceil((record.lockoutUntil - now) / 1000);
        const error = new Error(`Registration rate limit exceeded. Please wait ${remainingSeconds}s before trying again.`);
        error.statusCode = 429;
        throw error;
    }

    record.attempts = record.attempts.filter(timestamp => now - timestamp < REG_RATE_LIMIT_WINDOW_MS);

    if (record.attempts.length >= REG_MAX_ATTEMPTS) {
        record.lockoutUntil = now + REG_RATE_LIMIT_WINDOW_MS;
        regRateLimitStore.set(key, record);
        const error = new Error('Too many registration requests. IP locked out for 15 minutes.');
        error.statusCode = 429;
        throw error;
    }

    record.attempts.push(now);
    regRateLimitStore.set(key, record);
}

// Whitelisted organizational email domains
const APPROVED_DOMAINS = new Set([
    'nagpurmc.gov.in',
    'cpcb.gov.in',
    'cleanroute.org',
    'hasirudala.in',
    'saahaszerowaste.com',
    'gov.in'
]);

export function isDomainAllowed(email) {
    if (!email || !email.includes('@')) return false;
    const domain = email.split('@')[1].toLowerCase().trim();
    if (APPROVED_DOMAINS.has(domain)) return true;
    return Array.from(APPROVED_DOMAINS).some(d => domain.endsWith('.' + d) || domain === d);
}

/**
 * Hash password securely using bcrypt (12 salt rounds)
 */
export function hashPassword(password) {
    return bcrypt.hashSync(password, 12);
}

/**
 * Verify password against stored bcrypt hash (with PBKDF2 legacy support)
 */
export function verifyPassword(password, storedHash) {
    if (!storedHash) return false;
    if (storedHash.startsWith('$2a$') || storedHash.startsWith('$2b$')) {
        return bcrypt.compareSync(password, storedHash);
    }
    // Fallback legacy PBKDF2 check
    if (storedHash.includes(':')) {
        const [salt, originalHash] = storedHash.split(':');
        const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
        return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(originalHash));
    }
    return false;
}

export function generateAuthToken(userProfile) {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const payload = Buffer.from(JSON.stringify({
        sub: userProfile.user_id,
        email: userProfile.email,
        name: userProfile.full_name || 'Authority Officer',
        role: userProfile.primary_role,
        verification_status: userProfile.verification_status,
        organization_id: userProfile.organization_id,
        organization_name: userProfile.organization_name,
        iat: now,
        exp: now + 15 * 60 // 15 min TTL
    })).toString('base64url');

    const signature = crypto.createHmac('sha256', JWT_SECRET)
        .update(`${header}.${payload}`)
        .digest('base64url');

    return {
        accessToken: `${header}.${payload}.${signature}`,
        refreshToken: `ref_${crypto.randomUUID()}`,
        expiresInSeconds: 900
    };
}

export function verifyAuthToken(token) {
    if (!token || !token.includes('.')) {
        const error = new Error('Missing or malformed Authorization token.');
        error.statusCode = 401;
        throw error;
    }
    const parts = token.split('.');
    if (parts.length !== 3) {
        const error = new Error('Invalid token structure.');
        error.statusCode = 401;
        throw error;
    }
    const [header, payload, signature] = parts;
    const expectedSig = crypto.createHmac('sha256', JWT_SECRET)
        .update(`${header}.${payload}`)
        .digest('base64url');

    if (signature !== expectedSig) {
        const error = new Error('Token signature validation failed.');
        error.statusCode = 401;
        throw error;
    }

    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (Math.floor(Date.now() / 1000) > claims.exp) {
        const error = new Error('Authorization token has expired. Please login again.');
        error.statusCode = 401;
        throw error;
    }

    return claims;
}

/**
 * Register Authority (Unified User + Authority Profile in SQLite)
 */
export function registerAuthority({ email, password, fullName, phoneNumber, organizationId, role, clientIP = '127.0.0.1' }) {
    checkRegistrationRateLimit(clientIP);

    const cleanEmail = (email || '').toLowerCase().trim();

    if (!isDomainAllowed(cleanEmail)) {
        const error = new Error(`Email domain @${cleanEmail.split('@')[1] || ''} is not an authorized government or partner organization domain.`);
        error.statusCode = 400;
        throw error;
    }

    const existingUser = db.prepare('SELECT user_id FROM users WHERE email = ?').get(cleanEmail);
    if (existingUser) {
        const error = new Error('An authority account with this email already exists.');
        error.statusCode = 409;
        throw error;
    }

    const userId = `usr_${crypto.randomUUID()}`;
    const profileId = `prof_${crypto.randomUUID()}`;
    const e164 = authService.normalizePhone(phoneNumber || '+919822012345');
    const phoneHash = authService.computePhoneHash(e164);
    const phoneEncrypted = JSON.stringify(authService.encryptPhone(e164));
    const passHash = hashPassword(password || 'OfficerPass123!');
    const targetRole = role || 'ROLE_AUTHORITY_MEMBER';
    const targetOrgId = organizationId || 'dept_sanitation_01';

    const insertUser = db.prepare(`
        INSERT INTO users (user_id, phone_hash, phone_encrypted, email, password_hash, primary_role)
        VALUES (?, ?, ?, ?, ?, ?)
    `);

    const insertProfile = db.prepare(`
        INSERT INTO authority_profiles (profile_id, user_id, organization_id, official_title, badge_number, verification_status)
        VALUES (?, ?, ?, ?, ?, 'PENDING_REVIEW')
    `);

    db.transaction(() => {
        insertUser.run(userId, phoneHash, phoneEncrypted, cleanEmail, passHash, targetRole);
        insertProfile.run(profileId, userId, targetOrgId, 'Field Inspector', 'BADGE-' + Math.floor(100 + Math.random() * 900));
    })();

    return {
        user_id: userId,
        email: cleanEmail,
        full_name: fullName,
        role: targetRole,
        verification_status: 'PENDING_REVIEW'
    };
}

/**
 * Login Authority User via SQLite
 */
export function loginAuthority({ email, password }) {
    const cleanEmail = (email || '').toLowerCase().trim();

    const user = db.prepare(`
        SELECT u.user_id, u.email, u.password_hash, u.primary_role,
               ap.profile_id, ap.official_title, ap.verification_status,
               o.organization_id, o.name as organization_name
        FROM users u
        LEFT JOIN authority_profiles ap ON u.user_id = ap.user_id
        LEFT JOIN organizations o ON ap.organization_id = o.organization_id
        WHERE LOWER(u.email) = LOWER(?)
    `).get(cleanEmail);

    if (!user) {
        console.warn(`[AUTH SERVICE] Login attempt failed: Account not found for email "${cleanEmail}"`);
        const error = new Error('Invalid email or credentials.');
        error.statusCode = 401;
        throw error;
    }

    if (!verifyPassword(password, user.password_hash)) {
        console.warn(`[AUTH SERVICE] Login attempt failed: Password mismatch for user "${user.email}" (${user.user_id})`);
        const error = new Error('Invalid email or credentials.');
        error.statusCode = 401;
        throw error;
    }

    const isSystemAdmin = ['ROLE_SYSTEM_ADMIN', 'SUPERADMIN', 'MUNICIPAL_ADMIN'].includes(user.primary_role);
    if (user.verification_status !== 'VERIFIED' && !isSystemAdmin) {
        console.warn(`[AUTH SERVICE] Login attempt blocked: Unverified status "${user.verification_status || 'PENDING'}" for user "${user.email}" (${user.user_id})`);
        const error = new Error(`Account verification status is ${user.verification_status || 'PENDING'}. Access requires administrator review and approval.`);
        error.statusCode = 403;
        throw error;
    }

    const tokens = generateAuthToken(user);
    console.log(`[AUTH SERVICE] Institutional login successful for user "${user.email}" (${user.user_id}) - Role: ${user.primary_role}`);
    return {
        authority: {
            authority_id: user.user_id,
            email: user.email,
            full_name: user.official_title,
            role: user.primary_role,
            verification_status: user.verification_status,
            department_id: user.organization_id,
            department_name: user.organization_name
        },
        tokens
    };
}

/**
 * Admin Account Approval Handler (SQLite)
 */
export function approveAccount(adminClaims, targetUserId) {
    if (!['ROLE_SYSTEM_ADMIN', 'ROLE_AUTHORITY_ADMIN', 'SUPERADMIN', 'MUNICIPAL_ADMIN'].includes(adminClaims.role)) {
        const error = new Error('Access denied. Administrator privileges required to approve authority accounts.');
        error.statusCode = 403;
        throw error;
    }

    const profile = db.prepare('SELECT profile_id FROM authority_profiles WHERE user_id = ?').get(targetUserId);
    if (!profile) {
        const error = new Error('Target authority profile not found.');
        error.statusCode = 404;
        throw error;
    }

    db.prepare(`
        UPDATE authority_profiles
        SET verification_status = 'VERIFIED', reviewed_by = ?, reviewed_at = datetime('now')
        WHERE user_id = ?
    `).run(adminClaims.sub, targetUserId);

    db.prepare(`
        UPDATE users
        SET primary_role = 'ROLE_AUTHORITY_MEMBER'
        WHERE user_id = ? AND primary_role = 'ROLE_CITIZEN'
    `).run(targetUserId);

    return { target_user_id: targetUserId, new_status: 'VERIFIED' };
}

/**
 * Get all authority accounts from SQLite
 */
export function getAllAuthorityAccounts() {
    return db.prepare(`
        SELECT u.user_id as authority_id, u.email, ap.official_title as full_name,
               u.primary_role as role, ap.verification_status as status,
               o.name as department_name, u.created_at
        FROM users u
        INNER JOIN authority_profiles ap ON u.user_id = ap.user_id
        LEFT JOIN organizations o ON ap.organization_id = o.organization_id
        ORDER BY u.created_at DESC
    `).all();
}
