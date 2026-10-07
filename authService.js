import crypto from 'crypto';

// System secrets (in production, loaded from environment variables or KMS)
const PEPPER_KEY = process.env.PHONE_PEPPER_KEY || 'cleanroute-kms-pepper-secret-key-32bytes!';
const ENCRYPTION_KEY = crypto.scryptSync(process.env.PHONE_ENCRYPT_SECRET || 'cleanroute-encryption-secret-key', 'salt', 32);

// Ephemeral memory stores (In production, backed by Redis)
const otpSessions = new Map();
const phoneRateLimits = new Map();
const ipRateLimits = new Map();
const phoneCooldowns = new Map();
const verificationTokens = new Map();

/**
 * Normalize phone number to E.164 format.
 * Defaults to +1 if country code missing for standard 10-digit numbers.
 */
export function normalizePhone(rawPhone) {
    if (!rawPhone || typeof rawPhone !== 'string') {
        const error = new Error('Mobile phone number is required.');
        error.statusCode = 400;
        throw error;
    }

    let cleaned = rawPhone.trim().replace(/[^\d+]/g, '');

    if (cleaned.startsWith('0')) {
        cleaned = cleaned.replace(/^0+/, '');
    }

    if (!cleaned.startsWith('+')) {
        if (cleaned.startsWith('91') && cleaned.length === 12) {
            cleaned = '+' + cleaned;
        } else {
            cleaned = '+91' + cleaned;
        }
    }

    const indianMobileRegex = /^\+91[6-9]\d{9}$/;
    if (!indianMobileRegex.test(cleaned)) {
        const error = new Error('Invalid Indian mobile number. Must be a valid 10-digit number starting with 6, 7, 8, or 9 (e.g. +919822012345).');
        error.statusCode = 400;
        throw error;
    }

    return cleaned;
}

/**
 * Generate deterministic HMAC-SHA256 blind index for phone lookup.
 */
export function computePhoneHash(e164Phone) {
    return crypto.createHmac('sha256', PEPPER_KEY).update(e164Phone).digest('hex');
}

/**
 * AES-256-GCM Encryption for PII at rest.
 */
export function encryptPhone(e164Phone) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(e164Phone, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return {
        ciphertext: encrypted,
        iv: iv.toString('hex'),
        authTag
    };
}

/**
 * AES-256-GCM Decryption.
 */
export function decryptPhone(encryptedData) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, Buffer.from(encryptedData.iv, 'hex'));
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    let decrypted = decipher.update(encryptedData.ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

/**
 * Request an OTP session with multi-layer rate limiting.
 */
export function requestOTP(rawPhone, clientIP) {
    const phone = normalizePhone(rawPhone);
    const phoneHash = computePhoneHash(phone);
    const now = Date.now();

    // 1. IP Rate Limit: Max 10 requests / min
    const ipHistory = ipRateLimits.get(clientIP) || [];
    const validIpHistory = ipHistory.filter(t => now - t < 60000);
    if (validIpHistory.length >= 10) {
        const error = new Error('Too many OTP requests from this IP address. Please wait a minute.');
        error.statusCode = 429;
        error.retryAfter = 60;
        throw error;
    }
    validIpHistory.push(now);
    ipRateLimits.set(clientIP, validIpHistory);

    // 2. Cooldown Check: Minimum 60 seconds between resends per phone
    const lastSent = phoneCooldowns.get(phoneHash);
    if (lastSent && now - lastSent < 60000) {
        const remaining = Math.ceil((60000 - (now - lastSent)) / 1000);
        const error = new Error(`Please wait ${remaining} seconds before requesting another verification code.`);
        error.statusCode = 429;
        error.retryAfter = remaining;
        throw error;
    }

    // 3. Phone Sliding Window: Max 3 OTPs / 15 mins
    const phoneHistory = phoneRateLimits.get(phoneHash) || [];
    const validPhoneHistory = phoneHistory.filter(t => now - t < 15 * 60000);
    if (validPhoneHistory.length >= 3) {
        const oldest = validPhoneHistory[0];
        const remaining = Math.ceil((15 * 60000 - (now - oldest)) / 1000);
        const error = new Error(`Maximum OTP request limit reached for this number. Retry in ${Math.ceil(remaining / 60)} minutes.`);
        error.statusCode = 429;
        error.retryAfter = remaining;
        throw error;
    }
    validPhoneHistory.push(now);
    phoneRateLimits.set(phoneHash, validPhoneHistory);
    phoneCooldowns.set(phoneHash, now);

    // Generate 6-digit numeric OTP and Session ID
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const otpDigest = crypto.createHash('sha256').update(otpCode).digest('hex');
    const sessionId = `sess_${crypto.randomUUID()}`;

    const session = {
        sessionId,
        phoneHash,
        encryptedPhone: encryptPhone(phone),
        otpDigest,
        attemptsLeft: 5,
        expiresAt: now + 5 * 60000, // 5 minutes
        status: 'ACTIVE'
    };

    otpSessions.set(sessionId, session);

    console.log(`[DEV OTP DISPATCH] Phone: ${phone} | Session: ${sessionId} | Code: ${otpCode}`);

    return {
        sessionId,
        expiresInSeconds: 300,
        resendCooldownSeconds: 60,
        devOtpCode: otpCode
    };
}

/**
 * Verify an OTP code and return a single-use verification token.
 */
export function verifyOTP(sessionId, otpCode) {
    const now = Date.now();
    const session = otpSessions.get(sessionId);

    if (!session || session.status !== 'ACTIVE') {
        const error = new Error('Verification session not found or inactive.');
        error.statusCode = 410;
        throw error;
    }

    if (now > session.expiresAt) {
        session.status = 'EXPIRED';
        const error = new Error('OTP session has expired. Please request a new code.');
        error.statusCode = 410;
        throw error;
    }

    const providedDigest = crypto.createHash('sha256').update((otpCode || '').trim()).digest('hex');

    if (providedDigest !== session.otpDigest) {
        session.attemptsLeft -= 1;
        if (session.attemptsLeft <= 0) {
            session.status = 'BLOCKED';
            const error = new Error('Maximum verification attempts exceeded. Session terminated.');
            error.statusCode = 410;
            throw error;
        }
        const error = new Error(`Invalid verification code. ${session.attemptsLeft} attempt(s) remaining.`);
        error.statusCode = 400;
        error.attemptsLeft = session.attemptsLeft;
        throw error;
    }

    session.status = 'VERIFIED';
    otpSessions.delete(sessionId);

    const tokenJti = `tok_${crypto.randomUUID()}`;
    const tokenData = {
        jti: tokenJti,
        phoneHash: session.phoneHash,
        encryptedPhone: session.encryptedPhone,
        expiresAt: now + 10 * 60000, // 10 minutes
        consumed: false
    };

    verificationTokens.set(tokenJti, tokenData);

    return {
        verificationToken: tokenJti,
        expiresInSeconds: 600
    };
}

/**
 * Validate and consume a single-use verification token.
 */
export function consumeVerificationToken(tokenJti) {
    const token = verificationTokens.get(tokenJti);
    if (!token) {
        const error = new Error('Invalid or missing verification token.');
        error.statusCode = 401;
        throw error;
    }
    if (token.consumed) {
        const error = new Error('Verification token has already been consumed.');
        error.statusCode = 401;
        throw error;
    }
    if (Date.now() > token.expiresAt) {
        verificationTokens.delete(tokenJti);
        const error = new Error('Verification token has expired. Please verify your phone number again.');
        error.statusCode = 401;
        throw error;
    }

    token.consumed = true;
    return token;
}
