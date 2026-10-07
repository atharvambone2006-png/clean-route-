import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import * as authService from '../services/authService.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const dbPath = process.env.DB_PATH || join(__dirname, '../cleanroute.db');
const db = new Database(dbPath);

// Enable Foreign Key Enforcement in SQLite
db.pragma('foreign_keys = ON');

/**
 * Initialize Database Tables and Indexes
 */
export function initDatabase() {
    console.log(`[DB INIT] Initializing SQLite database at: ${dbPath}`);

    db.exec(`
        -- 1. Organizations Master Table
        CREATE TABLE IF NOT EXISTS organizations (
            organization_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            code TEXT UNIQUE NOT NULL,
            category TEXT NOT NULL,
            whitelisted_domains TEXT NOT NULL, -- JSON array
            jurisdiction_wards TEXT NOT NULL,  -- JSON array
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        -- 2. Extended Users Table (Unified Identity Principal)
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            phone_hash TEXT UNIQUE NOT NULL,
            phone_encrypted TEXT NOT NULL,
            email TEXT UNIQUE,
            password_hash TEXT,
            primary_role TEXT NOT NULL DEFAULT 'ROLE_CITIZEN',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        -- 3. Polymorphic Authority Profile Extension Table
        CREATE TABLE IF NOT EXISTS authority_profiles (
            profile_id TEXT PRIMARY KEY,
            user_id TEXT UNIQUE NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            organization_id TEXT REFERENCES organizations(organization_id),
            official_title TEXT NOT NULL,
            badge_number TEXT,
            verification_status TEXT NOT NULL DEFAULT 'PENDING_EMAIL',
            reviewed_by TEXT REFERENCES users(user_id),
            reviewed_at TEXT,
            rejection_reason TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        -- 4. Verification Document Artifacts Table
        CREATE TABLE IF NOT EXISTS authority_verification_documents (
            document_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            document_type TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_name TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            uploaded_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        -- 5. Persistent Reports Table (with organization_id FK and ward_name)
        CREATE TABLE IF NOT EXISTS reports (
            report_id TEXT PRIMARY KEY,
            location_id TEXT NOT NULL,
            ward_name TEXT NOT NULL,
            address TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            categories TEXT, -- JSON array
            status TEXT NOT NULL DEFAULT 'SUBMITTED',
            created_by_phone_hash TEXT NOT NULL,
            created_by_phone_encrypted TEXT NOT NULL,
            organization_id TEXT REFERENCES organizations(organization_id),
            assigned_department_id TEXT,
            assigned_department_name TEXT,
            assigned_officer_id TEXT,
            assigned_officer_name TEXT,
            images TEXT, -- JSON array
            upvotes INTEGER DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT
        );

        -- 6. Immutable Security Audit Log Table
        CREATE TABLE IF NOT EXISTS security_audit_logs (
            audit_id TEXT PRIMARY KEY,
            actor_id TEXT NOT NULL REFERENCES users(user_id),
            actor_email TEXT NOT NULL,
            action TEXT NOT NULL,
            target_resource TEXT,
            ip_address TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        -- INDEXES
        CREATE INDEX IF NOT EXISTS idx_reports_ward ON reports(ward_name);
        CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
        CREATE INDEX IF NOT EXISTS idx_authority_profiles_status ON authority_profiles(verification_status);
        CREATE INDEX IF NOT EXISTS idx_authority_profiles_org ON authority_profiles(organization_id);
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_users_phone_hash ON users(phone_hash);
    `);

    seedInitialData();
}

/**
 * Seed Initial Organizations and Super-Admin Account from Environment Config
 */
function seedInitialData() {
    const orgCount = db.prepare('SELECT COUNT(*) as count FROM organizations').get().count;

    if (orgCount === 0) {
        console.log('[DB SEED] Seeding master organizations...');
        const insertOrg = db.prepare(`
            INSERT INTO organizations (organization_id, name, code, category, whitelisted_domains, jurisdiction_wards)
            VALUES (?, ?, ?, ?, ?, ?)
        `);

        insertOrg.run(
            'dept_sanitation_01',
            'Sanitation & Solid Waste Management',
            'SWM_NAGPUR',
            'GOVERNMENT',
            JSON.stringify(['nagpurmc.gov.in', 'cpcb.gov.in', 'cleanroute.org']),
            JSON.stringify(['Ward 4', 'Ward 12', 'Sitabuldi', 'Ram Nagar', 'Gokulpeth', 'Bhandewadi'])
        );

        insertOrg.run(
            'dept_pwd_02',
            'Public Works Department (PWD)',
            'PWD_NAGPUR',
            'GOVERNMENT',
            JSON.stringify(['nagpurmc.gov.in', 'pwd.gov.in']),
            JSON.stringify(['Ward 4', 'Ward 12', 'Sitabuldi', 'Central Park', 'Ward 24'])
        );

        insertOrg.run(
            'dept_biowaste_03',
            'Bio-Waste & Organic Composting Board',
            'BIO_NAGPUR',
            'NGO',
            JSON.stringify(['hasirudala.in', 'saahaszerowaste.com']),
            JSON.stringify(['Ward 12', 'Gokulpeth', 'Ram Nagar'])
        );
    }

    const adminEmail = process.env.SUPERADMIN_EMAIL || 'admin@nagpurmc.gov.in';
    const adminPass = process.env.SUPERADMIN_PASSWORD || 'AdminPass123!';

    const existingUser = db.prepare('SELECT user_id, password_hash FROM users WHERE LOWER(email) = LOWER(?)').get(adminEmail);

    if (!existingUser) {
        console.log('[DB SEED] Seeding Super-Admin user from .env credentials...');
        const adminId = 'usr_superadmin_001';
        const phone = '+919822000000';
        const phoneHash = authService.computePhoneHash(phone);
        const phoneEncrypted = JSON.stringify(authService.encryptPhone(phone));

        // Use bcrypt for secure password hashing (12 salt rounds)
        const passwordHash = bcrypt.hashSync(adminPass, 12);

        const insertUser = db.prepare(`
            INSERT INTO users (user_id, phone_hash, phone_encrypted, email, password_hash, primary_role)
            VALUES (?, ?, ?, ?, ?, ?)
        `);
        insertUser.run(adminId, phoneHash, phoneEncrypted, adminEmail, passwordHash, 'ROLE_SYSTEM_ADMIN');

        const insertProfile = db.prepare(`
            INSERT INTO authority_profiles (profile_id, user_id, organization_id, official_title, badge_number, verification_status, reviewed_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        `);
        insertProfile.run('prof_superadmin_001', adminId, 'dept_sanitation_01', 'Chief Municipal Administrator', 'BADGE-001', 'VERIFIED');
    } else {
        const isPasswordValid = existingUser.password_hash && bcrypt.compareSync(adminPass, existingUser.password_hash);
        if (!isPasswordValid) {
            console.log('[DB SEED] Updating Super-Admin password hash to sync with current .env credentials...');
            const newBcryptHash = bcrypt.hashSync(adminPass, 12);
            db.prepare('UPDATE users SET password_hash = ? WHERE user_id = ?').run(newBcryptHash, existingUser.user_id);
        }
    }

    seedSampleReports();
}

/**
 * Seed 10 realistic Nagpur sample reports covering SUBMITTED, ASSIGNED, IN_PROGRESS, and RESOLVED statuses
 * across Sanitation (SWM), PWD, and Bio-Waste organizations.
 */
function seedSampleReports() {
    const hasSampleReports = db.prepare("SELECT COUNT(*) as count FROM reports WHERE report_id LIKE 'REP-NAG-%'").get().count;

    if (hasSampleReports === 0) {
        console.log('[DB SEED] Seeding 10 realistic Nagpur sample reports across wards and organizations...');

        const insertReport = db.prepare(`
            INSERT INTO reports (
                report_id, location_id, ward_name, address, description, category, categories,
                status, created_by_phone_hash, created_by_phone_encrypted, organization_id,
                assigned_department_id, assigned_department_name, assigned_officer_id,
                assigned_officer_name, images, upvotes, created_at, updated_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, datetime('now'), ?
            )
        `);

        const sampleReports = [
            {
                id: 'REP-NAG-SWM-001',
                loc: 'LOC_SITABULDI_METRO',
                ward: 'Sitabuldi Ward 18',
                addr: 'Sitabuldi Main Market Entrance near Metro Gate 2, Nagpur',
                desc: 'Commercial plastic waste accumulation and discarded single-use cups blocking pavement walk.',
                cat: 'plastic',
                cats: JSON.stringify(['plastic', 'paper']),
                phone: '+919822012345',
                status: 'SUBMITTED',
                orgId: 'dept_sanitation_01',
                deptName: 'Sanitation & Solid Waste Management',
                officerId: null,
                officerName: null,
                assignedAt: null,
                updatedAt: null
            },
            {
                id: 'REP-NAG-SWM-002',
                loc: 'LOC_BHANDEWADI_ROAD',
                ward: 'Bhandewadi Ward 24',
                addr: 'Bhandewadi Dump Access Road near Power Substation, Nagpur',
                desc: 'Overflowing roadside garbage pile spilling into stormwater drain.',
                cat: 'plastic',
                cats: JSON.stringify(['plastic', 'other']),
                phone: '+919822098765',
                status: 'ASSIGNED',
                orgId: 'dept_sanitation_01',
                deptName: 'Sanitation & Solid Waste Management',
                officerId: 'usr_superadmin_001',
                officerName: 'Chief Inspector R. Sharma',
                assignedAt: new Date().toISOString(),
                updatedAt: null
            },
            {
                id: 'REP-NAG-SWM-003',
                loc: 'LOC_GOKULPETH_MARKET',
                ward: 'Gokulpeth Ward 12',
                addr: 'Gokulpeth Vegetable Market Lane 3, Nagpur',
                desc: 'Discarded plastic crates and paper packaging behind vegetable vendor stalls.',
                cat: 'paper',
                cats: JSON.stringify(['paper', 'plastic']),
                phone: '+919876543210',
                status: 'IN_PROGRESS',
                orgId: 'dept_sanitation_01',
                deptName: 'Sanitation & Solid Waste Management',
                officerId: 'usr_superadmin_001',
                officerName: 'Chief Inspector R. Sharma',
                assignedAt: new Date().toISOString(),
                updatedAt: null
            },
            {
                id: 'REP-NAG-SWM-004',
                loc: 'LOC_RAMNAGAR_SQ',
                ward: 'Ram Nagar Ward 14',
                addr: 'Ram Nagar Square beside Public Water Tank, Nagpur',
                desc: 'Litter cleared and area disinfected by morning sanitary squad.',
                cat: 'plastic',
                cats: JSON.stringify(['plastic']),
                phone: '+919811223344',
                status: 'RESOLVED',
                orgId: 'dept_sanitation_01',
                deptName: 'Sanitation & Solid Waste Management',
                officerId: 'usr_superadmin_001',
                officerName: 'Chief Inspector R. Sharma',
                assignedAt: new Date().toISOString(),
                updatedAt: new Date(Date.now() - 3600000).toISOString()
            },
            {
                id: 'REP-NAG-PWD-001',
                loc: 'LOC_CENTRAL_PARK_RD',
                ward: 'Central Park Ward 4',
                addr: 'Central Park Road near PWD Inspection Bungalow, Nagpur',
                desc: 'Discarded metal road barriers and construction iron mesh blocking pedestrian path.',
                cat: 'metal',
                cats: JSON.stringify(['metal', 'hazard']),
                phone: '+919833445566',
                status: 'ASSIGNED',
                orgId: 'dept_pwd_02',
                deptName: 'Public Works Department (PWD)',
                officerId: 'off_pwd_02',
                officerName: 'Engineer V. Kulkarni',
                assignedAt: new Date().toISOString(),
                updatedAt: null
            },
            {
                id: 'REP-NAG-PWD-002',
                loc: 'LOC_WARD24_BRIDGE',
                ward: 'Ward 24 Railway Flyover',
                addr: 'Ward 24 Railway Overbridge South Approach, Nagpur',
                desc: 'Exposed rebar and damaged concrete guardrails posing safety risk.',
                cat: 'hazard',
                cats: JSON.stringify(['hazard', 'metal']),
                phone: '+919844556677',
                status: 'IN_PROGRESS',
                orgId: 'dept_pwd_02',
                deptName: 'Public Works Department (PWD)',
                officerId: 'off_pwd_02',
                officerName: 'Engineer V. Kulkarni',
                assignedAt: new Date().toISOString(),
                updatedAt: null
            },
            {
                id: 'REP-NAG-PWD-003',
                loc: 'LOC_WARD4_CIRCLE',
                ward: 'Ward 4 Square',
                addr: 'Ward 4 Traffic Circle near High Court Road, Nagpur',
                desc: 'Steel fencing repaired and scrap material cleared.',
                cat: 'metal',
                cats: JSON.stringify(['metal']),
                phone: '+919855667788',
                status: 'RESOLVED',
                orgId: 'dept_pwd_02',
                deptName: 'Public Works Department (PWD)',
                officerId: 'off_pwd_02',
                officerName: 'Engineer V. Kulkarni',
                assignedAt: new Date().toISOString(),
                updatedAt: new Date(Date.now() - 7200000).toISOString()
            },
            {
                id: 'REP-NAG-BIO-001',
                loc: 'LOC_GOKULPETH_BIO',
                ward: 'Gokulpeth Ward 12',
                addr: 'Gokulpeth Wholesale Fruit Market Waste Pit, Nagpur',
                desc: 'Accumulated rotten fruit and organic waste generating odor; needs composting collection.',
                cat: 'organic',
                cats: JSON.stringify(['organic']),
                phone: '+919866778899',
                status: 'SUBMITTED',
                orgId: 'dept_biowaste_03',
                deptName: 'Bio-Waste & Organic Composting Board',
                officerId: null,
                officerName: null,
                assignedAt: null,
                updatedAt: null
            },
            {
                id: 'REP-NAG-BIO-002',
                loc: 'LOC_RAMNAGAR_BIO',
                ward: 'Ram Nagar Ward 14',
                addr: 'Ram Nagar Community Garden Compost Trench, Nagpur',
                desc: 'Garden leaf litter and wet organic waste collected for aerobic composting.',
                cat: 'organic',
                cats: JSON.stringify(['organic']),
                phone: '+919877889900',
                status: 'IN_PROGRESS',
                orgId: 'dept_biowaste_03',
                deptName: 'Bio-Waste & Organic Composting Board',
                officerId: 'off_bio_03',
                officerName: 'Coordinator S. Deshmukh',
                assignedAt: new Date().toISOString(),
                updatedAt: null
            },
            {
                id: 'REP-NAG-BIO-003',
                loc: 'LOC_WARD12_COMPOST',
                ward: 'Ward 12 Park',
                addr: 'Ward 12 Botanical Nursery Compost Yard, Nagpur',
                desc: 'Wet organic waste processed into bio-fertilizer batch #42.',
                cat: 'organic',
                cats: JSON.stringify(['organic']),
                phone: '+919888990011',
                status: 'RESOLVED',
                orgId: 'dept_biowaste_03',
                deptName: 'Bio-Waste & Organic Composting Board',
                officerId: 'off_bio_03',
                officerName: 'Coordinator S. Deshmukh',
                assignedAt: new Date().toISOString(),
                updatedAt: new Date(Date.now() - 10800000).toISOString()
            }
        ];

        for (const r of sampleReports) {
            const phoneHash = authService.computePhoneHash(r.phone);
            const phoneEnc = JSON.stringify(authService.encryptPhone(r.phone));

            insertReport.run(
                r.id, r.loc, r.ward, r.addr, r.desc, r.cat, r.cats,
                r.status, phoneHash, phoneEnc, r.orgId,
                r.orgId, r.deptName, r.officerId,
                r.officerName, JSON.stringify([]), 3, r.updatedAt
            );
        }
        console.log(`[DB SEED] Successfully seeded ${sampleReports.length} sample reports into cleanroute.db`);
    }
}

initDatabase();
export default db;
