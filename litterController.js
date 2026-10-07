import * as authService from '../services/authService.js';
import * as idGeneratorService from '../services/idGeneratorService.js';
import * as dedupIdempotencyService from '../services/dedupIdempotencyService.js';
import * as routingEngineService from '../services/routingEngineService.js';
import db from '../db/index.js';

const allowedCategories = new Set(['plastic', 'metal', 'organic', 'paper', 'glass', 'other']);

function normalizeCategories(categoryInput) {
    const values = [];

    if (Array.isArray(categoryInput)) {
        categoryInput.forEach((entry) => {
            if (typeof entry === 'string') {
                const cleaned = entry.trim().toLowerCase();
                if (cleaned) values.push(cleaned);
            }
        });
    } else if (typeof categoryInput === 'string') {
        const cleaned = categoryInput.trim().toLowerCase();
        if (cleaned) values.push(cleaned);
    }

    return values.filter((value) => allowedCategories.has(value));
}

function mapRowToReport(row) {
    if (!row) return null;
    let categories = [row.category];
    try {
        if (row.categories) categories = typeof row.categories === 'string' ? JSON.parse(row.categories) : row.categories;
    } catch (e) {}

    let phoneEncrypted = null;
    try {
        if (row.created_by_phone_encrypted) {
            phoneEncrypted = typeof row.created_by_phone_encrypted === 'string' ? JSON.parse(row.created_by_phone_encrypted) : row.created_by_phone_encrypted;
        }
    } catch (e) {
        phoneEncrypted = { ciphertext: row.created_by_phone_encrypted, iv: '', authTag: '' };
    }

    let images = [];
    try {
        if (row.images) images = typeof row.images === 'string' ? JSON.parse(row.images) : row.images;
    } catch (e) {}

    return {
        id: row.report_id,
        report_id: row.report_id,
        location_id: row.location_id,
        ward_name: row.ward_name,
        address: row.address,
        description: row.description,
        category: row.category,
        categories,
        status: row.status,
        upvotes: row.upvotes || 0,
        phone_hash: row.created_by_phone_hash,
        phone_encrypted: phoneEncrypted,
        organization_id: row.organization_id,
        assigned_department_id: row.assigned_department_id,
        assigned_department_name: row.assigned_department_name,
        assigned_officer_id: row.assigned_officer_id,
        assigned_officer_name: row.assigned_officer_name,
        images,
        timestamp: row.created_at,
        created_at: row.created_at,
        updated_at: row.updated_at
    };
}

/**
 * Secondary Lookup Query: Retrieve reports tied to a specific verified phone_hash
 */
export function getReportsByPhoneHash(phoneHash) {
    const rows = db.prepare('SELECT * FROM reports WHERE created_by_phone_hash = ? ORDER BY created_at DESC').all(phoneHash);
    return rows.map(mapRowToReport);
}

/**
 * Submit a new litter report with OTP Verification, Location-Bound ID, and SQLite persistence
 */
export const submitReport = (req, res) => {
    try {
        const idempotencyKey = req.headers['x-idempotency-key'];

        // 1. Idempotency Check
        if (idempotencyKey) {
            const cachedResponse = dedupIdempotencyService.getIdempotentResponse(idempotencyKey);
            if (cachedResponse && cachedResponse.status === 'COMPLETED') {
                return res.status(cachedResponse.statusCode).json(cachedResponse.payload);
            }
            dedupIdempotencyService.registerIdempotencyStart(idempotencyKey);
        }

        // 2. Extract Authorization Verification Token
        const authHeader = req.headers['authorization'];
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                error: 'UNAUTHORIZED',
                message: 'Authorization Bearer token containing a verified OTP token is required.'
            });
        }
        const verificationTokenJti = authHeader.substring(7).trim();

        // 3. Consume Single-Use Verification Token
        let tokenData;
        try {
            tokenData = authService.consumeVerificationToken(verificationTokenJti);
        } catch (authError) {
            return res.status(authError.statusCode || 401).json({
                error: 'TOKEN_INVALID',
                message: authError.message
            });
        }

        // 4. Extract & Validate Body Parameters
        const { description, address, location, location_id, ward_name, category, timestamp } = req.body;

        const files = Array.isArray(req.files) ? req.files : [];
        const images = files.map((f) => ({
            originalName: f.originalname,
            mimeType: f.mimetype,
            size: f.size
        }));

        const trimmedDescription = typeof description === 'string' ? description.trim() : '';
        const trimmedAddress = typeof address === 'string' ? address.trim() : (typeof location === 'string' ? location.trim() : '');
        const targetLocationId = location_id || trimmedAddress || 'LOC_UNKNOWN';
        const targetWardName = ward_name || trimmedAddress || 'Ward 12';

        const normalizedCategories = normalizeCategories(category);
        const safeCategory = normalizedCategories[0] || 'other';

        const validationErrors = [];

        if (!trimmedDescription) validationErrors.push({ field: 'description', message: 'Description is required.' });
        if (!trimmedAddress) {
            validationErrors.push({ field: 'address', message: 'Address or location identifier is required.' });
        }

        if (validationErrors.length) {
            return res.status(422).json({
                error: 'Validation failed',
                details: validationErrors,
                timestamp: new Date().toISOString()
            });
        }

        // 5. Anti-Spam Window Check
        try {
            dedupIdempotencyService.checkAndLockDeduplication(tokenData.phoneHash, targetLocationId);
        } catch (dedupError) {
            return res.status(dedupError.statusCode || 409).json({
                error: dedupError.code || 'DUPLICATE_REPORT_REJECTED',
                message: dedupError.message
            });
        }

        // 6. Generate Location-Bound 128-bit Distributed Report ID
        const reportId = idGeneratorService.generateLocationBoundReportId(targetLocationId);

        let initialReport = {
            id: reportId,
            report_id: reportId,
            location_id: targetLocationId,
            ward_name: targetWardName,
            address: trimmedAddress,
            description: trimmedDescription,
            category: safeCategory,
            categories: normalizedCategories,
            images,
            phone_hash: tokenData.phoneHash,
            phone_encrypted: tokenData.encryptedPhone,
            timestamp: timestamp || new Date().toISOString(),
            status: 'SUBMITTED',
            upvotes: 0
        };

        // 7. Automated Geospatial Department & Field Officer Routing
        const routedReport = routingEngineService.routeReport(initialReport);

        // 8. Persist to SQLite reports table
        const insertStmt = db.prepare(`
            INSERT INTO reports (
                report_id, location_id, ward_name, address, description, category, categories,
                status, created_by_phone_hash, created_by_phone_encrypted, organization_id,
                assigned_department_id, assigned_department_name, assigned_officer_id, assigned_officer_name,
                images, upvotes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        insertStmt.run(
            routedReport.report_id,
            routedReport.location_id,
            routedReport.ward_name,
            routedReport.address,
            routedReport.description,
            routedReport.category,
            JSON.stringify(routedReport.categories),
            routedReport.status,
            routedReport.phone_hash,
            JSON.stringify(routedReport.phone_encrypted),
            routedReport.organization_id,
            routedReport.assigned_department_id,
            routedReport.assigned_department_name,
            routedReport.assigned_officer_id,
            routedReport.assigned_officer_name,
            JSON.stringify(routedReport.images),
            routedReport.upvotes || 0,
            routedReport.timestamp
        );

        const responsePayload = {
            success: true,
            status: 'CREATED',
            message: `Report submitted successfully. Assigned to ${routedReport.assigned_department_name}.`,
            report_id: reportId,
            location_id: targetLocationId,
            assigned_department: routedReport.assigned_department_name,
            assigned_officer: routedReport.assigned_officer_name,
            report: routedReport
        };

        if (idempotencyKey) {
            dedupIdempotencyService.saveIdempotentResponse(idempotencyKey, 201, responsePayload);
        }

        res.status(201).json(responsePayload);
    } catch (error) {
        res.status(500).json({
            error: 'Internal server error',
            message: error.message
        });
    }
};

/**
 * Get all litter reports from SQLite
 */
export const getAllReports = (req, res) => {
    try {
        const { category, status, limit = 50, offset = 0 } = req.query;

        let query = 'SELECT * FROM reports WHERE 1=1';
        const params = [];

        if (category) {
            query += ' AND category = ?';
            params.push(category);
        }

        if (status) {
            query += ' AND status = ?';
            params.push(status);
        }

        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
        params.push(parseInt(limit), parseInt(offset));

        const rows = db.prepare(query).all(...params);
        const countQuery = 'SELECT COUNT(*) as total FROM reports';
        const total = db.prepare(countQuery).get().total;

        res.json({
            total,
            limit: parseInt(limit),
            offset: parseInt(offset),
            reports: rows.map(mapRowToReport)
        });
    } catch (error) {
        res.status(500).json({
            error: 'Internal server error',
            message: error.message
        });
    }
};

/**
 * Get specific report by ID
 */
export const getReportById = (req, res) => {
    try {
        const { id } = req.params;
        const row = db.prepare('SELECT * FROM reports WHERE report_id = ?').get(id);

        if (!row) {
            return res.status(404).json({ error: 'Report not found' });
        }

        res.json(mapRowToReport(row));
    } catch (error) {
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

/**
 * Update report status / description
 */
export const updateReport = (req, res) => {
    try {
        const { id } = req.params;
        const { description, status, category } = req.body;

        const row = db.prepare('SELECT * FROM reports WHERE report_id = ?').get(id);
        if (!row) {
            return res.status(404).json({ error: 'Report not found' });
        }

        const newDesc = description !== undefined ? description : row.description;
        const newStatus = status !== undefined ? status : row.status;
        const newCat = category !== undefined ? category : row.category;
        const now = new Date().toISOString();

        db.prepare('UPDATE reports SET description = ?, status = ?, category = ?, updated_at = ? WHERE report_id = ?')
            .run(newDesc, newStatus, newCat, now, id);

        const updatedRow = db.prepare('SELECT * FROM reports WHERE report_id = ?').get(id);

        res.json({
            success: true,
            message: 'Report updated successfully',
            report: mapRowToReport(updatedRow)
        });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

/**
 * Delete a report
 */
export const deleteReport = (req, res) => {
    try {
        const { id } = req.params;
        const row = db.prepare('SELECT * FROM reports WHERE report_id = ?').get(id);

        if (!row) {
            return res.status(404).json({ error: 'Report not found' });
        }

        db.prepare('DELETE FROM reports WHERE report_id = ?').run(id);

        res.json({
            success: true,
            message: 'Report deleted successfully',
            report: mapRowToReport(row)
        });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

/**
 * Get statistics from SQLite
 */
export const getStatistics = (req, res) => {
    try {
        const totalReports = db.prepare('SELECT COUNT(*) as count FROM reports').get().count;
        const rows = db.prepare('SELECT category, status FROM reports').all();

        const byCategory = {};
        const byStatus = {};

        rows.forEach(r => {
            byCategory[r.category] = (byCategory[r.category] || 0) + 1;
            byStatus[r.status] = (byStatus[r.status] || 0) + 1;
        });

        res.json({
            totalReports,
            byCategory,
            byStatus,
            averageReportsPerDay: totalReports > 0 ? totalReports : 0
        });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error', message: error.message });
    }
};

export function getAllReportsInternal() {
    const rows = db.prepare('SELECT * FROM reports ORDER BY created_at DESC').all();
    return rows.map(mapRowToReport);
}

export function updateReportStatusInternal(reportId, newStatus, updatedBy) {
    const row = db.prepare('SELECT * FROM reports WHERE report_id = ?').get(reportId);
    if (!row) {
        const error = new Error(`Report ID ${reportId} not found.`);
        error.statusCode = 404;
        throw error;
    }

    const now = new Date().toISOString();
    db.prepare('UPDATE reports SET status = ?, updated_at = ? WHERE report_id = ?').run(newStatus, now, reportId);
    const updatedRow = db.prepare('SELECT * FROM reports WHERE report_id = ?').get(reportId);
    return mapRowToReport(updatedRow);
}
