import crypto from 'crypto';
import db from '../db/index.js';

/**
 * Append an immutable audit log entry for an authority action into SQLite security_audit_logs.
 */
export function recordAuditLog({ authorityId, authorityEmail, action, reportId, clientIP, userAgent, payload }) {
    if (!authorityId || !action) {
        throw new Error('Authority ID and action are required for audit logging.');
    }

    const auditId = `audit_${crypto.randomUUID()}`;
    const payloadString = JSON.stringify(payload || {});
    const payloadHash = crypto.createHash('sha256').update(payloadString).digest('hex');
    const timestamp = new Date().toISOString();

    const insertStmt = db.prepare(`
        INSERT INTO security_audit_logs (audit_id, actor_id, actor_email, action, target_resource, ip_address, payload_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertStmt.run(
        auditId,
        authorityId,
        authorityEmail || 'unknown',
        action,
        reportId || null,
        clientIP || '127.0.0.1',
        payloadHash,
        timestamp
    );

    console.log(`[AUDIT LOG] [${timestamp}] Auth: ${authorityEmail} | Action: ${action} | Report: ${reportId || 'N/A'}`);

    return {
        log_id: auditId,
        authority_id: authorityId,
        authority_email: authorityEmail,
        action,
        report_id: reportId,
        ip_address: clientIP,
        payload_hash: payloadHash,
        timestamp
    };
}

/**
 * Query audit logs from SQLite (Restricted to Administrators)
 */
export function getAuditLogs({ limit = 50, authorityId, reportId } = {}) {
    let query = 'SELECT audit_id as log_id, actor_id as authority_id, actor_email as authority_email, action, target_resource as report_id, ip_address, payload_hash, created_at as timestamp FROM security_audit_logs WHERE 1=1';
    const params = [];

    if (authorityId) {
        query += ' AND actor_id = ?';
        params.push(authorityId);
    }
    if (reportId) {
        query += ' AND target_resource = ?';
        params.push(reportId);
    }

    query += ' ORDER BY created_at DESC LIMIT ?';
    params.push(parseInt(limit));

    return db.prepare(query).all(...params);
}
