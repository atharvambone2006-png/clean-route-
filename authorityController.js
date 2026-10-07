import * as authorityAuthService from '../services/authorityAuthService.js';
import * as auditLogService from '../services/auditLogService.js';
import * as routingEngineService from '../services/routingEngineService.js';
import { getAllReportsInternal, updateReportStatusInternal } from './litterController.js';
import { computeFileHash, validateFileMagicBytes } from '../middleware/documentUploadHandler.js';
import db from '../db/index.js';
import crypto from 'crypto';
import fs from 'fs';

/**
 * POST /api/v1/authority/auth/register
 * Authority Account Registration with Domain Validation & Pending Approval
 */
export const registerAuthorityHandler = (req, res, next) => {
    try {
        const { email, password, full_name, phone_number, department_code, role } = req.body;

        if (!email || !password || !full_name) {
            return res.status(400).json({
                error: 'BAD_REQUEST',
                message: 'Fields email, password, and full_name are required.'
            });
        }

        const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

        const account = authorityAuthService.registerAuthority({
            email,
            password,
            fullName: full_name,
            phoneNumber: phone_number,
            organizationId: department_code,
            role,
            clientIP
        });

        res.status(202).json({
            status: 'PENDING_REVIEW',
            message: `Authority account registered successfully. Domain @${account.email.split('@')[1]} validated. Account pending artifact upload and administrator review.`,
            account
        });
    } catch (error) {
        if (error.statusCode) {
            return res.status(error.statusCode).json({
                error: 'REGISTRATION_FAILED',
                message: error.message
            });
        }
        next(error);
    }
};

/**
 * POST /api/v1/authority/documents
 * Upload verification documents (ID Badge / Authorization Letter) with SHA-256 hashing
 */
export const uploadDocumentHandler = (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.substring(7) : null;
        const claims = authorityAuthService.verifyAuthToken(token);

        if (!req.file) {
            return res.status(400).json({ error: 'BAD_REQUEST', message: 'No verification document file attached.' });
        }

        const filePath = req.file.path;

        if (!validateFileMagicBytes(filePath)) {
            try { fs.unlinkSync(filePath); } catch (e) {}
            return res.status(400).json({
                error: 'INVALID_FILE_FORMAT',
                message: 'File content failed magic byte validation. Uploaded file is not a valid PNG, JPEG, or PDF document.'
            });
        }

        const fileHash = computeFileHash(filePath);
        const docId = `doc_${crypto.randomUUID()}`;
        const docType = req.body.document_type || 'OFFICIAL_ID';

        db.prepare(`
            INSERT INTO authority_verification_documents (document_id, user_id, document_type, file_path, file_name, file_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(docId, claims.sub, docType, filePath, req.file.filename, fileHash);

        res.status(200).json({
            status: 'SUCCESS',
            document_id: docId,
            file_name: req.file.filename,
            file_hash: fileHash,
            message: 'Verification document uploaded successfully with SHA-256 integrity hash. Pending review.'
        });
    } catch (error) {
        if (error.statusCode) {
            return res.status(error.statusCode).json({ error: 'UPLOAD_FAILED', message: error.message });
        }
        next(error);
    }
};

/**
 * POST /api/v1/authority/auth/login
 * Authenticate Authority via Email/Password or OIDC Token
 */
export const loginAuthorityHandler = (req, res, next) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            console.warn('[AUTH CONTROLLER] Login failed: Missing email or password in request body.');
            return res.status(400).json({
                error: 'BAD_REQUEST',
                message: 'Both email and password are required.'
            });
        }

        const { authority, tokens } = authorityAuthService.loginAuthority({ email, password });

        res.status(200).json({
            status: 'AUTHENTICATED',
            message: 'Authority authentication successful.',
            access_token: tokens.accessToken,
            refresh_token: tokens.refreshToken,
            expires_in_seconds: tokens.expiresInSeconds,
            authority_profile: authority
        });
    } catch (error) {
        console.error(`[AUTH CONTROLLER] Authentication failure for email "${req.body?.email}": [Code: ${error.statusCode || 500}] ${error.message}`);
        if (error.statusCode) {
            return res.status(error.statusCode).json({
                error: error.statusCode === 403 ? 'ACCOUNT_PENDING' : 'AUTHENTICATION_FAILED',
                message: error.message
            });
        }
        next(error);
    }
};

/**
 * POST /api/v1/authority/admin/approve-account
 * Admin Approval Handler for Pending Authority Accounts
 */
export const approveAccountHandler = (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.substring(7) : null;
        const claims = authorityAuthService.verifyAuthToken(token);

        const { target_authority_id } = req.body;
        if (!target_authority_id) {
            return res.status(400).json({
                error: 'BAD_REQUEST',
                message: 'target_authority_id is required.'
            });
        }

        const approvedAccount = authorityAuthService.approveAccount(claims, target_authority_id);

        const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
        auditLogService.recordAuditLog({
            authorityId: claims.sub,
            authorityEmail: claims.email,
            action: 'APPROVE_ACCOUNT',
            clientIP,
            payload: { approved_account_id: target_authority_id }
        });

        res.status(200).json({
            status: 'APPROVED',
            message: `Authority account activated successfully.`,
            account: approvedAccount
        });
    } catch (error) {
        if (error.statusCode) {
            return res.status(error.statusCode).json({
                error: 'APPROVAL_FAILED',
                message: error.message
            });
        }
        next(error);
    }
};

/**
 * GET /api/v1/authority/tasks/assigned
 * Retrieve Assigned Tasks for the Logged-in Authority
 */
export const getAssignedTasksHandler = (req, res, next) => {
    try {
        const claims = req.userClaims || authorityAuthService.verifyAuthToken(
            req.headers['authorization']?.substring(7)
        );

        const allReports = getAllReportsInternal();
        const assignedTasks = allReports.filter(r =>
            r.organization_id === claims.organization_id ||
            r.assigned_officer_id === claims.sub ||
            ['ROLE_SYSTEM_ADMIN', 'ROLE_AUTHORITY_ADMIN', 'SUPERADMIN', 'MUNICIPAL_ADMIN'].includes(claims.role)
        );

        res.status(200).json({
            status: 'SUCCESS',
            organization_id: claims.organization_id,
            authority_role: claims.role,
            total_assigned: assignedTasks.length,
            tasks: assignedTasks
        });
    } catch (error) {
        if (error.statusCode) {
            return res.status(error.statusCode).json({ error: 'UNAUTHORIZED', message: error.message });
        }
        next(error);
    }
};

/**
 * PATCH /api/v1/authority/tasks/:id/status
 * Update Task Status (Claim, In Progress, Resolve) + Audit Log + Webhook
 */
export const updateTaskStatusHandler = (req, res, next) => {
    try {
        const claims = req.userClaims || authorityAuthService.verifyAuthToken(
            req.headers['authorization']?.substring(7)
        );

        const { id } = req.params;
        const { status, resolution_notes } = req.body;

        if (!status) {
            return res.status(400).json({ error: 'BAD_REQUEST', message: 'status is required.' });
        }

        const updatedReport = updateReportStatusInternal(id, status, claims.email);

        const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
        const userAgent = req.headers['user-agent'] || 'API Client';

        const auditEntry = auditLogService.recordAuditLog({
            authorityId: claims.sub,
            authorityEmail: claims.email,
            action: `UPDATE_STATUS_${status.toUpperCase()}`,
            reportId: id,
            clientIP,
            userAgent,
            payload: { new_status: status, resolution_notes }
        });

        routingEngineService.dispatchWebhookEvent(`report.${status.toLowerCase()}`, updatedReport);

        res.status(200).json({
            status: 'UPDATED',
            message: `Report status updated to ${status}.`,
            report_id: id,
            new_status: status,
            audit_log_id: auditEntry.log_id,
            report: updatedReport
        });
    } catch (error) {
        if (error.statusCode) {
            return res.status(error.statusCode).json({ error: 'AUTHORITY_ACTION_FAILED', message: error.message });
        }
        next(error);
    }
};

/**
 * GET /api/v1/authority/admin/accounts
 */
export const getAuthorityAccountsHandler = (req, res, next) => {
    try {
        const claims = req.userClaims || authorityAuthService.verifyAuthToken(
            req.headers['authorization']?.substring(7)
        );

        if (!['ROLE_SYSTEM_ADMIN', 'ROLE_AUTHORITY_ADMIN', 'SUPERADMIN', 'MUNICIPAL_ADMIN'].includes(claims.role)) {
            return res.status(403).json({ error: 'FORBIDDEN', message: 'Administrator privileges required.' });
        }

        const accounts = authorityAuthService.getAllAuthorityAccounts();
        res.status(200).json({ accounts });
    } catch (error) {
        if (error.statusCode) {
            return res.status(error.statusCode).json({ error: 'UNAUTHORIZED', message: error.message });
        }
        next(error);
    }
};

/**
 * GET /api/v1/authority/admin/audit-logs
 */
export const getAuditLogsHandler = (req, res, next) => {
    try {
        const claims = req.userClaims || authorityAuthService.verifyAuthToken(
            req.headers['authorization']?.substring(7)
        );

        if (!['ROLE_SYSTEM_ADMIN', 'ROLE_AUTHORITY_ADMIN', 'SUPERADMIN', 'MUNICIPAL_ADMIN'].includes(claims.role)) {
            return res.status(403).json({ error: 'FORBIDDEN', message: 'Administrator privileges required.' });
        }

        const logs = auditLogService.getAuditLogs({ limit: 100 });
        res.status(200).json({ total_logs: logs.length, logs });
    } catch (error) {
        if (error.statusCode) {
            return res.status(error.statusCode).json({ error: 'UNAUTHORIZED', message: error.message });
        }
        next(error);
    }
};
