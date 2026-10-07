import * as authorityAuthService from '../services/authorityAuthService.js';
import db from '../db/index.js';

/**
 * Policy Decision Point (PDP) RBAC/ABAC Guard Middleware
 * Re-validates live database verification_status on EVERY request to ensure instant 0ms session revocation if suspended.
 */
export function pdpGuard({ requiredRoles = [], requiredStatus = 'VERIFIED', checkOrganizationMatch = false } = {}) {
    return (req, res, next) => {
        try {
            const authHeader = req.headers['authorization'];
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({
                    error: 'UNAUTHORIZED',
                    message: 'Missing or malformed Authorization Bearer token.'
                });
            }

            const token = authHeader.substring(7).trim();
            const claims = authorityAuthService.verifyAuthToken(token);

            // Live Database Re-validation for Instant Mid-Session Revocation
            const liveUser = db.prepare(`
                SELECT u.primary_role, ap.verification_status, ap.organization_id
                FROM users u
                LEFT JOIN authority_profiles ap ON u.user_id = ap.user_id
                WHERE u.user_id = ?
            `).get(claims.sub);

            if (!liveUser) {
                return res.status(401).json({
                    error: 'ACCOUNT_NOT_FOUND',
                    message: 'User account no longer exists.'
                });
            }

            const currentStatus = liveUser.verification_status || 'UNVERIFIED';
            const currentRole = liveUser.primary_role || claims.role;

            // 1. Instant Revocation Check: Suspended User Block
            if (currentStatus === 'SUSPENDED') {
                return res.status(403).json({
                    error: 'ACCOUNT_SUSPENDED',
                    message: 'Account has been suspended by an administrator. Active session revoked.'
                });
            }

            // 2. RBAC Check: Static Role Assertion
            if (requiredRoles.length > 0) {
                const hasRole = requiredRoles.includes(currentRole) || currentRole === 'ROLE_SYSTEM_ADMIN' || currentRole === 'SUPERADMIN';
                if (!hasRole) {
                    return res.status(403).json({
                        error: 'FORBIDDEN',
                        message: `Access denied. Requires one of roles: [${requiredRoles.join(', ')}].`
                    });
                }
            }

            // 3. ABAC Attribute Check: Verification Status Assertion
            if (requiredStatus && currentRole !== 'ROLE_SYSTEM_ADMIN' && currentRole !== 'SUPERADMIN') {
                if (currentStatus !== requiredStatus) {
                    return res.status(403).json({
                        error: 'VERIFICATION_REQUIRED',
                        message: `Live account status is '${currentStatus}'. Requires '${requiredStatus}' status.`
                    });
                }
            }

            // 4. ABAC Attribute Check: Resource Organization Match Assertion
            if (checkOrganizationMatch && req.params.id && currentRole !== 'ROLE_SYSTEM_ADMIN' && currentRole !== 'SUPERADMIN') {
                const reportId = req.params.id;
                const report = db.prepare('SELECT organization_id, ward_name FROM reports WHERE report_id = ?').get(reportId);

                if (report) {
                    const userOrgId = liveUser.organization_id || claims.organization_id;
                    const orgMatch = report.organization_id === userOrgId;
                    if (!orgMatch) {
                        return res.status(403).json({
                            error: 'JURISDICTION_DENIED',
                            message: `Access denied. Report belongs to organization '${report.organization_id}', but subject belongs to '${userOrgId}'.`
                        });
                    }
                }
            }

            req.userClaims = {
                ...claims,
                role: currentRole,
                verification_status: currentStatus,
                organization_id: liveUser.organization_id || claims.organization_id
            };
            next();
        } catch (error) {
            return res.status(error.statusCode || 401).json({
                error: 'AUTHENTICATION_FAILED',
                message: error.message
            });
        }
    };
}
