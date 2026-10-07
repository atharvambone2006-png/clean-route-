import * as authService from '../services/authService.js';
import { getReportsByPhoneHash } from './litterController.js';

/**
 * POST /api/v1/auth/otp/request
 * Request an OTP session
 */
export const requestOTPHandler = (req, res, next) => {
    try {
        const { phone_number } = req.body;
        const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

        if (!phone_number) {
            return res.status(400).json({
                error: 'BAD_REQUEST',
                message: 'Field phone_number is required.'
            });
        }

        const result = authService.requestOTP(phone_number, clientIP);

        res.status(202).json({
            status: 'SUCCESS',
            message: 'OTP dispatch initiated.',
            session_id: result.sessionId,
            expires_in_seconds: result.expiresInSeconds,
            resend_cooldown_seconds: result.resendCooldownSeconds,
            dev_otp_code: result.devOtpCode // convenient for API testing
        });
    } catch (error) {
        if (error.statusCode) {
            return res.status(error.statusCode).json({
                error: 'RATE_LIMIT_EXCEEDED',
                message: error.message,
                retry_after_seconds: error.retryAfter
            });
        }
        next(error);
    }
};

/**
 * POST /api/v1/auth/otp/verify
 * Verify OTP code and obtain single-use verification token
 */
export const verifyOTPHandler = (req, res, next) => {
    try {
        const { session_id, otp_code } = req.body;

        if (!session_id || !otp_code) {
            return res.status(400).json({
                error: 'BAD_REQUEST',
                message: 'Both session_id and otp_code are required.'
            });
        }

        const result = authService.verifyOTP(session_id, otp_code);

        res.status(200).json({
            status: 'VERIFIED',
            message: 'OTP verified successfully.',
            verification_token: result.verificationToken,
            expires_in_seconds: result.expiresInSeconds
        });
    } catch (error) {
        if (error.statusCode) {
            return res.status(error.statusCode).json({
                error: error.statusCode === 410 ? 'SESSION_EXPIRED' : 'INVALID_OTP',
                message: error.message,
                attempts_remaining: error.attemptsLeft
            });
        }
        next(error);
    }
};

/**
 * POST /api/v1/auth/reports/lookup/phone
 * Secondary lookup for reports by verified phone number
 */
export const lookupReportsByPhoneHandler = (req, res, next) => {
    try {
        const { phone_number } = req.body;

        if (!phone_number) {
            return res.status(400).json({
                error: 'BAD_REQUEST',
                message: 'phone_number is required for lookup.'
            });
        }

        const e164 = authService.normalizePhone(phone_number);
        const phoneHash = authService.computePhoneHash(e164);
        const userReports = getReportsByPhoneHash(phoneHash);

        res.status(200).json({
            status: 'SUCCESS',
            phone_hash: phoneHash,
            total_reports: userReports.length,
            reports: userReports
        });
    } catch (error) {
        next(error);
    }
};
