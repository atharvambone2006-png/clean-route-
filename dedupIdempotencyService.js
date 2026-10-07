// Ephemeral memory stores (In production, backed by Redis cluster and DB constraints)
const activeDeduplicationLocks = new Map();
const idempotencyStore = new Map();

const DEDUP_WINDOW_MS = 30 * 60 * 1000; // 30 minutes window

/**
 * Check and enforce anti-spam deduplication.
 * Rejects submissions if the same phone number has submitted a report for the exact same location
 * within the 30-minute window.
 */
export function checkAndLockDeduplication(phoneHash, locationId) {
    const now = Date.now();
    const cleanLocation = locationId.trim().toUpperCase();
    const dedupKey = `dedup:${phoneHash}:${cleanLocation}`;

    const existingLock = activeDeduplicationLocks.get(dedupKey);
    if (existingLock && now < existingLock.expiresAt) {
        const remainingMinutes = Math.ceil((existingLock.expiresAt - now) / 60000);
        const error = new Error(`A report for this location has already been submitted by your phone number within the active window. Please retry in ${remainingMinutes} minute(s).`);
        error.statusCode = 409; // Conflict
        error.code = 'DUPLICATE_REPORT_REJECTED';
        throw error;
    }

    // Set lock with TTL
    activeDeduplicationLocks.set(dedupKey, {
        phoneHash,
        locationId: cleanLocation,
        expiresAt: now + DEDUP_WINDOW_MS
    });
}

/**
 * Check idempotency key status.
 * If processing/completed, returns cached status and response.
 */
export function getIdempotentResponse(idempotencyKey) {
    if (!idempotencyKey) return null;

    const record = idempotencyStore.get(idempotencyKey);
    if (!record) return null;

    if (record.status === 'PROCESSING') {
        const error = new Error('A request with this Idempotency Key is currently being processed.');
        error.statusCode = 409;
        throw error;
    }

    return record;
}

/**
 * Register an idempotency key as PROCESSING.
 */
export function registerIdempotencyStart(idempotencyKey) {
    if (!idempotencyKey) return;
    idempotencyStore.set(idempotencyKey, {
        status: 'PROCESSING',
        createdAt: Date.now()
    });
}

/**
 * Complete idempotency key execution with response payload and status.
 */
export function saveIdempotentResponse(idempotencyKey, statusCode, payload) {
    if (!idempotencyKey) return;
    idempotencyStore.set(idempotencyKey, {
        status: 'COMPLETED',
        statusCode,
        payload,
        completedAt: Date.now()
    });
}
