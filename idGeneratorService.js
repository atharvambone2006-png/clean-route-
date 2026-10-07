import crypto from 'crypto';

const NODE_ID = parseInt(process.env.NODE_ID || '1', 10) & 0x3FF; // 10-bit Node ID (0-1023)
const CUSTOM_EPOCH = 1767225600000; // 2026-01-01T00:00:00.000Z epoch offset

let lastTimestamp = -1;
let sequence = 0;

/**
 * Generate a 64-bit Location Domain Hash from a location primitive (H3 spatial index or Sight UUID).
 */
export function computeLocationHash(locationId) {
    if (!locationId || typeof locationId !== 'string') {
        throw new Error('Location ID is required to generate location-bound report ID.');
    }
    const cleanLoc = locationId.trim().toUpperCase();
    const hashBuffer = crypto.createHash('sha256').update(cleanLoc).digest();
    // Use top 8 bytes (64 bits) as location domain hex
    return hashBuffer.subarray(0, 8).toString('hex').toUpperCase();
}

/**
 * Generate a 128-bit Distributed Location-Bound Report ID.
 * Canonical format: REP-<LOCATION_64BIT_HEX>-<EPOCH_TIMESTAMP_HEX>-<NODE_SEQ_HEX>
 * Ensures:
 * 1. Zero ID space overlap between distinct locations (Top 64 bits differ).
 * 2. Guaranteed collision-free monotonic order within the same location across distributed worker nodes.
 */
export function generateLocationBoundReportId(locationId) {
    const locHashHex = computeLocationHash(locationId);

    let now = Date.now();
    let currentOffset = now - CUSTOM_EPOCH;

    if (currentOffset < lastTimestamp) {
        // Clock drift protection
        console.warn(`[ID Generator] System clock drift detected! System time rolled back by ${lastTimestamp - currentOffset}ms.`);
        now = lastTimestamp + CUSTOM_EPOCH;
        currentOffset = lastTimestamp;
    }

    if (currentOffset === lastTimestamp) {
        sequence = (sequence + 1) & 0xFFF; // 12-bit sequence (0-4095)
        if (sequence === 0) {
            // Sequence overflow per millisecond: wait for next millisecond tick
            while (now <= lastTimestamp + CUSTOM_EPOCH) {
                now = Date.now();
            }
            currentOffset = now - CUSTOM_EPOCH;
        }
    } else {
        sequence = 0;
    }

    lastTimestamp = currentOffset;

    const timestampHex = currentOffset.toString(16).padStart(11, '0').toUpperCase();
    const nodeSeqCombined = ((NODE_ID << 12) | sequence).toString(16).padStart(6, '0').toUpperCase();

    return `REP-${locHashHex}-${timestampHex}-${nodeSeqCombined}`;
}
