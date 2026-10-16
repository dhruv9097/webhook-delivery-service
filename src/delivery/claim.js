import { prisma } from '../db.js';
import { MAX_ATTEMPTS } from './backoff.js';

/**
 * Atomically claims up to `batchSize` due deliveries for this worker.
 *
 * `FOR UPDATE SKIP LOCKED` is what makes this safe with N workers and no
 * coordination: each worker's inner SELECT locks the rows it reads and skips
 * any already locked by a peer, so two workers can never claim the same row.
 * No leader election, no distributed lock, no Redis involvement.
 *
 * attempt_count is incremented HERE, at claim time, not when the attempt
 * finishes. If a worker dies mid-delivery the increment survives, so the retry
 * schedule advances rather than looping forever on attempt 1. The cost is that
 * a crashed attempt leaves a gap in the attempt numbers — which is honest: it
 * records an attempt whose outcome genuinely is unknown.
 *
 * locked_until is a lease, not a lock. Nothing has to be released for recovery
 * to work; the lease simply expires and the reaper picks the row back up.
 */
export async function claimDue({ workerId, batchSize, leaseSeconds }) {
  return prisma.$queryRaw`
    UPDATE deliveries AS d
    SET state = 'IN_FLIGHT',
        attempt_count = d.attempt_count + 1,
        locked_until = now() + make_interval(secs => ${leaseSeconds}::int),
        locked_by = ${workerId}
    WHERE d.id IN (
      SELECT id
      FROM deliveries
      WHERE state IN ('PENDING', 'RETRYING')
        AND next_attempt_at <= now()
      ORDER BY next_attempt_at
      LIMIT ${batchSize}::int
      FOR UPDATE SKIP LOCKED
    )
    RETURNING d.id AS "id", d.attempt_count AS "attemptNo"
  `;
}

/** Loads everything an attempt needs: the payload, the target, the secrets. */
export async function loadClaimedDeliveries(ids) {
  if (ids.length === 0) return [];
  return prisma.delivery.findMany({
    where: { id: { in: ids } },
    include: {
      event: { select: { id: true, eventType: true, payload: true, createdAt: true } },
      endpoint: {
        select: {
          id: true,
          url: true,
          secretCurrent: true,
          secretPrevious: true,
          secretRotatedAt: true,
          state: true,
        },
      },
    },
  });
}

/**
 * Records the outcome of one attempt and moves the delivery to its next state.
 *
 * The attempt row and the state transition are written in one transaction. Split
 * apart, a crash between them would leave the delivery claiming three attempts
 * while only two are visible in the inspector — the audit trail would lie.
 */
async function recordOutcome({ deliveryId, attemptNo, result, delivery }) {
  const attempt = {
    deliveryId,
    attemptNo,
    requestHeaders: result.requestHeaders ?? undefined,
    responseStatus: result.status ?? null,
    responseBodySnippet: result.bodySnippet ?? null,
    latencyMs: result.latencyMs ?? null,
    errorKind: result.errorKind ?? null,
  };

  await prisma.$transaction([
    prisma.deliveryAttempt.create({ data: attempt }),
    prisma.delivery.update({ where: { id: deliveryId }, data: delivery }),
  ]);
}

export function markSucceeded({ deliveryId, attemptNo, result }) {
  return recordOutcome({
    deliveryId,
    attemptNo,
    result,
    delivery: {
      state: 'SUCCEEDED',
      completedAt: new Date(),
      lockedUntil: null,
      lockedBy: null,
      lastError: null,
    },
  });
}

export function scheduleRetry({ deliveryId, attemptNo, result, nextAttemptAt }) {
  return recordOutcome({
    deliveryId,
    attemptNo,
    result,
    delivery: {
      state: 'RETRYING',
      nextAttemptAt,
      // The lease is released immediately. Holding it until expiry would block
      // the retry for a full lease period even though this worker is done.
      lockedUntil: null,
      lockedBy: null,
      lastError: result.errorKind ?? `HTTP ${result.status}`,
    },
  });
}

export function markFailedPermanent({ deliveryId, attemptNo, result, reason }) {
  return recordOutcome({
    deliveryId,
    attemptNo,
    result,
    delivery: {
      state: 'FAILED_PERMANENT',
      completedAt: new Date(),
      lockedUntil: null,
      lockedBy: null,
      lastError: reason ?? result.errorKind ?? `HTTP ${result.status}`,
    },
  });
}

/**
 * Returns a claimed delivery to the queue WITHOUT counting it as an attempt.
 *
 * Used when the delivery was never actually tried — an open circuit is the only
 * current case. The claim already incremented attempt_count, so that increment
 * is rolled back here.
 *
 * Without the rollback, a delivery sitting behind an open circuit burns its
 * retry budget on deferrals that never opened a socket, and can reach
 * FAILED_PERMANENT having literally never been sent. The retry schedule is a
 * budget for *attempts*, so something that was not attempted must not spend it.
 *
 * No DeliveryAttempt row is written either: the inspector should show what was
 * actually sent, not a list of times we declined to send.
 */
export function deferDelivery({ deliveryId, nextAttemptAt, reason }) {
  return prisma.delivery.update({
    where: { id: deliveryId },
    data: {
      state: 'RETRYING',
      nextAttemptAt,
      attemptCount: { decrement: 1 },
      lockedUntil: null,
      lockedBy: null,
      lastError: reason,
    },
  });
}

/** An endpoint disabled after the delivery was claimed — drop it, don't retry. */
export function markDiscarded({ deliveryId, reason }) {
  return prisma.delivery.update({
    where: { id: deliveryId },
    data: {
      state: 'DISCARDED',
      completedAt: new Date(),
      lockedUntil: null,
      lockedBy: null,
      lastError: reason,
    },
  });
}

/**
 * Returns deliveries abandoned by workers that died mid-attempt.
 *
 * This is the entire crash-recovery mechanism. A SIGKILLed worker releases
 * nothing and notifies no one; its claims simply stop being renewed, and this
 * sweep reclaims them once the lease expires.
 *
 * next_attempt_at is deliberately left in the past so a reclaimed delivery is
 * immediately due — the attempt never happened, so there is nothing to back off
 * from. The attempt_count increment from the original claim still stands, so a
 * delivery that repeatedly kills its worker walks the schedule and eventually
 * exhausts it rather than looping forever.
 */
export async function reapExpiredLeases() {
  return prisma.$queryRaw`
    UPDATE deliveries
    SET state = CASE
          WHEN attempt_count >= ${MAX_ATTEMPTS}::int THEN 'FAILED_PERMANENT'::"DeliveryState"
          ELSE 'RETRYING'::"DeliveryState"
        END,
        locked_until = NULL,
        locked_by = NULL,
        completed_at = CASE
          WHEN attempt_count >= ${MAX_ATTEMPTS}::int THEN now()
          ELSE NULL
        END,
        last_error = 'worker lease expired before the attempt completed'
    WHERE state = 'IN_FLIGHT'
      AND locked_until < now()
    RETURNING id AS "id", attempt_count AS "attemptCount", state AS "state"
  `;
}
