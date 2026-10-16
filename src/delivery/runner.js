import { config } from '../config.js';
import { logger, withTrace } from '../logger.js';
import { prisma } from '../db.js';
import { attemptDelivery } from './attempt.js';
import { checkCircuit, recordFailure, recordSuccess } from './circuit.js';
import { isExhausted, nextAttemptAt } from './backoff.js';
import {
  claimDue,
  deferDelivery,
  loadClaimedDeliveries,
  markDiscarded,
  markFailedPermanent,
  markSucceeded,
  scheduleRetry,
} from './claim.js';

/**
 * Processes one claimed delivery through to a recorded outcome.
 *
 * Runs under the delivery's own trace context, so every log line from the
 * attempt through to the state transition carries the same trace_id as the
 * ingest request that created it.
 */
async function processOne(delivery, dispatcher) {
  return withTrace(`del-${delivery.id}`, async () => {
    const log = logger();
    const attemptNo = delivery.attemptCount;

    // The endpoint may have been disabled between fan-out and this attempt.
    // Discarding rather than retrying respects the customer's decision: they
    // turned the endpoint off, so they do not want the backlog either.
    if (delivery.endpoint.state !== 'ENABLED') {
      await markDiscarded({ deliveryId: delivery.id, reason: 'endpoint disabled before delivery' });
      log.info({ delivery_id: delivery.id }, 'delivery discarded, endpoint disabled');
      return 'discarded';
    }

    // Consult the breaker before opening a socket. An open circuit means we
    // already know this receiver is down, so the delivery is rescheduled
    // without spending a worker slot on the connect timeout.
    const circuit = await checkCircuit(delivery.endpoint.id);
    if (!circuit.allowed) {
      const retryAt = new Date(Date.now() + circuit.retryAfterSeconds * 1000);
      // Deferred, not attempted: no socket was opened, so this must not consume
      // one of the delivery's eight attempts.
      await deferDelivery({
        deliveryId: delivery.id,
        nextAttemptAt: retryAt,
        reason: 'circuit_open',
      });
      log.debug(
        { delivery_id: delivery.id, endpoint_id: delivery.endpoint.id, retry_at: retryAt.toISOString() },
        'delivery deferred, circuit open',
      );
      return 'circuit_open';
    }

    const result = await attemptDelivery({ delivery, dispatcher });

    if (result.outcome === 'success') {
      await recordSuccess(delivery.endpoint.id);
      await markSucceeded({ deliveryId: delivery.id, attemptNo, result });
      log.info(
        { delivery_id: delivery.id, attempt: attemptNo, status: result.status, latency_ms: result.latencyMs },
        'delivery succeeded',
      );
      return 'succeeded';
    }

    // Retrying a blocked target is pointless: the denylist will not change on
    // its own, and 8 attempts over 24h would just bury the real problem. Fail
    // it immediately so the reason is visible in the dashboard straight away.
    if (result.outcome === 'blocked') {
      await markFailedPermanent({
        deliveryId: delivery.id,
        attemptNo,
        result,
        reason: `blocked target: ${result.blockReason}`,
      });
      log.error(
        { delivery_id: delivery.id, endpoint_id: delivery.endpoint.id, block_reason: result.blockReason },
        'delivery blocked by SSRF guard',
      );
      return 'blocked';
    }

    if (result.outcome === 'permanent') {
      await markFailedPermanent({
        deliveryId: delivery.id,
        attemptNo,
        result,
        reason: 'receiver returned 410 Gone',
      });
      log.warn({ delivery_id: delivery.id, attempt: attemptNo }, 'delivery abandoned, receiver said gone');
      return 'failed_permanent';
    }

    // Everything below here is a genuine receiver failure, so it feeds the
    // breaker. Blocked targets returned earlier and deliberately do not: they
    // are a configuration fault, and tripping a breaker for them would hide the
    // real reason behind a generic "circuit open".
    const breaker = await recordFailure(delivery.endpoint.id, { wasProbe: circuit.state === 'half-open' });
    if (breaker.opened) {
      log.warn(
        {
          endpoint_id: delivery.endpoint.id,
          consecutive_failures: breaker.consecutiveFailures,
          cooldown_seconds: breaker.cooldownSeconds,
          reopen_count: breaker.generation,
        },
        'circuit opened for endpoint',
      );
      await maybeAutoDisable(delivery.endpoint.id, breaker, log);
    }

    if (isExhausted(attemptNo)) {
      await markFailedPermanent({
        deliveryId: delivery.id,
        attemptNo,
        result,
        reason: `exhausted after ${attemptNo} attempts (${result.errorKind})`,
      });
      log.warn(
        { delivery_id: delivery.id, attempts: attemptNo, error_kind: result.errorKind },
        'delivery exhausted retry schedule',
      );
      return 'failed_permanent';
    }

    const retryAt = nextAttemptAt(attemptNo);
    await scheduleRetry({ deliveryId: delivery.id, attemptNo, result, nextAttemptAt: retryAt });
    log.warn(
      {
        delivery_id: delivery.id,
        attempt: attemptNo,
        status: result.status,
        error_kind: result.errorKind,
        retry_at: retryAt.toISOString(),
        retry_in_ms: retryAt.getTime() - Date.now(),
      },
      'delivery failed, retry scheduled',
    );
    return 'retrying';
  });
}

/**
 * Disables an endpoint that has stayed broken across many breaker cycles.
 *
 * The breaker alone never gives up — it keeps probing forever at a capped
 * interval. That is right for an outage and wrong for an endpoint whose owner
 * deleted the service months ago. After AUTO_DISABLE_GENERATION consecutive
 * re-opens (roughly a day at the capped cooldown) the endpoint is disabled in
 * Postgres, which is durable and visible in the dashboard, and subsequent
 * events stop fanning out to it at all.
 */
const AUTO_DISABLE_GENERATION = 12;

async function maybeAutoDisable(endpointId, breaker, log) {
  if (breaker.generation < AUTO_DISABLE_GENERATION) return;

  const result = await prisma.endpoint.updateMany({
    where: { id: endpointId, state: 'ENABLED' },
    data: { state: 'DISABLED', disabledAt: new Date() },
  });

  if (result.count > 0) {
    log.error(
      { endpoint_id: endpointId, reopen_count: breaker.generation },
      'endpoint auto-disabled after sustained failure',
    );
  }
}

/**
 * One tick: claim a batch, deliver it, record every outcome.
 *
 * The batch runs concurrently because each delivery is an independent network
 * call to a different host — serialising them would make one slow receiver set
 * the pace for the entire batch.
 *
 * allSettled, not all: one delivery throwing must not abandon its siblings
 * mid-flight, leaving them IN_FLIGHT until their leases expire.
 */
export async function runTick({ workerId, dispatcher }) {
  const claimed = await claimDue({
    workerId,
    batchSize: config.WORKER_CLAIM_BATCH,
    leaseSeconds: config.WORKER_LEASE_SECONDS,
  });

  if (claimed.length === 0) return 0;

  const deliveries = await loadClaimedDeliveries(claimed.map((c) => c.id));
  const outcomes = await Promise.allSettled(deliveries.map((d) => processOne(d, dispatcher)));

  for (const outcome of outcomes) {
    if (outcome.status === 'rejected') {
      // Recording the outcome itself failed — the delivery is stranded
      // IN_FLIGHT. Not lost: the reaper reclaims it when the lease expires.
      logger().error({ err: outcome.reason }, 'failed to record delivery outcome, lease will expire');
    }
  }

  return claimed.length;
}
