import { redis } from '../redis.js';

/**
 * Per-endpoint circuit breaker.
 *
 * Without one, a customer whose receiver has been down for a week still gets a
 * full delivery attempt every time one of their events comes due. Each attempt
 * occupies a worker slot for the whole connect timeout. Enough dead endpoints
 * and the worker pool spends its time waiting on hosts that will not answer,
 * while healthy customers' deliveries queue behind them. The breaker converts
 * "wait 5 seconds to learn it is still down" into "skip it, we already know".
 *
 * States:
 *   closed    - normal. Failures accumulate toward the threshold.
 *   open      - skip immediately, no socket opened, until the cooldown expires.
 *   half-open - exactly one probe allowed through. Success closes the circuit;
 *               failure re-opens it with a longer cooldown.
 *
 * State lives in Redis, not Postgres, on purpose: it is high-churn, per-attempt
 * data that is safe to lose. A Redis flush costs one round of re-learning. The
 * durable consequence — an endpoint disabled after sustained failure — is
 * written to Postgres, because that one must survive.
 */

export const FAILURE_THRESHOLD = 20;
const BASE_COOLDOWN_SECONDS = 60;
const MAX_COOLDOWN_SECONDS = 3600;
// Counters expire on their own so an endpoint that fails occasionally over
// weeks never accumulates its way to an open circuit. The breaker should react
// to a burst of failures, not to a long tail of unrelated ones.
const FAILURE_WINDOW_SECONDS = 600;

const failureKey = (endpointId) => `circuit:fail:${endpointId}`;
const openKey = (endpointId) => `circuit:open:${endpointId}`;
const probeKey = (endpointId) => `circuit:probe:${endpointId}`;
const generationKey = (endpointId) => `circuit:gen:${endpointId}`;

function cooldownFor(generation) {
  // Each consecutive re-open doubles the wait, so an endpoint that has been
  // dead for hours is probed hourly rather than every minute.
  return Math.min(BASE_COOLDOWN_SECONDS * 2 ** Math.max(generation - 1, 0), MAX_COOLDOWN_SECONDS);
}

/**
 * Decides whether an attempt may proceed.
 *
 * Returns { allowed, state, retryAfterSeconds? }. In the half-open state this
 * hands out exactly one probe token; concurrent workers that lose the race are
 * told the circuit is still open, so a recovering receiver gets one request to
 * prove itself with, not a stampede from the entire backlog.
 */
export async function checkCircuit(endpointId) {
  const openUntil = await redis.get(openKey(endpointId));
  if (!openUntil) return { allowed: true, state: 'closed' };

  const remainingMs = Number(openUntil) - Date.now();
  if (remainingMs > 0) {
    return { allowed: false, state: 'open', retryAfterSeconds: Math.ceil(remainingMs / 1000) };
  }

  // Cooldown elapsed. SET NX is what makes the probe exclusive: whichever
  // worker sets the key first gets to probe, everyone else is turned away.
  const token = await redis.set(probeKey(endpointId), '1', 'EX', 60, 'NX');
  if (token === 'OK') return { allowed: true, state: 'half-open' };

  return { allowed: false, state: 'open', retryAfterSeconds: 5 };
}

/** A successful delivery closes the circuit and clears the failure history. */
export async function recordSuccess(endpointId) {
  await redis.del(
    failureKey(endpointId),
    openKey(endpointId),
    probeKey(endpointId),
    generationKey(endpointId),
  );
}

/**
 * Records a failure and opens the circuit once the threshold is crossed.
 *
 * Returns { opened, consecutiveFailures, generation, cooldownSeconds }.
 */
export async function recordFailure(endpointId, { wasProbe = false } = {}) {
  if (wasProbe) {
    // A failed half-open probe re-opens immediately with a longer cooldown.
    // Waiting for the counter to climb again would let a dead endpoint be
    // probed every cooldown period forever at the same frequency.
    const generation = await redis.incr(generationKey(endpointId));
    await redis.expire(generationKey(endpointId), MAX_COOLDOWN_SECONDS * 2);
    const cooldownSeconds = cooldownFor(generation);
    await redis.set(openKey(endpointId), String(Date.now() + cooldownSeconds * 1000), 'EX', cooldownSeconds + 60);
    await redis.del(probeKey(endpointId));
    return { opened: true, consecutiveFailures: FAILURE_THRESHOLD, generation, cooldownSeconds };
  }

  const consecutiveFailures = await redis.incr(failureKey(endpointId));
  await redis.expire(failureKey(endpointId), FAILURE_WINDOW_SECONDS);

  if (consecutiveFailures < FAILURE_THRESHOLD) {
    return { opened: false, consecutiveFailures, generation: 0, cooldownSeconds: 0 };
  }

  const generation = await redis.incr(generationKey(endpointId));
  await redis.expire(generationKey(endpointId), MAX_COOLDOWN_SECONDS * 2);
  const cooldownSeconds = cooldownFor(generation);
  await redis.set(openKey(endpointId), String(Date.now() + cooldownSeconds * 1000), 'EX', cooldownSeconds + 60);

  return { opened: true, consecutiveFailures, generation, cooldownSeconds };
}

/** How long an endpoint has been continuously open, for the auto-disable rule. */
export async function openGeneration(endpointId) {
  const generation = await redis.get(generationKey(endpointId));
  return Number(generation ?? 0);
}

export async function resetCircuit(endpointId) {
  await recordSuccess(endpointId);
}

/** Dashboard view of an endpoint's breaker. */
export async function circuitStatus(endpointId) {
  const [openUntil, failures, generation] = await redis.mget(
    openKey(endpointId),
    failureKey(endpointId),
    generationKey(endpointId),
  );

  const remainingMs = openUntil ? Number(openUntil) - Date.now() : 0;
  return {
    state: remainingMs > 0 ? 'open' : openUntil ? 'half-open' : 'closed',
    consecutiveFailures: Number(failures ?? 0),
    openUntil: openUntil ? new Date(Number(openUntil)).toISOString() : null,
    reopenCount: Number(generation ?? 0),
  };
}
