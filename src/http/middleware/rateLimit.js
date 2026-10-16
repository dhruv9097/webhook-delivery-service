import { redis } from '../../redis.js';
import { RateLimitError } from '../../errors.js';
import { logger } from '../../logger.js';

/**
 * Token bucket rate limiting, evaluated atomically in Redis.
 *
 * A bucket holds `capacity` tokens and refills at `refillPerSecond`. Each
 * request takes one. This shape is chosen over a fixed window because a fixed
 * window allows a double-rate burst across a boundary — 100 requests at 11:59:59
 * and 100 more at 12:00:00 is 200 in one second under a "100 per minute" limit.
 * A token bucket bounds the burst by capacity and the sustained rate by refill,
 * independently.
 *
 * The whole read-compute-write runs as one Lua script. Doing it in application
 * code would be a read-modify-write race: under concurrency several workers
 * read the same token count and each decide there is room, letting the limit be
 * exceeded by however many requests arrive together — exactly when the limit
 * matters most.
 *
 * State is stored lazily: a bucket exists in Redis only after its owner's first
 * request, and expires once it would have refilled to full, so idle tenants
 * cost nothing.
 */
const TOKEN_BUCKET = `
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_per_second = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])

local bucket = redis.call('HMGET', key, 'tokens', 'updated_at')
local tokens = tonumber(bucket[1])
local updated_at = tonumber(bucket[2])

if tokens == nil then
  tokens = capacity
  updated_at = now_ms
end

-- Refill for the time elapsed since this bucket was last touched.
local elapsed_ms = math.max(0, now_ms - updated_at)
tokens = math.min(capacity, tokens + (elapsed_ms / 1000.0) * refill_per_second)

local allowed = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
end

redis.call('HMSET', key, 'tokens', tokens, 'updated_at', now_ms)
-- Expire once the bucket would be full again; a full bucket is
-- indistinguishable from a missing one, so keeping it wastes memory.
local ttl = math.ceil(capacity / refill_per_second) + 1
redis.call('EXPIRE', key, ttl)

local retry_after = 0
if allowed == 0 then
  retry_after = math.ceil((cost - tokens) / refill_per_second)
end

return { allowed, math.floor(tokens), retry_after }
`;

let scriptSha = null;

async function consume(key, { capacity, refillPerSecond, cost = 1 }) {
  const args = [String(capacity), String(refillPerSecond), String(Date.now()), String(cost)];

  try {
    if (!scriptSha) scriptSha = await redis.script('LOAD', TOKEN_BUCKET);
    return await redis.evalsha(scriptSha, 1, key, ...args);
  } catch (err) {
    // A restarted or flushed Redis loses the cached script. Reload once rather
    // than failing the request.
    if (String(err.message).includes('NOSCRIPT')) {
      scriptSha = await redis.script('LOAD', TOKEN_BUCKET);
      return redis.evalsha(scriptSha, 1, key, ...args);
    }
    throw err;
  }
}

/**
 * Builds rate limiting middleware.
 *
 * `keyFor` derives the bucket identity from the request — per API key for
 * ingest, per IP for unauthenticated endpoints. Limiting per tenant rather than
 * globally is the point: one noisy customer must not consume the budget that
 * keeps every other customer's events flowing.
 */
export function rateLimit({ capacity, refillPerSecond, keyFor, name = 'default' }) {
  return async function rateLimitMiddleware(req, res, next) {
    let bucketKey;
    try {
      bucketKey = keyFor(req);
    } catch {
      return next();
    }
    if (!bucketKey) return next();

    const key = `ratelimit:${name}:${bucketKey}`;

    let allowed;
    let remaining;
    let retryAfter;
    try {
      [allowed, remaining, retryAfter] = await consume(key, { capacity, refillPerSecond });
    } catch (err) {
      // Fail open. A rate limiter that rejects everything when its datastore is
      // unavailable converts a Redis blip into a full outage, which is a worse
      // failure than briefly allowing traffic through unmetered.
      logger().error({ err, limiter: name }, 'rate limiter unavailable, allowing request');
      return next();
    }

    res.setHeader('RateLimit-Limit', String(capacity));
    res.setHeader('RateLimit-Remaining', String(Math.max(remaining, 0)));
    res.setHeader('RateLimit-Policy', `${capacity};w=${Math.ceil(capacity / refillPerSecond)}`);

    if (allowed === 1) return next();

    res.setHeader('RateLimit-Reset', String(retryAfter));
    return next(new RateLimitError(Math.max(retryAfter, 1)));
  };
}

/** Ingest is the hot path and gets the most generous bucket. */
export const ingestRateLimit = rateLimit({
  name: 'ingest',
  capacity: 500,
  refillPerSecond: 100,
  keyFor: (req) => req.auth?.apiKeyId ?? req.auth?.orgId,
});

/**
 * Authentication is limited by IP and kept deliberately tight: this bucket
 * exists to make password and API-key guessing expensive, not to shape traffic.
 */
export const authRateLimit = rateLimit({
  name: 'auth',
  capacity: 10,
  refillPerSecond: 0.2,
  keyFor: (req) => req.ip,
});

/** Everything else: generous enough to be invisible to normal dashboard use. */
export const generalRateLimit = rateLimit({
  name: 'general',
  capacity: 200,
  refillPerSecond: 20,
  keyFor: (req) => req.auth?.orgId ?? req.ip,
});
