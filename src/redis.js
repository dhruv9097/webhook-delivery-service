import Redis from 'ioredis';
import { config } from './config.js';
import { baseLogger } from './logger.js';

function create(name, options = {}) {
  const client = new Redis(config.REDIS_URL, {
    // BullMQ requires this to be null on its connections; keeping it uniform
    // avoids commands failing after a reconnect elsewhere too.
    maxRetriesPerRequest: null,
    enableReadyCheck: true,
    lazyConnect: false,
    ...options,
  });

  client.on('error', (err) => baseLogger.error({ err, redis: name }, 'redis error'));
  client.on('reconnecting', () => baseLogger.warn({ redis: name }, 'redis reconnecting'));

  return client;
}

// Shared client for ordinary commands: rate limit buckets, circuit breaker
// counters, idempotency caching.
export const redis = create('main');

/**
 * BullMQ needs its own connections — a blocking connection cannot serve
 * ordinary commands. Callers own the returned client and must close it.
 */
export function createQueueConnection(name) {
  return create(name);
}

export async function disconnectRedis() {
  await redis.quit();
}

export async function pingRedis() {
  const reply = await redis.ping();
  if (reply !== 'PONG') throw new Error(`unexpected redis ping reply: ${reply}`);
}
