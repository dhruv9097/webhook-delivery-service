import { z } from 'zod';

// Load .env when present. In Docker the environment is injected directly and
// no .env file exists, so a miss here is expected and harmless.
try {
  process.loadEnvFile();
} catch {
  // no .env on disk — fall through to the real environment
}

// Env vars arrive as strings; these coerce and bound them so the rest of the
// codebase can treat config values as real numbers and booleans.
const int = (min, max) => z.coerce.number().int().min(min).max(max);
const bool = z
  .enum(['true', 'false'])
  .transform((v) => v === 'true');

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  // Human-readable log output. Its own switch rather than a function of
  // NODE_ENV: the containerised dev stack is genuinely a development
  // environment but runs an image built without dev dependencies, so it
  // needs development semantics with production log transport.
  LOG_PRETTY: bool.default('false'),

  PORT: int(1, 65535).default(3000),
  SHUTDOWN_GRACE_SECONDS: int(1, 300).default(15),

  DATABASE_URL: z.string().url(),
  REDIS_URL: z.string().url(),

  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  JWT_TTL_SECONDS: int(60, 86400).default(3600),

  // How long a rotated-out signing secret keeps verifying. This is the whole
  // point of rotation: without an expiry the old secret stays valid forever and
  // rotating revokes nothing. Long enough for a customer to deploy their new
  // secret, short enough that a leaked one stops working.
  SECRET_OVERLAP_SECONDS: int(60, 604800).default(86400),

  // Key for encrypting endpoint signing secrets at rest. 32 bytes of hex.
  // Signing secrets cannot be hashed — we need the value to sign with — so
  // encryption with a key held outside the database is the only protection
  // available against a dump. Generate with: openssl rand -hex 32
  SECRET_ENCRYPTION_KEY: z
    .string()
    .regex(/^[0-9a-fA-F]{64}$/, 'SECRET_ENCRYPTION_KEY must be 64 hex characters (32 bytes)'),

  WORKER_CLAIM_BATCH: int(1, 1000).default(20),
  WORKER_LEASE_SECONDS: int(5, 3600).default(60),
  WORKER_POLL_INTERVAL_MS: int(50, 60000).default(1000),
  REAPER_INTERVAL_MS: int(1000, 300000).default(10000),

  DELIVERY_CONNECT_TIMEOUT_MS: int(100, 60000).default(5000),
  DELIVERY_TOTAL_TIMEOUT_MS: int(100, 300000).default(30000),
  DELIVERY_MAX_RESPONSE_BYTES: int(256, 1048576).default(4096),
  // Max simultaneous connections the worker's HTTP pool holds PER ORIGIN.
  // Surfaced as config rather than hardcoded because the lease invariant below
  // depends on it.
  DELIVERY_POOL_CONNECTIONS: int(1, 1024).default(128),
  ALLOW_PRIVATE_DELIVERY_TARGETS: bool.default('false'),
});

const parsed = schema.safeParse(process.env);

if (!parsed.success) {
  // Fail fast and loudly. A process that boots with bad config and only
  // discovers it on the first request is strictly worse than one that refuses
  // to start — the failure shows up in the deploy, not in production traffic.
  const issues = parsed.error.issues
    .map((i) => `  ${i.path.join('.') || '(root)'}: ${i.message}`)
    .join('\n');
  process.stderr.write(`Invalid environment configuration:\n${issues}\n`);
  process.exit(1);
}

export const config = Object.freeze(parsed.data);

// The lease must outlive the slowest delivery in a claimed batch.
//
// The obvious check — lease > one delivery's timeout — is not sufficient, and
// an earlier version of this file shipped exactly that, which was worse than no
// check because it looked like the lease math was handled.
//
// A batch is delivered concurrently, but concurrency is capped by the HTTP
// pool, and that cap is PER ORIGIN. In the worst realistic case every delivery
// in a batch targets the same customer host, so they run in waves of
// DELIVERY_POOL_CONNECTIONS. The last delivery in the batch therefore cannot
// finish until ceil(batch / connections) timeouts have elapsed. If the lease
// expires first, the reaper hands a still-running delivery to another worker
// and the receiver gets it twice.
const deliveryWaves = Math.ceil(config.WORKER_CLAIM_BATCH / config.DELIVERY_POOL_CONNECTIONS);
const worstCaseBatchMs = deliveryWaves * config.DELIVERY_TOTAL_TIMEOUT_MS;

if (config.WORKER_LEASE_SECONDS * 1000 <= worstCaseBatchMs) {
  process.stderr.write(
    `Invalid configuration: WORKER_LEASE_SECONDS (${config.WORKER_LEASE_SECONDS}s) must exceed the ` +
      `worst-case batch duration of ${worstCaseBatchMs}ms.\n\n` +
      `  WORKER_CLAIM_BATCH        = ${config.WORKER_CLAIM_BATCH}\n` +
      `  DELIVERY_POOL_CONNECTIONS = ${config.DELIVERY_POOL_CONNECTIONS}\n` +
      `  DELIVERY_TOTAL_TIMEOUT_MS = ${config.DELIVERY_TOTAL_TIMEOUT_MS}\n` +
      `  => ${deliveryWaves} wave(s) x ${config.DELIVERY_TOTAL_TIMEOUT_MS}ms = ${worstCaseBatchMs}ms\n\n` +
      `A batch larger than the pool queues behind it, so deliveries can lose their lease ` +
      `mid-flight and be delivered twice. Raise WORKER_LEASE_SECONDS, lower WORKER_CLAIM_BATCH, ` +
      `or raise DELIVERY_POOL_CONNECTIONS.\n`,
  );
  process.exit(1);
}

if (config.NODE_ENV === 'production' && config.ALLOW_PRIVATE_DELIVERY_TARGETS) {
  process.stderr.write(
    'Refusing to start: ALLOW_PRIVATE_DELIVERY_TARGETS disables the SSRF private-range ' +
      'denylist and must never be enabled in production.\n',
  );
  process.exit(1);
}

export const isProduction = config.NODE_ENV === 'production';
export const isTest = config.NODE_ENV === 'test';
