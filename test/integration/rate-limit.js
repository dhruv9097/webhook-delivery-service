/**
 * Rate limiter atomicity.
 *
 * Sequential requests would pass even with a naive read-modify-write limiter.
 * The property worth testing is what happens when requests arrive together:
 * without the Lua script, concurrent callers each read the same token count,
 * each conclude there is room, and the limit is exceeded by roughly the
 * concurrency level — precisely when a limiter is most needed.
 */
import { redis } from '../../src/redis.js';
import { rateLimit } from '../../src/http/middleware/rateLimit.js';

const failures = [];
const check = (ok, description) => {
  process.stdout.write(`  ${ok ? 'PASS' : 'FAIL'}  ${description}\n`);
  if (!ok) failures.push(description);
};

/** Drives the middleware directly — no HTTP server needed. */
function callLimiter(middleware, key) {
  const req = { ip: key, auth: { orgId: key } };
  const res = { setHeader() {} };
  return new Promise((resolve) => middleware(req, res, (err) => resolve(err ? 'limited' : 'allowed')));
}

try {
  const CAPACITY = 25;
  const BURST = 200;

  const bucket = `concurrency-${Date.now()}`;
  const limiter = rateLimit({
    name: `test-${Date.now()}`,
    capacity: CAPACITY,
    // Slow refill so nothing meaningfully replenishes during the burst.
    refillPerSecond: 0.1,
    keyFor: (req) => req.ip,
  });

  process.stdout.write(`\n  firing ${BURST} simultaneous requests at a bucket of ${CAPACITY}\n\n`);
  const outcomes = await Promise.all(Array.from({ length: BURST }, () => callLimiter(limiter, bucket)));
  const allowed = outcomes.filter((o) => o === 'allowed').length;

  check(
    allowed === CAPACITY,
    `exactly ${CAPACITY} of ${BURST} concurrent requests allowed (got ${allowed}) — no read-modify-write race`,
  );

  // Refill: after a wait, tokens should reappear at the configured rate, not
  // all at once.
  const refillLimiter = rateLimit({
    name: `refill-${Date.now()}`,
    capacity: 5,
    refillPerSecond: 5,
    keyFor: (req) => req.ip,
  });
  const refillBucket = `refill-${Date.now()}`;

  const drained = await Promise.all(
    Array.from({ length: 5 }, () => callLimiter(refillLimiter, refillBucket)),
  );
  check(drained.every((o) => o === 'allowed'), 'a fresh bucket allows its full capacity');
  check((await callLimiter(refillLimiter, refillBucket)) === 'limited', 'the next request is limited');

  await new Promise((resolve) => setTimeout(resolve, 1100));
  check(
    (await callLimiter(refillLimiter, refillBucket)) === 'allowed',
    'tokens refill over time and the bucket recovers',
  );

  // Independence: one tenant exhausting their bucket must not affect another.
  const noisy = `noisy-${Date.now()}`;
  const quiet = `quiet-${Date.now()}`;
  const shared = rateLimit({
    name: `tenancy-${Date.now()}`,
    capacity: 3,
    refillPerSecond: 0.1,
    keyFor: (req) => req.ip,
  });

  await Promise.all(Array.from({ length: 20 }, () => callLimiter(shared, noisy)));
  check(
    (await callLimiter(shared, noisy)) === 'limited',
    'the noisy tenant is limited after exhausting their bucket',
  );
  check(
    (await callLimiter(shared, quiet)) === 'allowed',
    'a quiet tenant is unaffected by the noisy one',
  );
} finally {
  await redis.quit().catch(() => {});
}

process.stdout.write(
  failures.length === 0
    ? '\n  PASS: the limiter is atomic, refills correctly, and isolates tenants\n\n'
    : `\n  FAIL: ${failures.length} assertion(s) failed\n\n`,
);
process.exit(failures.length === 0 ? 0 : 1);
