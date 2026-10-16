/**
 * Crash recovery: SIGKILL a worker mid-delivery, prove nothing is lost.
 *
 * SIGKILL, not SIGTERM. SIGTERM lets the graceful shutdown path run, which is a
 * different (already tested) property. SIGKILL is the real failure: no cleanup,
 * no notification, no lease release. The delivery is left claimed by a process
 * that no longer exists.
 *
 * What must hold afterwards:
 *   1. The delivery is not lost — a surviving worker reclaims and delivers it.
 *   2. X-Relay-Id is identical across the abandoned and the recovered attempt,
 *      so the receiver can recognise the duplicate. This is what makes
 *      at-least-once safe rather than merely honest.
 *   3. attempt_count reflects the abandoned attempt, so the retry schedule
 *      advances instead of looping on attempt 1 forever.
 *
 * Leases and timeouts are compressed here so the test runs in seconds rather
 * than the production minute.
 */
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { prisma } from '../../src/db.js';
import { withExclusiveQueue } from './helpers.js';
import { generateSigningSecret } from '../../src/services/apiKeys.js';

const RECEIVER = process.env.RECEIVER_URL ?? 'http://localhost:4210';

const WORKER_ENV = {
  ...process.env,
  DELIVERY_TOTAL_TIMEOUT_MS: '3000',
  DELIVERY_CONNECT_TIMEOUT_MS: '1000',
  WORKER_LEASE_SECONDS: '5',
  REAPER_INTERVAL_MS: '1000',
  WORKER_POLL_INTERVAL_MS: '300',
  LOG_LEVEL: 'warn',
  LOG_PRETTY: 'false',
};

const receiver = {
  reset: () => fetch(`${RECEIVER}/reset`, { method: 'POST' }),
  mode: (body) => fetch(`${RECEIVER}/mode`, { method: 'POST', body: JSON.stringify(body) }),
  received: () => fetch(`${RECEIVER}/received`).then((r) => r.json()),
};

function startWorker(label) {
  const proc = spawn('node', ['src/worker.js'], { env: WORKER_ENV, stdio: ['ignore', 'pipe', 'pipe'] });
  proc.stderr.on('data', (d) => {
    const line = d.toString();
    if (line.includes('fatal') || line.includes('FATAL')) process.stderr.write(`[${label}] ${line}`);
  });
  return proc;
}

async function waitFor(label, predicate, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await predicate();
    if (value) return value;
    await sleep(200);
  }
  throw new Error(`timed out waiting for: ${label}`);
}

const failures = [];
const check = (ok, description) => {
  process.stdout.write(`  ${ok ? 'PASS' : 'FAIL'}  ${description}\n`);
  if (!ok) failures.push(description);
};

let workerA;
let workerB;

await withExclusiveQueue(async () => {
try {
  await receiver.reset();

  // Fixtures: an endpoint reachable from a host-run worker.
  const org = await prisma.organization.create({
    data: {
      name: 'Chaos Test',
      slug: `chaos-${Date.now().toString(36)}`,
      applications: {
        create: {
          name: 'chaos',
          environment: 'TEST',
          endpoints: {
            create: { url: `${RECEIVER}/hook`, eventTypes: [], secretCurrent: generateSigningSecret() },
          },
        },
      },
    },
    include: { applications: { include: { endpoints: true } } },
  });
  const app = org.applications[0];
  const endpoint = app.endpoints[0];

  // The receiver hangs, so the attempt is genuinely in flight when we kill.
  await receiver.mode({ mode: 'hang' });

  const event = await prisma.event.create({
    data: { appId: app.id, eventType: 'chaos.test', payload: { probe: true } },
  });
  const delivery = await prisma.delivery.create({
    data: { eventId: event.id, endpointId: endpoint.id },
  });

  process.stdout.write('\n  starting worker A\n');
  workerA = startWorker('A');

  const claimed = await waitFor('delivery claimed by worker A', async () => {
    const row = await prisma.delivery.findUnique({ where: { id: delivery.id } });
    return row?.state === 'IN_FLIGHT' && row.lockedBy ? row : null;
  });
  process.stdout.write(`  worker A claimed it (lease holder ${claimed.lockedBy})\n`);

  const receivedBeforeKill = await receiver.received();
  const firstRelayId = receivedBeforeKill.deliveries[0]?.headers['x-relay-id'];

  process.stdout.write('  SIGKILL worker A mid-delivery\n\n');
  workerA.kill('SIGKILL');
  await new Promise((resolve) => workerA.on('exit', resolve));
  workerA = null;

  const stranded = await prisma.delivery.findUnique({ where: { id: delivery.id } });
  check(stranded.state === 'IN_FLIGHT', 'delivery is stranded IN_FLIGHT after the kill');
  check(stranded.attemptCount === 1, 'the abandoned attempt still counted (attempt_count = 1)');

  // Receiver recovers; a surviving worker should now finish the job.
  await receiver.mode({ mode: 'ok' });
  process.stdout.write('  starting worker B (receiver now healthy)\n');
  workerB = startWorker('B');

  const recovered = await waitFor(
    'delivery recovered and succeeded',
    async () => {
      const row = await prisma.delivery.findUnique({ where: { id: delivery.id }, include: { attempts: true } });
      return row?.state === 'SUCCEEDED' ? row : null;
    },
    30_000,
  );

  process.stdout.write('\n');
  check(true, 'a surviving worker reclaimed the expired lease and delivered it');
  check(recovered.attemptCount >= 2, `retry schedule advanced (attempt_count = ${recovered.attemptCount})`);
  check(recovered.lockedBy === null, 'lease released on completion');

  const after = await receiver.received();
  const relayIds = new Set(after.deliveries.map((d) => d.headers['x-relay-id']));
  check(
    relayIds.size === 1 && (!firstRelayId || relayIds.has(firstRelayId)),
    `X-Relay-Id stable across the crash (${relayIds.size} distinct id across ${after.count} deliveries)`,
  );

  const successes = await prisma.deliveryAttempt.count({
    where: { deliveryId: delivery.id, responseStatus: { gte: 200, lt: 300 } },
  });
  check(successes === 1, `exactly one attempt succeeded (${successes})`);

  await prisma.organization.delete({ where: { id: org.id } });
} finally {
  workerA?.kill('SIGKILL');
  workerB?.kill('SIGTERM');
  await receiver.reset().catch(() => {});
  await prisma.$disconnect();
}
});

process.stdout.write(
  failures.length === 0
    ? '\n  PASS: no deliveries lost, duplicated, or stalled across a worker crash\n\n'
    : `\n  FAIL: ${failures.length} assertion(s) failed\n\n`,
);
process.exit(failures.length === 0 ? 0 : 1);
