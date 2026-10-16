/**
 * Concurrency: N workers, one queue, no double delivery.
 *
 * The claim query's correctness rests entirely on FOR UPDATE SKIP LOCKED. If it
 * were a plain SELECT-then-UPDATE, two workers polling simultaneously would
 * both read the same due rows and both deliver them, and every receiver would
 * see duplicates under load. That failure is invisible with one worker, which
 * is exactly why it needs a dedicated test.
 *
 * Asserted: with a healthy receiver, total successful attempts equals the
 * number of deliveries. Any double-claim shows up as an extra attempt.
 */
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { prisma } from '../../src/db.js';
import { withExclusiveQueue } from './helpers.js';
import { generateSigningSecret } from '../../src/services/apiKeys.js';

const RECEIVER = process.env.RECEIVER_URL ?? 'http://localhost:4210';
const WORKERS = Number(process.env.WORKERS ?? 4);
const EVENTS = Number(process.env.EVENTS ?? 60);

const WORKER_ENV = {
  ...process.env,
  WORKER_POLL_INTERVAL_MS: '100',
  // Small batches force workers to contend on the same query repeatedly
  // instead of one worker draining the queue in a single sweep.
  WORKER_CLAIM_BATCH: '5',
  LOG_LEVEL: 'error',
  LOG_PRETTY: 'false',
};

const failures = [];
const check = (ok, description) => {
  process.stdout.write(`  ${ok ? 'PASS' : 'FAIL'}  ${description}\n`);
  if (!ok) failures.push(description);
};

const workers = [];
let org;

await withExclusiveQueue(async () => {
try {
  await fetch(`${RECEIVER}/reset`, { method: 'POST' });

  org = await prisma.organization.create({
    data: {
      name: 'Concurrency Test',
      slug: `conc-${Date.now().toString(36)}`,
      applications: {
        create: {
          name: 'conc',
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

  // Queue everything up front so all workers start against a full backlog.
  const events = await prisma.$transaction(
    Array.from({ length: EVENTS }, (_, i) =>
      prisma.event.create({ data: { appId: app.id, eventType: 'load.test', payload: { i } } }),
    ),
  );
  await prisma.delivery.createMany({
    data: events.map((e) => ({ eventId: e.id, endpointId: endpoint.id })),
  });

  process.stdout.write(`\n  queued ${EVENTS} deliveries, starting ${WORKERS} workers\n\n`);

  for (let i = 0; i < WORKERS; i += 1) {
    workers.push(spawn('node', ['src/worker.js'], { env: WORKER_ENV, stdio: 'ignore' }));
  }

  const startedAt = Date.now();
  const deadline = startedAt + 60_000;
  let done = 0;
  while (Date.now() < deadline) {
    done = await prisma.delivery.count({
      where: { endpointId: endpoint.id, state: 'SUCCEEDED' },
    });
    if (done === EVENTS) break;
    await sleep(250);
  }
  const elapsedMs = Date.now() - startedAt;

  check(done === EVENTS, `all ${EVENTS} deliveries succeeded (${done})`);

  const attempts = await prisma.deliveryAttempt.count({
    where: { delivery: { endpointId: endpoint.id } },
  });
  if (attempts !== EVENTS) {
    const byKind = await prisma.deliveryAttempt.groupBy({
      by: ['errorKind'],
      where: { delivery: { endpointId: endpoint.id } },
      _count: true,
    });
    process.stdout.write('  attempt breakdown by outcome:\n');
    for (const row of byKind) {
      process.stdout.write(`      ${row.errorKind ?? 'success'}: ${row._count}\n`);
    }
  }
  check(attempts === EVENTS, `exactly one attempt per delivery — no double-claim (${attempts} attempts)`);

  const receiverSaw = await fetch(`${RECEIVER}/received`).then((r) => r.json());
  check(
    receiverSaw.count === EVENTS,
    `receiver saw each event exactly once (${receiverSaw.count} requests)`,
  );

  const relayIds = new Set(receiverSaw.deliveries.map((d) => d.headers['x-relay-id']));
  check(relayIds.size === EVENTS, `every delivery had a distinct X-Relay-Id (${relayIds.size})`);

  const stuck = await prisma.delivery.count({
    where: { endpointId: endpoint.id, state: { in: ['IN_FLIGHT', 'PENDING', 'RETRYING'] } },
  });
  check(stuck === 0, `no deliveries left unfinished (${stuck})`);

  process.stdout.write(
    `\n  drained ${EVENTS} deliveries across ${WORKERS} workers in ${elapsedMs}ms ` +
      `(~${Math.round((EVENTS / elapsedMs) * 1000)}/s)\n`,
  );
} finally {
  for (const w of workers) w.kill('SIGKILL');
  if (org) await prisma.organization.delete({ where: { id: org.id } }).catch(() => {});
  await fetch(`${RECEIVER}/reset`, { method: 'POST' }).catch(() => {});
  await prisma.$disconnect();
}
});

process.stdout.write(
  failures.length === 0
    ? '\n  PASS: SKIP LOCKED held — no delivery was claimed by two workers\n\n'
    : `\n  FAIL: ${failures.length} assertion(s) failed\n\n`,
);
process.exit(failures.length === 0 ? 0 : 1);
