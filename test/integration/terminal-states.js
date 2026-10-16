/**
 * The terminal branches of the delivery state machine.
 *
 * These are the paths that take 24 hours or a specific receiver behaviour to
 * reach in normal operation, so they are the ones least likely to be exercised
 * by hand and most likely to be silently wrong. Each is driven directly by
 * seeding the delivery into the precondition rather than waiting for it.
 */
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { prisma } from '../../src/db.js';
import { MAX_ATTEMPTS } from '../../src/delivery/backoff.js';
import { generateSigningSecret } from '../../src/services/apiKeys.js';
import { withExclusiveQueue } from '../chaos/helpers.js';

const RECEIVER = process.env.RECEIVER_URL ?? 'http://localhost:4210';

const failures = [];
const check = (ok, description) => {
  process.stdout.write(`  ${ok ? 'PASS' : 'FAIL'}  ${description}\n`);
  if (!ok) failures.push(description);
};

async function waitForState(deliveryId, timeoutMs = 25_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const row = await prisma.delivery.findUnique({ where: { id: deliveryId } });
    if (['SUCCEEDED', 'FAILED_PERMANENT', 'DISCARDED'].includes(row.state)) return row;
    await sleep(200);
  }
  return prisma.delivery.findUnique({ where: { id: deliveryId } });
}

await withExclusiveQueue(async () => {
  let worker;
  let org;
  try {
    await fetch(`${RECEIVER}/reset`, { method: 'POST' });

    org = await prisma.organization.create({
      data: {
        name: 'State Machine Test',
        slug: `states-${Date.now().toString(36)}`,
        applications: {
          create: {
            name: 'states',
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

    const makeDelivery = async (data = {}) => {
      const event = await prisma.event.create({
        data: { appId: app.id, eventType: 'state.test', payload: {} },
      });
      return prisma.delivery.create({
        data: { eventId: event.id, endpointId: endpoint.id, ...data },
      });
    };

    worker = spawn('node', ['src/worker.js'], {
      env: { ...process.env, WORKER_POLL_INTERVAL_MS: '200', LOG_LEVEL: 'error', LOG_PRETTY: 'false' },
      stdio: 'ignore',
    });

    // --- 1. 410 Gone is a permanent verdict, not a retry ---
    process.stdout.write('\n  410 Gone\n');
    await fetch(`${RECEIVER}/mode`, { method: 'POST', body: JSON.stringify({ mode: 'fail', status: 410 }) });
    const gone = await waitForState((await makeDelivery()).id);
    check(gone.state === 'FAILED_PERMANENT', `410 -> FAILED_PERMANENT (got ${gone.state})`);
    check(gone.attemptCount === 1, `abandoned after a single attempt, not retried (${gone.attemptCount})`);
    check(/gone/i.test(gone.lastError ?? ''), `reason records the receiver's verdict ("${gone.lastError}")`);

    // --- 2. A 500 is NOT permanent: it retries ---
    process.stdout.write('\n  500 Internal Server Error\n');
    await fetch(`${RECEIVER}/mode`, { method: 'POST', body: JSON.stringify({ mode: 'fail', status: 500 }) });
    const transient = await makeDelivery();
    await sleep(3000);
    const retrying = await prisma.delivery.findUnique({ where: { id: transient.id } });
    check(
      ['RETRYING', 'IN_FLIGHT'].includes(retrying.state),
      `500 -> still retrying, not abandoned (${retrying.state})`,
    );
    check(retrying.nextAttemptAt > new Date(Date.now() - 1000), 'a future retry is scheduled');

    // --- 3. Exhausting the schedule ends in FAILED_PERMANENT ---
    process.stdout.write('\n  Retry schedule exhaustion\n');
    const nearlyDone = await makeDelivery({ attemptCount: MAX_ATTEMPTS - 1 });
    const exhausted = await waitForState(nearlyDone.id);
    check(
      exhausted.state === 'FAILED_PERMANENT',
      `attempt ${MAX_ATTEMPTS} failing -> FAILED_PERMANENT (got ${exhausted.state})`,
    );
    check(/exhausted/i.test(exhausted.lastError ?? ''), `reason says exhausted ("${exhausted.lastError}")`);
    check(exhausted.completedAt !== null, 'completedAt is stamped on a terminal failure');

    // --- 4. An endpoint disabled after fan-out discards rather than retries ---
    process.stdout.write('\n  Endpoint disabled mid-flight\n');
    await prisma.endpoint.update({
      where: { id: endpoint.id },
      data: { state: 'DISABLED', disabledAt: new Date() },
    });
    const orphan = await makeDelivery();
    const discarded = await waitForState(orphan.id);
    check(discarded.state === 'DISCARDED', `disabled endpoint -> DISCARDED (got ${discarded.state})`);

    // --- 5. Terminal deliveries always release their lease ---
    const leaked = await prisma.delivery.count({
      where: {
        endpointId: endpoint.id,
        state: { in: ['SUCCEEDED', 'FAILED_PERMANENT', 'DISCARDED'] },
        OR: [{ lockedBy: { not: null } }, { lockedUntil: { not: null } }],
      },
    });
    process.stdout.write('\n  Lease hygiene\n');
    check(leaked === 0, `no terminal delivery still holds a lease (${leaked})`);
  } finally {
    worker?.kill('SIGKILL');
    if (org) await prisma.organization.delete({ where: { id: org.id } }).catch(() => {});
    await fetch(`${RECEIVER}/reset`, { method: 'POST' }).catch(() => {});
    await prisma.$disconnect();
  }
});

process.stdout.write(
  failures.length === 0
    ? '\n  PASS: every terminal branch behaves as specified\n\n'
    : `\n  FAIL: ${failures.length} assertion(s) failed\n\n`,
);
process.exit(failures.length === 0 ? 0 : 1);
