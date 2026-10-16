/**
 * Circuit breaker behaviour, and the property that justifies it: failure
 * isolation between tenants.
 *
 * The headline assertion is the last one. A dead endpoint and a healthy one
 * share a worker pool; without a breaker the dead one consumes a worker slot
 * for its full connect timeout on every attempt, and the healthy tenant's
 * deliveries queue behind it. With a breaker, the dead endpoint stops opening
 * sockets and the healthy tenant is unaffected.
 */
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { prisma } from '../../src/db.js';
import { circuitStatus, resetCircuit, FAILURE_THRESHOLD } from '../../src/delivery/circuit.js';
import { redis } from '../../src/redis.js';
import { generateSigningSecret } from '../../src/services/apiKeys.js';
import { withExclusiveQueue } from '../chaos/helpers.js';

const RECEIVER = process.env.RECEIVER_URL ?? 'http://localhost:4210';

const failures = [];
const check = (ok, description) => {
  process.stdout.write(`  ${ok ? 'PASS' : 'FAIL'}  ${description}\n`);
  if (!ok) failures.push(description);
};

await withExclusiveQueue(async () => {
  let worker;
  let org;
  try {
    await fetch(`${RECEIVER}/reset`, { method: 'POST' });

    org = await prisma.organization.create({
      data: {
        name: 'Breaker Test',
        slug: `breaker-${Date.now().toString(36)}`,
        applications: { create: { name: 'breaker', environment: 'TEST' } },
      },
      include: { applications: true },
    });
    const app = org.applications[0];

    // One endpoint nothing is listening on, one that works.
    const dead = await prisma.endpoint.create({
      data: { appId: app.id, url: 'http://127.0.0.1:9/hook', eventTypes: [], secretCurrent: generateSigningSecret() },
    });
    const healthy = await prisma.endpoint.create({
      data: { appId: app.id, url: `${RECEIVER}/hook`, eventTypes: [], secretCurrent: generateSigningSecret() },
    });
    await resetCircuit(dead.id);
    await resetCircuit(healthy.id);

    const queue = async (endpointId, count) => {
      const ids = [];
      for (let i = 0; i < count; i += 1) {
        const event = await prisma.event.create({
          data: { appId: app.id, eventType: 'breaker.test', payload: { i } },
        });
        const delivery = await prisma.delivery.create({
          data: { eventId: event.id, endpointId },
        });
        ids.push(delivery.id);
      }
      return ids;
    };

    // Enough traffic to the dead endpoint to cross the threshold.
    const deadIds = await queue(dead.id, FAILURE_THRESHOLD + 10);
    const healthyIds = await queue(healthy.id, 10);

    process.stdout.write(
      `\n  queued ${deadIds.length} deliveries to a dead endpoint and ${healthyIds.length} to a healthy one\n\n`,
    );

    worker = spawn('node', ['src/worker.js'], {
      env: {
        ...process.env,
        ALLOW_PRIVATE_DELIVERY_TARGETS: 'true',
        WORKER_POLL_INTERVAL_MS: '150',
        WORKER_CLAIM_BATCH: '10',
        DELIVERY_CONNECT_TIMEOUT_MS: '500',
        DELIVERY_TOTAL_TIMEOUT_MS: '1000',
        WORKER_LEASE_SECONDS: '10',
        LOG_LEVEL: 'error',
        LOG_PRETTY: 'false',
      },
      stdio: 'ignore',
    });

    // The healthy tenant must drain regardless of the dead one's state.
    const deadline = Date.now() + 40_000;
    let healthyDone = 0;
    while (Date.now() < deadline) {
      healthyDone = await prisma.delivery.count({
        where: { id: { in: healthyIds }, state: 'SUCCEEDED' },
      });
      if (healthyDone === healthyIds.length) break;
      await sleep(250);
    }

    const status = await circuitStatus(dead.id);
    process.stdout.write(`  dead endpoint circuit: ${JSON.stringify(status)}\n\n`);

    check(status.state !== 'closed', `circuit opened for the dead endpoint (state=${status.state})`);
    check(status.reopenCount >= 1, `breaker recorded at least one open cycle (${status.reopenCount})`);

    // The point of the whole mechanism.
    check(
      healthyDone === healthyIds.length,
      `healthy tenant fully delivered despite the dead endpoint (${healthyDone}/${healthyIds.length})`,
    );

    // Attempts to the dead endpoint must be bounded by the threshold rather
    // than growing with the queue depth — that gap is the saved worker time.
    const deadAttempts = await prisma.deliveryAttempt.count({
      where: { delivery: { endpointId: dead.id } },
    });
    const budgetSpent = await prisma.delivery.aggregate({
      where: { id: { in: deadIds }, lastError: 'circuit_open' },
      _max: { attemptCount: true },
    });
    const deferred = await prisma.delivery.count({
      where: { id: { in: deadIds }, lastError: 'circuit_open' },
    });
    process.stdout.write(`  attempts actually made to the dead endpoint: ${deadAttempts}\n`);
    process.stdout.write(`  deliveries deferred without opening a socket: ${deferred}\n\n`);

    check(
      deadAttempts < deadIds.length,
      `breaker prevented sockets — ${deadAttempts} attempts for ${deadIds.length} queued deliveries`,
    );
    check(deferred > 0, `deliveries were deferred by the open circuit (${deferred})`);
    // A deferral must not spend retry budget: nothing was sent, so nothing was
    // attempted. Otherwise a delivery can exhaust all eight attempts behind an
    // open circuit and be abandoned without ever reaching the network.
    check(
      (budgetSpent._max.attemptCount ?? 0) === 0,
      `deferred deliveries spent no retry budget (max attemptCount = ${budgetSpent._max.attemptCount ?? 0})`,
    );

    // Recovery: clearing the breaker lets the endpoint be tried again.
    await resetCircuit(dead.id);
    const afterReset = await circuitStatus(dead.id);
    check(afterReset.state === 'closed', `circuit closes on reset (state=${afterReset.state})`);
  } finally {
    worker?.kill('SIGKILL');
    if (org) await prisma.organization.delete({ where: { id: org.id } }).catch(() => {});
    await fetch(`${RECEIVER}/reset`, { method: 'POST' }).catch(() => {});
    await redis.quit().catch(() => {});
    await prisma.$disconnect();
  }
});

process.stdout.write(
  failures.length === 0
    ? '\n  PASS: a dead endpoint trips its breaker and cannot degrade another tenant\n\n'
    : `\n  FAIL: ${failures.length} assertion(s) failed\n\n`,
);
process.exit(failures.length === 0 ? 0 : 1);
