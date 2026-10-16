/**
 * End-to-end SSRF proof.
 *
 * The unit tests exercise the classifier with a fake resolver. This runs a real
 * worker, with a real undici pool, against endpoints a real attacker would
 * register — and asserts no socket is ever opened to them.
 *
 * Run with ALLOW_PRIVATE_DELIVERY_TARGETS forced off, because the local dev
 * default is on (the mock receiver lives on a private address).
 */
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { prisma } from '../../src/db.js';
import { generateSigningSecret } from '../../src/services/apiKeys.js';
import { withExclusiveQueue } from '../chaos/helpers.js';

const ATTACKS = [
  ['http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'AWS instance metadata'],
  // A HOSTNAME that resolves to a private address. This is the case the
  // resolver hook exists for — unlike the literals above, it genuinely goes
  // through DNS. metadata.google.internal would be the realistic example but
  // does not resolve off-GCP, so it would pass for the wrong reason.
  ['http://localhost:5442/', 'hostname resolving to loopback — exercises the resolver hook'],
  ['http://127.0.0.1:5442/', 'loopback — the database itself'],
  ['http://10.0.0.1/admin', 'RFC1918 internal service'],
  ['http://192.168.1.1/', 'home router'],
  ['http://[::ffff:169.254.169.254]/', 'IPv4-mapped metadata bypass'],
  ['http://[::1]:5442/', 'IPv6 loopback'],
  ['file:///etc/passwd', 'local file scheme'],
];

const failures = [];
const check = (ok, description) => {
  process.stdout.write(`  ${ok ? 'PASS' : 'FAIL'}  ${description}\n`);
  if (!ok) failures.push(description);
};

await withExclusiveQueue(async () => {
  let worker;
  let org;
  try {
    org = await prisma.organization.create({
      data: { name: 'SSRF Test', slug: `ssrf-${Date.now().toString(36)}`,
        applications: { create: { name: 'ssrf', environment: 'TEST' } } },
      include: { applications: true },
    });
    const app = org.applications[0];

    const cases = [];
    for (const [url, label] of ATTACKS) {
      const endpoint = await prisma.endpoint.create({
        data: { appId: app.id, url, eventTypes: [], secretCurrent: generateSigningSecret() },
      });
      const event = await prisma.event.create({
        data: { appId: app.id, eventType: 'ssrf.probe', payload: { probe: true } },
      });
      const delivery = await prisma.delivery.create({
        data: { eventId: event.id, endpointId: endpoint.id },
      });
      cases.push({ url, label, deliveryId: delivery.id });
    }

    process.stdout.write(`\n  ${cases.length} hostile endpoints queued; starting a guarded worker\n\n`);

    worker = spawn('node', ['src/worker.js'], {
      env: {
        ...process.env,
        ALLOW_PRIVATE_DELIVERY_TARGETS: 'false',
        WORKER_POLL_INTERVAL_MS: '200',
        DELIVERY_CONNECT_TIMEOUT_MS: '2000',
        DELIVERY_TOTAL_TIMEOUT_MS: '4000',
        WORKER_LEASE_SECONDS: '10',
        LOG_LEVEL: 'error',
        LOG_PRETTY: 'false',
      },
      stdio: 'ignore',
    });

    const deadline = Date.now() + 45_000;
    while (Date.now() < deadline) {
      const pending = await prisma.delivery.count({
        where: { id: { in: cases.map((c) => c.deliveryId) }, state: { notIn: ['FAILED_PERMANENT', 'SUCCEEDED', 'DISCARDED'] } },
      });
      if (pending === 0) break;
      await sleep(400);
    }

    for (const { label, deliveryId } of cases) {
      const row = await prisma.delivery.findUnique({
        where: { id: deliveryId },
        include: { attempts: true },
      });
      const blocked = row.state === 'FAILED_PERMANENT' && /blocked target/i.test(row.lastError ?? '');
      check(blocked, `${label} → refused (${row.state}${blocked ? `: ${row.lastError}` : ''})`);
    }

    // Nothing hostile may have succeeded, and nothing may still be retrying —
    // a retrying blocked target would mean the guard is treating it as
    // transient and will keep trying to reach it.
    const anySuccess = await prisma.delivery.count({
      where: { id: { in: cases.map((c) => c.deliveryId) }, state: 'SUCCEEDED' },
    });
    check(anySuccess === 0, `no hostile endpoint was ever reached (${anySuccess} successes)`);

    const stillTrying = await prisma.delivery.count({
      where: { id: { in: cases.map((c) => c.deliveryId) }, state: { in: ['PENDING', 'RETRYING', 'IN_FLIGHT'] } },
    });
    check(stillTrying === 0, `no blocked target left on the retry schedule (${stillTrying})`);
  } finally {
    worker?.kill('SIGKILL');
    if (org) await prisma.organization.delete({ where: { id: org.id } }).catch(() => {});
    await prisma.$disconnect();
  }
});

process.stdout.write(
  failures.length === 0
    ? '\n  PASS: every SSRF probe was refused before a socket was opened\n\n'
    : `\n  FAIL: ${failures.length} probe(s) were not blocked\n\n`,
);
process.exit(failures.length === 0 ? 0 : 1);
