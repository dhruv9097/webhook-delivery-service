import { randomUUID } from 'node:crypto';
import { Agent } from 'undici';
import { config } from './config.js';
import { baseLogger } from './logger.js';
import { disconnectDb } from './db.js';
import { disconnectRedis } from './redis.js';
import { createGuardedLookup } from './security/ssrf.js';
import { reapExpiredLeases } from './delivery/claim.js';
import { purgeExpiredSecrets } from './delivery/maintenance.js';
import { runTick } from './delivery/runner.js';
import { createShutdown } from './shutdown.js';

// Identifies this worker in `locked_by`, so an operator can tell which process
// holds a lease and correlate it with that process's logs.
const workerId = `worker-${process.pid}-${randomUUID().slice(0, 8)}`;

const log = baseLogger.child({ process: 'worker', worker_id: workerId });
const shutdown = createShutdown({ graceSeconds: config.SHUTDOWN_GRACE_SECONDS, logger: log });

// A shared connection pool across all deliveries. Without keep-alive every
// attempt pays a fresh TCP and TLS handshake, which for a customer receiving
// thousands of events dominates the actual delivery time.
const dispatcher = new Agent({
  connect: {
    timeout: config.DELIVERY_CONNECT_TIMEOUT_MS,
    // The SSRF guard lives here, as the pool's resolver, so the address it
    // approves is literally the address the socket connects to. Checking the
    // URL before calling request() would leave a gap between the two
    // resolutions, and that gap is the DNS-rebinding vulnerability.
    lookup: createGuardedLookup({ allowPrivate: config.ALLOW_PRIVATE_DELIVERY_TARGETS }),
  },
  keepAliveTimeout: 10_000,
  keepAliveMaxTimeout: 60_000,
  connections: config.DELIVERY_POOL_CONNECTIONS,
});

let running = true;
let currentTick = Promise.resolve(0);

async function deliveryLoop() {
  while (running) {
    try {
      currentTick = runTick({ workerId, dispatcher });
      const claimed = await currentTick;

      // Only idle when the queue was empty. Sleeping after a full batch would
      // cap throughput at batch-size per poll interval regardless of backlog.
      if (claimed === 0) {
        await new Promise((resolve) => setTimeout(resolve, config.WORKER_POLL_INTERVAL_MS));
      }
    } catch (err) {
      log.error({ err }, 'delivery tick failed');
      await new Promise((resolve) => setTimeout(resolve, config.WORKER_POLL_INTERVAL_MS));
    }
  }
}

/**
 * Reclaims deliveries whose worker died mid-attempt.
 *
 * Every worker runs this, not a designated one. The sweep is a single atomic
 * UPDATE, so concurrent reapers are harmless — and electing a leader would mean
 * the leader's own death stops recovery exactly when it is needed most.
 */
async function reaperLoop() {
  while (running) {
    try {
      const reaped = await reapExpiredLeases();
      if (reaped.length > 0) {
        log.warn(
          {
            count: reaped.length,
            failed_permanent: reaped.filter((r) => r.state === 'FAILED_PERMANENT').length,
          },
          'reclaimed deliveries from expired leases',
        );
      }
      // Piggybacks on the reaper's cadence rather than running its own timer:
      // both are cheap periodic sweeps and there is no reason for two loops.
      const purged = await purgeExpiredSecrets();
      if (purged > 0) {
        log.info({ count: purged }, 'purged signing secrets past their overlap window');
      }
    } catch (err) {
      log.error({ err }, 'reaper sweep failed');
    }
    await new Promise((resolve) => setTimeout(resolve, config.REAPER_INTERVAL_MS));
  }
}

shutdown.register('datastores', async () => {
  await Promise.allSettled([disconnectDb(), disconnectRedis()]);
});

shutdown.register('http-pool', async () => {
  await dispatcher.close();
});

shutdown.register('delivery-loop', async () => {
  running = false;
  // Let the in-flight tick finish rather than abandoning claimed deliveries.
  // The reaper would recover them, but only after a full lease period — so
  // finishing here is the difference between a clean deploy and a minute of
  // stalled deliveries.
  await currentTick.catch(() => {});
});

shutdown.listen();

log.info(
  {
    claim_batch: config.WORKER_CLAIM_BATCH,
    lease_seconds: config.WORKER_LEASE_SECONDS,
    poll_interval_ms: config.WORKER_POLL_INTERVAL_MS,
  },
  'worker started',
);

Promise.all([deliveryLoop(), reaperLoop()]).catch((err) => {
  log.fatal({ err }, 'worker loops exited unexpectedly');
  process.exit(1);
});
