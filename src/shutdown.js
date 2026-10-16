import { baseLogger } from './logger.js';

/**
 * Coordinated graceful shutdown, shared by the api and worker entrypoints.
 *
 * Wired on day one rather than retrofitted, because "drain cleanly on SIGTERM"
 * is an assumption the rest of the system gets to make: the worker's lease
 * release and the API's request draining both depend on this running.
 *
 * Sequence on SIGTERM:
 *   1. Flip to draining, so /health and /ready start returning 503 and the
 *      load balancer stops sending new work here.
 *   2. Run registered hooks in reverse registration order (LIFO), so resources
 *      are torn down in the opposite order they were built up.
 *   3. Exit. A hard timer guarantees exit even if a hook hangs.
 */
export function createShutdown({ graceSeconds, logger = baseLogger }) {
  const hooks = [];
  let draining = false;
  let shuttingDown = false;

  function register(name, fn) {
    hooks.push({ name, fn });
  }

  function isDraining() {
    return draining;
  }

  async function run(signal) {
    // A second SIGTERM while already draining means someone is impatient.
    // Honour it: exit immediately rather than ignoring the operator.
    if (shuttingDown) {
      logger.warn({ signal }, 'second shutdown signal — exiting immediately');
      process.exit(1);
    }
    shuttingDown = true;
    draining = true;

    logger.info({ signal, grace_seconds: graceSeconds }, 'shutdown initiated, draining');

    // Unref'd so this timer cannot itself keep the event loop alive once
    // everything else has finished and the process is ready to exit naturally.
    const hardStop = setTimeout(() => {
      logger.error({ grace_seconds: graceSeconds }, 'grace period expired — forcing exit');
      process.exit(1);
    }, graceSeconds * 1000);
    hardStop.unref();

    for (const { name, fn } of [...hooks].reverse()) {
      try {
        await fn();
        logger.info({ hook: name }, 'shutdown hook complete');
      } catch (err) {
        // One failing hook must not prevent the rest from running; a stuck
        // database disconnect should still let us release worker leases.
        logger.error({ err, hook: name }, 'shutdown hook failed');
      }
    }

    logger.info('shutdown complete');
    clearTimeout(hardStop);
    process.exit(0);
  }

  function listen() {
    for (const signal of ['SIGTERM', 'SIGINT']) {
      process.on(signal, () => {
        run(signal).catch((err) => {
          logger.error({ err }, 'shutdown failed');
          process.exit(1);
        });
      });
    }

    // An unhandled rejection or uncaught exception has left the process in an
    // unknown state. Attempt an orderly exit, but do not pretend it is healthy.
    process.on('unhandledRejection', (reason) => {
      logger.fatal({ err: reason }, 'unhandled promise rejection');
      run('unhandledRejection').catch(() => process.exit(1));
    });
    process.on('uncaughtException', (err) => {
      logger.fatal({ err }, 'uncaught exception');
      run('uncaughtException').catch(() => process.exit(1));
    });
  }

  return { register, listen, isDraining };
}
