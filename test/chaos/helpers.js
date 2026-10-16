import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

/**
 * Chaos tests need exclusive ownership of the delivery queue.
 *
 * The Compose `worker` service polls the same Postgres table, so if it is left
 * running it claims some of the test's deliveries. Worse, it cannot reach a
 * receiver on the host's loopback address — from inside the container
 * `localhost:4210` is the container itself — so those claims fail with
 * connection_refused and retry, inflating attempt counts and masking the
 * property under test.
 *
 * That interference is an artifact of the split host/container test setup, not
 * a system defect: in a real deployment every worker is network-equivalent.
 * Still, a test that silently shares its queue is not testing what it claims,
 * so take the service down for the duration and restore it afterwards.
 */
export async function withExclusiveQueue(body) {
  let wasRunning = false;
  try {
    const { stdout } = await run('docker', ['compose', 'ps', '--status=running', '--services']);
    wasRunning = stdout.split('\n').includes('worker');
  } catch {
    // No Compose stack here — nothing competing, nothing to restore.
  }

  if (wasRunning) {
    process.stdout.write('  (stopping the Compose worker so this test owns the queue)\n');
    await run('docker', ['compose', 'stop', 'worker']);
  }

  try {
    return await body();
  } finally {
    if (wasRunning) {
      await run('docker', ['compose', 'start', 'worker']).catch(() => {});
      process.stdout.write('  (Compose worker restarted)\n');
    }
  }
}
