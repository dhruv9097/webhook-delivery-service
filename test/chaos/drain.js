/**
 * Graceful shutdown verification.
 *
 * The claim under test is narrow and specific: a request the server has already
 * ACCEPTED completes with a full response, even if SIGTERM arrives mid-flight.
 *
 * Requests that never got a connection are NOT failures — after close() the
 * listener is gone and the kernel refuses new connections, which is exactly
 * what should happen while a load balancer drains this instance. Conflating
 * those two outcomes is what makes naive drain tests report false failures.
 *
 * So each request is classified as:
 *   completed  - got a full HTTP response          (must be 100% of accepted)
 *   refused    - never connected                   (expected, not a failure)
 *   DROPPED    - connected, then reset/truncated   (the actual bug)
 */
import { spawn } from 'node:child_process';
import { request } from 'node:http';

const PORT = Number(process.env.PORT ?? 3310);
const CONCURRENCY = Number(process.env.CONCURRENCY ?? 150);

function fire(path) {
  return new Promise((resolve) => {
    let connected = false;
    const req = request({ host: '127.0.0.1', port: PORT, path, timeout: 20_000 }, (res) => {
      res.resume();
      res.on('end', () => resolve({ outcome: 'completed', status: res.statusCode }));
      res.on('aborted', () => resolve({ outcome: 'DROPPED', reason: 'response aborted' }));
    });
    req.on('socket', (s) => s.on('connect', () => { connected = true; }));
    req.on('error', (err) => {
      // Connected then failed = we accepted work and did not finish it.
      resolve(connected
        ? { outcome: 'DROPPED', reason: err.code }
        : { outcome: 'refused', reason: err.code });
    });
    req.end();
  });
}

const api = spawn('node', ['src/server.js'], {
  env: { ...process.env, PORT: String(PORT) },
  stdio: ['ignore', 'pipe', 'pipe'],
});

let ready = false;
for (let i = 0; i < 60 && !ready; i += 1) {
  await new Promise((r) => setTimeout(r, 200));
  ready = await fire('/health').then((r) => r.outcome === 'completed');
}
if (!ready) {
  api.kill('SIGKILL');
  throw new Error('API did not become ready');
}

// Launch everything at once, then signal while they are genuinely in flight.
const inFlight = Array.from({ length: CONCURRENCY }, () => fire('/ready'));
setTimeout(() => api.kill('SIGTERM'), 60);

const results = await Promise.all(inFlight);
const tally = results.reduce((acc, r) => ({ ...acc, [r.outcome]: (acc[r.outcome] ?? 0) + 1 }), {});

const exitCode = await new Promise((resolve) => api.on('exit', resolve));

const completed = tally.completed ?? 0;
const refused = tally.refused ?? 0;
const dropped = tally.DROPPED ?? 0;

process.stdout.write(
  [
    '',
    `  in-flight requests : ${CONCURRENCY}`,
    `  completed          : ${completed}`,
    `  refused (expected) : ${refused}`,
    `  DROPPED            : ${dropped}`,
    `  process exit code  : ${exitCode}`,
    '',
  ].join('\n'),
);

const failures = [];
if (dropped > 0) failures.push(`${dropped} accepted requests were dropped mid-flight`);
if (completed === 0) failures.push('no requests completed — test proved nothing');
if (exitCode !== 0) failures.push(`process exited ${exitCode}, expected 0`);

if (failures.length > 0) {
  process.stdout.write(`  FAIL: ${failures.join('; ')}\n\n`);
  process.exit(1);
}
process.stdout.write('  PASS: every accepted request completed and the process exited cleanly\n\n');
