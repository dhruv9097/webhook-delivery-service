import { createServer } from 'node:http';

/**
 * A webhook receiver whose failure behaviour is controllable at runtime.
 *
 * This exists so the delivery engine's retry, timeout, and circuit-breaker
 * paths can be tested against a real socket rather than a mock. Assertions
 * about "we retried three times then succeeded" are only meaningful if
 * something on the other end actually refused three times.
 *
 *   POST /hook          receive a delivery (behaviour per current mode)
 *   GET  /received      everything received so far
 *   POST /mode          { mode, ... } change behaviour
 *   POST /reset         clear the log and return to mode "ok"
 *
 * Modes: ok | fail (status) | hang | close | flaky (succeedOnAttempt)
 */
const PORT = Number(process.env.PORT ?? 4000);

const received = [];
let mode = { mode: 'ok' };
let hookCallCount = 0;

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) });
  res.end(payload);
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks);
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (req.method === 'POST' && url.pathname === '/hook') {
    const body = await readBody(req);
    hookCallCount += 1;

    received.push({
      at: new Date().toISOString(),
      callNumber: hookCallCount,
      headers: req.headers,
      // Retained verbatim. Re-serializing would change the bytes the signature
      // was computed over and make verification impossible.
      rawBody: body.toString('utf8'),
    });

    switch (mode.mode) {
      case 'fail':
        return json(res, mode.status ?? 500, { ok: false });

      case 'hang':
        // Never responds. Exercises the delivery total-timeout path.
        return;

      case 'close':
        // Destroys the socket mid-response, which surfaces as a transport
        // error rather than an HTTP status.
        res.writeHead(200, { 'content-type': 'application/json', 'content-length': '999' });
        res.write('{"partial":');
        return res.socket.destroy();

      case 'flaky': {
        const succeedOn = mode.succeedOnAttempt ?? 3;
        if (hookCallCount < succeedOn) return json(res, 503, { ok: false, attempt: hookCallCount });
        return json(res, 200, { ok: true, attempt: hookCallCount });
      }

      default:
        return json(res, 200, { ok: true });
    }
  }

  if (req.method === 'GET' && url.pathname === '/received') {
    return json(res, 200, { count: received.length, deliveries: received });
  }

  if (req.method === 'POST' && url.pathname === '/mode') {
    mode = JSON.parse((await readBody(req)).toString('utf8') || '{}');
    return json(res, 200, { mode });
  }

  if (req.method === 'POST' && url.pathname === '/reset') {
    received.length = 0;
    hookCallCount = 0;
    mode = { mode: 'ok' };
    return json(res, 200, { reset: true });
  }

  return json(res, 404, { error: 'not found' });
});

server.listen(PORT, () => {
  process.stdout.write(`mock-receiver listening on ${PORT}\n`);
});

process.on('SIGTERM', () => server.close(() => process.exit(0)));
