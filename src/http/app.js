import express from 'express';
import pinoHttp from 'pino-http';
import { baseLogger } from '../logger.js';
import { pingDb } from '../db.js';
import { pingRedis } from '../redis.js';
import { MAX_PAYLOAD_BYTES } from '../schemas/event.js';
import { errorHandler, notFoundHandler } from './middleware/errorHandler.js';
import { traceId } from './middleware/traceId.js';
import { authRouter } from './routes/auth.js';
import { applicationsRouter } from './routes/applications.js';
import { endpointsRouter } from './routes/endpoints.js';
import { eventsRouter } from './routes/events.js';
import { deliveriesRouter } from './routes/deliveries.js';

export function createApp({ shutdown } = {}) {
  const app = express();

  // Behind a proxy, req.ip must reflect X-Forwarded-For or rate limiting keys
  // every caller to the proxy's address. `1` trusts exactly one hop; trusting
  // all hops would let clients spoof their own IP.
  app.set('trust proxy', 1);
  app.disable('x-powered-by');

  app.use(traceId);

  app.use(
    pinoHttp({
      logger: baseLogger,
      genReqId: (req) => req.traceId,
      customLogLevel: (_req, res, err) => {
        if (err || res.statusCode >= 500) return 'error';
        if (res.statusCode >= 400) return 'warn';
        return 'info';
      },
      // The default serializers dump every header on every request. Keep the
      // fields that aid debugging and drop the noise.
      serializers: {
        req: (req) => ({ method: req.method, url: req.url }),
        res: (res) => ({ status: res.statusCode }),
      },
    }),
  );

  // Retaining the raw body is required for signature verification on inbound
  // webhooks: re-serializing parsed JSON can reorder keys or change whitespace,
  // producing a different byte string and a signature that will never match.
  app.use(
    express.json({
      limit: MAX_PAYLOAD_BYTES,
      verify: (req, _res, buf) => {
        req.rawBody = buf;
      },
    }),
  );

  /**
   * Liveness: is this process running? Deliberately does not touch Postgres or
   * Redis — a dependency outage should not cause the orchestrator to kill and
   * restart an otherwise healthy process, which only adds load to a struggling
   * system.
   */
  app.get('/health', (_req, res) => {
    if (shutdown?.isDraining()) return res.status(503).json({ status: 'draining' });
    res.json({ status: 'ok', uptime_seconds: Math.floor(process.uptime()) });
  });

  /** Readiness: should this process receive traffic? This one does check deps. */
  app.get('/ready', async (_req, res) => {
    if (shutdown?.isDraining()) return res.status(503).json({ status: 'draining' });

    const checks = await Promise.allSettled([pingDb(), pingRedis()]);
    const [db, redis] = checks.map((c) => (c.status === 'fulfilled' ? 'ok' : 'unavailable'));

    const ready = db === 'ok' && redis === 'ok';
    res.status(ready ? 200 : 503).json({ status: ready ? 'ready' : 'degraded', checks: { db, redis } });
  });

  app.use('/v1/auth', authRouter);
  app.use('/v1/applications', applicationsRouter);
  app.use('/v1/endpoints', endpointsRouter);
  app.use('/v1/events', eventsRouter);
  app.use('/v1/deliveries', deliveriesRouter);

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
