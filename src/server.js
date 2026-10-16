import { createServer } from 'node:http';
import { config } from './config.js';
import { baseLogger } from './logger.js';
import { disconnectDb } from './db.js';
import { disconnectRedis } from './redis.js';
import { createApp } from './http/app.js';
import { createShutdown } from './shutdown.js';

const log = baseLogger.child({ process: 'api' });
const shutdown = createShutdown({ graceSeconds: config.SHUTDOWN_GRACE_SECONDS, logger: log });

const app = createApp({ shutdown });
const server = createServer(app);

// Must exceed the load balancer's idle timeout. If the server closes a kept
// alive connection the balancer still believes is usable, the balancer sends a
// request into a closing socket and the client sees a spurious 502.
server.keepAliveTimeout = 65_000;
server.headersTimeout = 70_000;

// Registered first, so it runs last: connections stay open while the rest of
// the shutdown work happens, then the datastores close underneath.
shutdown.register('datastores', async () => {
  await Promise.allSettled([disconnectDb(), disconnectRedis()]);
});

shutdown.register('http-server', async () => {
  await new Promise((resolve) => {
    // close() stops accepting new connections and waits for in-flight requests
    // to finish. Idle keep-alive sockets would otherwise hold it open for the
    // full keepAliveTimeout, so close those explicitly.
    server.close(resolve);
    server.closeIdleConnections();
  });
});

shutdown.listen();

server.listen(config.PORT, () => {
  log.info({ port: config.PORT, env: config.NODE_ENV }, 'api listening');
});
