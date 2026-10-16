import { AsyncLocalStorage } from 'node:async_hooks';
import pino from 'pino';
import { config } from './config.js';

// Holds the trace ID for the duration of a request or a delivery job, so any
// code deep in a service can log with the right trace ID without every function
// taking a logger argument. This is what makes one trace ID span
// API -> queue -> outbound HTTP attempt.
const traceStore = new AsyncLocalStorage();

export const baseLogger = pino({
  level: config.LOG_LEVEL,
  // Structured JSON by default so logs stay queryable. pino-pretty is a dev
  // dependency and absent from the built image, so this must be opt-in rather
  // than inferred from NODE_ENV.
  transport: config.LOG_PRETTY
    ? { target: 'pino-pretty', options: { colorize: true, translateTime: 'HH:MM:ss.l' } }
    : undefined,
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'headers.authorization',
      '*.secretCurrent',
      '*.secretPrevious',
      '*.passwordHash',
      '*.keyHash',
    ],
    censor: '[redacted]',
  },
  formatters: {
    level: (label) => ({ level: label }),
  },
});


/**
 * Run `fn` with `traceId` bound to the async context. Everything logged inside,
 * including across awaits, carries the trace ID.
 */
export function withTrace(traceId, fn) {
  return traceStore.run({ traceId }, fn);
}

export function currentTraceId() {
  return traceStore.getStore()?.traceId;
}

/**
 * Logger bound to the ambient trace ID. Use this everywhere instead of
 * importing baseLogger directly.
 */
export function logger() {
  const traceId = currentTraceId();
  return traceId ? baseLogger.child({ trace_id: traceId }) : baseLogger;
}
