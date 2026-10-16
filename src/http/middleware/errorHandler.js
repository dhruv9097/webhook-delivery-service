import { AppError } from '../../errors.js';
import { logger } from '../../logger.js';

/** 404 for unmatched routes, so they flow through the same response shape. */
export function notFoundHandler(req, res) {
  res.status(404).json({
    error: {
      type: 'not_found',
      message: `No route for ${req.method} ${req.path}`,
      trace_id: req.traceId,
    },
  });
}

/**
 * Terminal error handler. Express 5 forwards rejected async handlers here
 * automatically, which is why route handlers carry no try/catch.
 *
 * Express identifies error middleware by arity, so the unused `next` parameter
 * is load-bearing — removing it silently turns this into ordinary middleware
 * that never runs.
 */
// eslint-disable-next-line no-unused-vars
export function errorHandler(err, req, res, next) {
  const log = logger();

  if (err instanceof AppError) {
    if (err.expected) {
      log.warn({ err_type: err.type, status: err.status, path: req.path }, err.message);
    } else {
      log.error({ err, err_type: err.type, path: req.path }, err.message);
    }

    if (err.retryAfterSeconds != null) {
      res.setHeader('Retry-After', String(err.retryAfterSeconds));
    }

    return res.status(err.status).json({
      error: {
        type: err.type,
        message: err.message,
        ...(err.details ? { details: err.details } : {}),
        trace_id: req.traceId,
      },
    });
  }

  // Express's own body parser raises these before our code sees the request.
  if (err?.type === 'entity.too.large') {
    return res.status(413).json({
      error: { type: 'payload_too_large', message: 'Request body too large', trace_id: req.traceId },
    });
  }
  if (err?.type === 'entity.parse.failed') {
    return res.status(400).json({
      error: { type: 'invalid_json', message: 'Request body is not valid JSON', trace_id: req.traceId },
    });
  }

  // Anything reaching here is an unhandled bug. Log the full stack; return
  // nothing but the trace ID so internals stay internal.
  log.error({ err, path: req.path, method: req.method }, 'unhandled error');

  return res.status(500).json({
    error: {
      type: 'internal_error',
      message: 'An unexpected error occurred',
      trace_id: req.traceId,
    },
  });
}
