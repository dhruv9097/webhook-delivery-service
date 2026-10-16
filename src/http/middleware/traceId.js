import { randomUUID } from 'node:crypto';
import { withTrace } from '../../logger.js';

const TRACE_HEADER = 'x-relay-trace-id';
// A trace ID is echoed back to clients and written to logs, so it must not be
// a vector for header injection or log forging.
const SAFE_TRACE_ID = /^[A-Za-z0-9_-]{8,64}$/;

/**
 * Establishes a trace ID for the request and binds it to the async context for
 * the entire downstream call tree. Honours a caller-supplied ID so a tenant can
 * correlate their logs with ours, but only if it is well-formed.
 */
export function traceId(req, res, next) {
  const supplied = req.get(TRACE_HEADER);
  const id = supplied && SAFE_TRACE_ID.test(supplied) ? supplied : randomUUID();

  req.traceId = id;
  res.setHeader(TRACE_HEADER, id);

  withTrace(id, () => next());
}
