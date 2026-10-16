/**
 * Typed application errors.
 *
 * Every error that reaches a client goes through one of these, so responses
 * share a single shape:
 *   { error: { type, message, details?, trace_id } }
 *
 * Anything that is NOT an AppError is treated as an unexpected bug: it gets
 * logged at error level with its stack and returned as a generic 500, so
 * internal details never leak into a response body.
 */
export class AppError extends Error {
  constructor(status, type, message, details) {
    super(message);
    this.name = new.target.name;
    this.status = status;
    this.type = type;
    this.details = details;
    // `expected` marks errors that are part of normal operation (a 404, a
    // validation failure). The handler logs these at warn, not error, so real
    // bugs stay visible in the noise.
    this.expected = status < 500;
    Error.captureStackTrace?.(this, new.target);
  }
}

export class ValidationError extends AppError {
  constructor(details, message = 'Request validation failed') {
    super(400, 'validation_error', message, details);
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = 'Missing or invalid credentials') {
    super(401, 'unauthorized', message);
  }
}

export class ForbiddenError extends AppError {
  constructor(message = 'Insufficient permissions for this operation') {
    super(403, 'forbidden', message);
  }
}

/**
 * Used for genuinely missing resources AND for resources that exist but belong
 * to another tenant. Returning 404 rather than 403 for cross-tenant access is
 * deliberate: a 403 confirms the ID exists, which leaks the existence of other
 * tenants' records to anyone who can guess an ID.
 */
export class NotFoundError extends AppError {
  constructor(resource = 'Resource') {
    super(404, 'not_found', `${resource} not found`);
  }
}

export class ConflictError extends AppError {
  constructor(message, details) {
    super(409, 'conflict', message, details);
  }
}

export class RateLimitError extends AppError {
  constructor(retryAfterSeconds) {
    super(429, 'rate_limited', 'Rate limit exceeded');
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** Raised by the SSRF guard when a delivery target resolves somewhere it must not. */
export class BlockedTargetError extends AppError {
  constructor(message, details) {
    super(422, 'blocked_target', message, details);
  }
}

export class PayloadTooLargeError extends AppError {
  constructor(limitBytes) {
    super(413, 'payload_too_large', `Payload exceeds the ${limitBytes} byte limit`);
  }
}
