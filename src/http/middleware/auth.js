import { createHash, timingSafeEqual } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { config } from '../../config.js';
import { prisma } from '../../db.js';
import { ForbiddenError, UnauthorizedError } from '../../errors.js';

const API_KEY_PATTERN = /^rly_(live|test)_[A-Za-z0-9]{32}$/;

/** Prefix stored alongside the hash so a key is identifiable in the dashboard. */
export function apiKeyPrefix(key) {
  return key.slice(0, 17); // rly_live_ + first 8 chars of the secret
}

export function hashApiKey(key) {
  return createHash('sha256').update(key).digest('hex');
}

function constantTimeEquals(a, b) {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

function bearerToken(req) {
  const header = req.get('authorization');
  if (!header) return null;
  const [scheme, token] = header.split(' ');
  if (!token || scheme.toLowerCase() !== 'bearer') return null;
  return token.trim();
}

/**
 * Authenticates a machine caller by API key.
 *
 * Lookup is by the non-secret prefix (a unique indexed column) rather than by
 * scanning hashes, then the full hash is compared in constant time. Comparing
 * with === would leak information through timing.
 */
export async function requireApiKey(req, _res, next) {
  const token = bearerToken(req);
  if (!token || !API_KEY_PATTERN.test(token)) {
    return next(new UnauthorizedError('Provide an API key as: Authorization: Bearer rly_live_...'));
  }

  const record = await prisma.apiKey.findUnique({
    where: { prefix: apiKeyPrefix(token) },
    include: { org: true },
  });

  // Every failure below returns the same generic message: distinguishing
  // "unknown key" from "revoked key" tells an attacker which guesses landed.
  if (!record || !constantTimeEquals(record.keyHash, hashApiKey(token))) {
    return next(new UnauthorizedError('Invalid API key'));
  }
  if (record.revokedAt) return next(new UnauthorizedError('Invalid API key'));
  if (record.expiresAt && record.expiresAt < new Date()) {
    return next(new UnauthorizedError('Invalid API key'));
  }

  req.auth = {
    kind: 'api_key',
    orgId: record.orgId,
    apiKeyId: record.id,
    scopes: record.scopes,
  };

  // Fire-and-forget: last-used tracking must never add latency to or fail the
  // request it is recording.
  prisma.apiKey
    .update({ where: { id: record.id }, data: { lastUsedAt: new Date() } })
    .catch(() => {});

  return next();
}

/** Authenticates a human via a dashboard session token. */
export async function requireUser(req, _res, next) {
  const token = bearerToken(req);
  if (!token) return next(new UnauthorizedError('Missing session token'));

  let claims;
  try {
    claims = jwt.verify(token, config.JWT_SECRET, { algorithms: ['HS256'] });
  } catch {
    return next(new UnauthorizedError('Invalid or expired session'));
  }

  const user = await prisma.user.findUnique({ where: { id: claims.sub } });
  if (!user) return next(new UnauthorizedError('Invalid or expired session'));

  req.auth = { kind: 'user', orgId: user.orgId, userId: user.id, role: user.role };
  return next();
}

/** Accepts either an API key or a session token. */
export async function requireAuth(req, res, next) {
  const token = bearerToken(req);
  if (token && API_KEY_PATTERN.test(token)) return requireApiKey(req, res, next);
  return requireUser(req, res, next);
}

const ROLE_RANK = { MEMBER: 0, ADMIN: 1, OWNER: 2 };

/** Gate an operation behind a minimum role. API keys carry scopes, not roles. */
export function requireRole(minimum) {
  return (req, _res, next) => {
    if (req.auth?.kind !== 'user') {
      return next(new ForbiddenError('This operation requires a dashboard session'));
    }
    if (ROLE_RANK[req.auth.role] < ROLE_RANK[minimum]) {
      return next(new ForbiddenError(`Requires ${minimum} role or higher`));
    }
    return next();
  };
}

export function requireScope(scope) {
  return (req, _res, next) => {
    if (req.auth?.kind !== 'api_key') return next();
    if (!req.auth.scopes.includes(scope) && !req.auth.scopes.includes('*')) {
      return next(new ForbiddenError(`API key is missing the '${scope}' scope`));
    }
    return next();
  };
}

/**
 * Authorises a write by whichever credential the caller presented: an API key
 * needs the matching scope, a human needs at least ADMIN.
 *
 * This exists because `requireRole` and `requireScope` cannot be stacked. The
 * two model different credential types, so `requireRole('ADMIN')` rejects every
 * API key outright and makes any `requireScope` beside it unreachable. Routes
 * that both humans and machines should be able to call need one guard that
 * understands both, not two that each veto the other's callers.
 *
 * Account-level operations (minting and revoking API keys) deliberately keep
 * `requireRole` instead: a key that can mint keys can escalate its own scopes
 * and survive revocation of the original.
 */
export function requireWrite(scope, minimumRole = 'ADMIN') {
  return (req, res, next) => {
    if (req.auth?.kind === 'api_key') return requireScope(scope)(req, res, next);
    return requireRole(minimumRole)(req, res, next);
  };
}
