import { randomBytes } from 'node:crypto';
import { Router } from 'express';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import { config } from '../../config.js';
import { prisma } from '../../db.js';
import { ConflictError, UnauthorizedError } from '../../errors.js';
import { logger } from '../../logger.js';
import { generateApiKey } from '../../services/apiKeys.js';
import { createApiKeySchema, loginSchema, signupSchema } from '../../schemas/auth.js';
import { requireRole, requireUser } from '../middleware/auth.js';
import { authRateLimit } from '../middleware/rateLimit.js';
import { validate } from '../middleware/validate.js';

export const authRouter = Router();

function slugify(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60);
}

// A real argon2 hash of a value nobody can present, computed once at startup.
// Verifying against this when the email is unknown makes the failure path cost
// the same as the success path. A hardcoded literal would not work: a malformed
// hash makes verify() throw immediately, doing none of the work whose duration
// is the whole point.
const DUMMY_HASH = await argon2.hash(randomBytes(32).toString('hex'), { type: argon2.argon2id });

function issueSession(user) {
  return jwt.sign({ sub: user.id, org: user.orgId, role: user.role }, config.JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: config.JWT_TTL_SECONDS,
  });
}

// Creates an organization and its first user, who becomes OWNER.
authRouter.post('/signup', authRateLimit, validate({ body: signupSchema }), async (req, res) => {
  const { organizationName, email, password } = req.body;

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) throw new ConflictError('An account with that email already exists');

  const passwordHash = await argon2.hash(password, { type: argon2.argon2id });

  // Organization and owner are created together or not at all — a half-created
  // org with no way to log in would be unrecoverable for the user.
  const user = await prisma.$transaction(async (tx) => {
    const org = await tx.organization.create({
      data: { name: organizationName, slug: `${slugify(organizationName)}-${Date.now().toString(36)}` },
    });
    return tx.user.create({ data: { orgId: org.id, email, passwordHash, role: 'OWNER' } });
  });

  logger().info({ user_id: user.id, org_id: user.orgId }, 'organization created');

  res.status(201).json({
    token: issueSession(user),
    user: { id: user.id, email: user.email, role: user.role, organizationId: user.orgId },
  });
});

authRouter.post('/login', authRateLimit, validate({ body: loginSchema }), async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({ where: { email } });

  // Verify against a dummy hash when the user is unknown so that response time
  // does not reveal whether an email is registered.
  const valid = await argon2.verify(user ? user.passwordHash : DUMMY_HASH, password);

  if (!user || !valid) throw new UnauthorizedError('Invalid email or password');

  res.json({
    token: issueSession(user),
    user: { id: user.id, email: user.email, role: user.role, organizationId: user.orgId },
  });
});

authRouter.get('/me', requireUser, async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { id: req.auth.userId },
    select: { id: true, email: true, role: true, orgId: true, org: { select: { name: true } } },
  });
  res.json({ id: user.id, email: user.email, role: user.role, organization: { id: user.orgId, name: user.org.name } });
});

// The plaintext key is returned here and never again.
authRouter.post(
  '/api-keys',
  requireUser,
  requireRole('ADMIN'),
  validate({ body: createApiKeySchema }),
  async (req, res) => {
    const { name, scopes, expiresAt } = req.body;
    const { plaintext, prefix, keyHash } = generateApiKey('LIVE');

    const record = await prisma.apiKey.create({
      data: { orgId: req.auth.orgId, name, scopes, expiresAt, prefix, keyHash },
      select: { id: true, name: true, prefix: true, scopes: true, expiresAt: true, createdAt: true },
    });

    logger().info({ api_key_id: record.id, org_id: req.auth.orgId }, 'api key created');

    res.status(201).json({ ...record, key: plaintext, warning: 'Store this key now. It cannot be retrieved again.' });
  },
);

authRouter.get('/api-keys', requireUser, async (req, res) => {
  const keys = await prisma.apiKey.findMany({
    where: { orgId: req.auth.orgId, revokedAt: null },
    select: { id: true, name: true, prefix: true, scopes: true, lastUsedAt: true, expiresAt: true, createdAt: true },
    orderBy: { createdAt: 'desc' },
  });
  res.json({ data: keys });
});

// Revocation is a soft delete: the row is retained so delivery logs and audit
// trails referencing this key stay resolvable.
authRouter.delete('/api-keys/:id', requireUser, requireRole('ADMIN'), async (req, res) => {
  const result = await prisma.apiKey.updateMany({
    where: { id: req.params.id, orgId: req.auth.orgId, revokedAt: null },
    data: { revokedAt: new Date() },
  });

  // updateMany with an org-scoped filter means a key belonging to another
  // tenant matches zero rows and reads as "not found", never as success.
  if (result.count === 0) return res.status(404).json({
    error: { type: 'not_found', message: 'API key not found', trace_id: req.traceId },
  });

  logger().info({ api_key_id: req.params.id, org_id: req.auth.orgId }, 'api key revoked');
  res.status(204).end();
});
