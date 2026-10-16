import { Router } from 'express';
import { prisma } from '../../db.js';
import { NotFoundError } from '../../errors.js';
import { logger } from '../../logger.js';
import { encryptSecret } from '../../security/secrets.js';
import { generateSigningSecret } from '../../services/apiKeys.js';
import { cuid, idParam } from '../../schemas/common.js';
import { createEndpointSchema, updateEndpointSchema } from '../../schemas/endpoint.js';
import { requireAuth, requireWrite } from '../middleware/auth.js';
import { generalRateLimit } from '../middleware/rateLimit.js';
import { validate } from '../middleware/validate.js';
import { z } from 'zod';

export const endpointsRouter = Router();

endpointsRouter.use(requireAuth);
endpointsRouter.use(generalRateLimit);

// Endpoints are nested under an application, so every query joins through the
// application's orgId. That single join is the tenant boundary for this router.
const appScope = (orgId) => ({ app: { orgId } });

// Signing secrets are write-only over the API. They are shown once at creation
// and once at rotation; after that the customer must rotate to get a new one.
const PUBLIC_FIELDS = {
  id: true,
  appId: true,
  url: true,
  description: true,
  eventTypes: true,
  state: true,
  disabledAt: true,
  secretRotatedAt: true,
  createdAt: true,
};

endpointsRouter.get(
  '/',
  validate({ query: z.object({ applicationId: cuid.optional() }) }),
  async (req, res) => {
    const { applicationId } = req.validated.query;
    const endpoints = await prisma.endpoint.findMany({
      where: { ...appScope(req.auth.orgId), ...(applicationId ? { appId: applicationId } : {}) },
      select: PUBLIC_FIELDS,
      orderBy: { createdAt: 'desc' },
    });
    res.json({ data: endpoints });
  },
);

endpointsRouter.post(
  '/',
  requireWrite('endpoints:write'),
  validate({ body: createEndpointSchema.extend({ applicationId: cuid }) }),
  async (req, res) => {
    const { applicationId, url, description, eventTypes } = req.body;

    // Confirm the application belongs to this tenant before attaching anything
    // to it; otherwise a valid ID from another org would be accepted.
    const application = await prisma.application.findFirst({
      where: { id: applicationId, orgId: req.auth.orgId },
      select: { id: true },
    });
    if (!application) throw new NotFoundError('Application');

    const secret = generateSigningSecret();
    const endpoint = await prisma.endpoint.create({
      // Encrypted at rest; `secret` is returned to the caller once and then
      // only ever exists in ciphertext here.
      data: { appId: application.id, url, description, eventTypes, secretCurrent: encryptSecret(secret) },
      select: PUBLIC_FIELDS,
    });

    logger().info({ endpoint_id: endpoint.id, org_id: req.auth.orgId }, 'endpoint created');

    res.status(201).json({ ...endpoint, secret, warning: 'Store this secret now. It cannot be retrieved again.' });
  },
);

endpointsRouter.get('/:id', validate({ params: idParam }), async (req, res) => {
  const endpoint = await prisma.endpoint.findFirst({
    where: { id: req.params.id, ...appScope(req.auth.orgId) },
    select: PUBLIC_FIELDS,
  });
  if (!endpoint) throw new NotFoundError('Endpoint');
  res.json(endpoint);
});

endpointsRouter.patch(
  '/:id',
  requireWrite('endpoints:write'),
  validate({ params: idParam, body: updateEndpointSchema }),
  async (req, res) => {
    const patch = { ...req.body };

    // Re-enabling clears the disabled timestamp; disabling records when.
    if (patch.state === 'ENABLED') patch.disabledAt = null;
    if (patch.state === 'DISABLED') patch.disabledAt = new Date();

    const result = await prisma.endpoint.updateMany({
      where: { id: req.params.id, ...appScope(req.auth.orgId) },
      data: patch,
    });
    if (result.count === 0) throw new NotFoundError('Endpoint');

    res.json(await prisma.endpoint.findUnique({ where: { id: req.params.id }, select: PUBLIC_FIELDS }));
  },
);

/**
 * Rotates the signing secret.
 *
 * The outgoing secret moves to secretPrevious rather than being discarded, and
 * deliveries sign with both for the overlap window. Without that overlap, every
 * event in flight during a rotation would fail verification at the receiver.
 */
endpointsRouter.post(
  '/:id/rotate-secret',
  requireWrite('endpoints:write'),
  validate({ params: idParam }),
  async (req, res) => {
    const endpoint = await prisma.endpoint.findFirst({
      where: { id: req.params.id, ...appScope(req.auth.orgId) },
      select: { id: true, secretCurrent: true },
    });
    if (!endpoint) throw new NotFoundError('Endpoint');

    const secret = generateSigningSecret();
    const updated = await prisma.endpoint.update({
      where: { id: endpoint.id },
      data: {
        secretCurrent: encryptSecret(secret),
        // Already ciphertext — carried across as stored, not re-encrypted.
        secretPrevious: endpoint.secretCurrent,
        secretRotatedAt: new Date(),
      },
      select: PUBLIC_FIELDS,
    });

    logger().info({ endpoint_id: endpoint.id, org_id: req.auth.orgId }, 'signing secret rotated');

    res.json({
      ...updated,
      secret,
      warning: 'Store this secret now. It cannot be retrieved again.',
      note: 'The previous secret also signs deliveries until you call this again.',
    });
  },
);
