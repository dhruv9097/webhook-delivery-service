import { Router } from 'express';
import { prisma } from '../../db.js';
import { NotFoundError } from '../../errors.js';
import { logger } from '../../logger.js';
import { replayDelivery } from '../../services/ingest.js';
import { idParam, pagination } from '../../schemas/common.js';
import { listDeliveriesQuery } from '../../schemas/event.js';
import { requireAuth, requireWrite } from '../middleware/auth.js';
import { generalRateLimit } from '../middleware/rateLimit.js';
import { validate } from '../middleware/validate.js';

export const deliveriesRouter = Router();

deliveriesRouter.use(requireAuth);
deliveriesRouter.use(generalRateLimit);

// Tenant boundary: every delivery reaches its org through endpoint -> app.
const orgScope = (orgId) => ({ endpoint: { app: { orgId } } });

deliveriesRouter.get(
  '/',
  validate({ query: pagination.merge(listDeliveriesQuery) }),
  async (req, res) => {
    const { limit, cursor, state, endpointId, eventType } = req.validated.query;

    const deliveries = await prisma.delivery.findMany({
      where: {
        ...orgScope(req.auth.orgId),
        ...(state ? { state } : {}),
        ...(endpointId ? { endpointId } : {}),
        ...(eventType ? { event: { eventType } } : {}),
      },
      select: {
        id: true,
        endpointId: true,
        state: true,
        attemptCount: true,
        nextAttemptAt: true,
        lastError: true,
        completedAt: true,
        createdAt: true,
        event: { select: { id: true, eventType: true } },
      },
      orderBy: { createdAt: 'desc' },
      take: limit + 1,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    });

    const hasMore = deliveries.length > limit;
    const page = hasMore ? deliveries.slice(0, limit) : deliveries;

    res.json({ data: page, hasMore, nextCursor: hasMore ? page.at(-1).id : null });
  },
);

/** The inspector view: full attempt history, oldest first. */
deliveriesRouter.get('/:id', validate({ params: idParam }), async (req, res) => {
  const delivery = await prisma.delivery.findFirst({
    where: { id: req.params.id, ...orgScope(req.auth.orgId) },
    include: {
      event: { select: { id: true, eventType: true, payload: true, createdAt: true } },
      endpoint: { select: { id: true, url: true, state: true } },
      attempts: { orderBy: { attemptNo: 'asc' } },
    },
  });
  if (!delivery) throw new NotFoundError('Delivery');
  res.json(delivery);
});

deliveriesRouter.post(
  '/:id/replay',
  requireWrite('events:write'),
  validate({ params: idParam }),
  async (req, res) => {
    const delivery = await prisma.delivery.findFirst({
      where: { id: req.params.id, ...orgScope(req.auth.orgId) },
      select: { id: true, state: true },
    });
    if (!delivery) throw new NotFoundError('Delivery');

    // Replaying something already queued would reset its attempt count and
    // restart the backoff, which is the opposite of what the caller wants.
    if (['PENDING', 'RETRYING', 'IN_FLIGHT'].includes(delivery.state)) {
      return res.status(409).json({
        error: {
          type: 'conflict',
          message: `Delivery is already ${delivery.state.toLowerCase()} and will be attempted without a replay`,
          trace_id: req.traceId,
        },
      });
    }

    const replayed = await replayDelivery(delivery.id);
    logger().info({ delivery_id: delivery.id, previous_state: delivery.state }, 'delivery replayed');

    return res.status(202).json({
      id: replayed.id,
      state: replayed.state,
      nextAttemptAt: replayed.nextAttemptAt,
    });
  },
);
