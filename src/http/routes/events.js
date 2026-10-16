import { Router } from 'express';
import { prisma } from '../../db.js';
import { NotFoundError, ValidationError } from '../../errors.js';
import { ingestEvent } from '../../services/ingest.js';
import { cuid, idParam, pagination } from '../../schemas/common.js';
import { createEventSchema, eventIdempotencyHeader } from '../../schemas/event.js';
import { requireAuth, requireWrite } from '../middleware/auth.js';
import { ingestRateLimit } from '../middleware/rateLimit.js';
import { validate } from '../middleware/validate.js';

export const eventsRouter = Router();

eventsRouter.use(requireAuth);

eventsRouter.post(
  '/',
  requireWrite('events:write'),
  // After auth, so the bucket is keyed to the API key rather than to everyone
  // sharing an IP.
  ingestRateLimit,
  validate({ body: createEventSchema }),
  async (req, res) => {
    const { applicationId, eventType, payload } = req.body;

    // The key travels as a header, not in the body, so it is not part of the
    // signed payload and a client can retry the identical body verbatim.
    const rawKey = req.get('idempotency-key');
    let idempotencyKey;
    if (rawKey !== undefined) {
      const parsed = eventIdempotencyHeader.safeParse(rawKey);
      if (!parsed.success) {
        throw new ValidationError(
          parsed.error.issues.map((i) => ({ field: 'Idempotency-Key', code: i.code, message: i.message })),
        );
      }
      idempotencyKey = parsed.data;
    }

    const application = await prisma.application.findFirst({
      where: { id: applicationId, orgId: req.auth.orgId },
      select: { id: true },
    });
    if (!application) throw new NotFoundError('Application');

    const { event, deliveryCount, deduplicated } = await ingestEvent({
      appId: application.id,
      eventType,
      payload,
      idempotencyKey,
    });

    // 202, not 201: the event is durably recorded but delivery has not been
    // attempted yet. Returning 201 would imply the receivers have it.
    res.status(202).json({
      id: event.id,
      eventType: event.eventType,
      createdAt: event.createdAt,
      deliveryCount,
      deduplicated,
    });
  },
);

eventsRouter.get(
  '/',
  validate({ query: pagination.extend({ applicationId: cuid.optional() }) }),
  async (req, res) => {
    const { limit, cursor, applicationId } = req.validated.query;

    const events = await prisma.event.findMany({
      where: {
        app: { orgId: req.auth.orgId },
        ...(applicationId ? { appId: applicationId } : {}),
      },
      select: {
        id: true,
        appId: true,
        eventType: true,
        idempotencyKey: true,
        createdAt: true,
        _count: { select: { deliveries: true } },
      },
      orderBy: { createdAt: 'desc' },
      // Fetch one extra to detect a further page without a second count query.
      take: limit + 1,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    });

    const hasMore = events.length > limit;
    const page = hasMore ? events.slice(0, limit) : events;

    res.json({
      data: page.map(({ _count, ...event }) => ({ ...event, deliveryCount: _count.deliveries })),
      hasMore,
      nextCursor: hasMore ? page.at(-1).id : null,
    });
  },
);

eventsRouter.get('/:id', validate({ params: idParam }), async (req, res) => {
  const event = await prisma.event.findFirst({
    where: { id: req.params.id, app: { orgId: req.auth.orgId } },
    include: {
      deliveries: {
        select: {
          id: true,
          endpointId: true,
          state: true,
          attemptCount: true,
          nextAttemptAt: true,
          lastError: true,
          completedAt: true,
        },
      },
    },
  });
  if (!event) throw new NotFoundError('Event');
  res.json(event);
});
