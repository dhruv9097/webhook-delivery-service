import { prisma } from '../db.js';
import { logger } from '../logger.js';

/**
 * Creates an event and fans it out to every subscribed endpoint.
 *
 * Two properties this must hold:
 *
 * 1. Idempotency. Retrying a POST with the same Idempotency-Key must not create
 *    a second event. This is enforced by the unique index on
 *    (app_id, idempotency_key), NOT by checking first — a read-then-write races:
 *    two concurrent requests both find nothing, both insert, and one crashes
 *    with a constraint violation the caller never asked for. Attempting the
 *    insert and handling the conflict is the only version that is correct under
 *    concurrency.
 *
 * 2. Atomicity. The event and its deliveries are committed together. An event
 *    with no delivery rows is invisible to the worker and would be silently
 *    lost; delivery rows with no event violate their foreign key.
 */
export async function ingestEvent({ appId, eventType, payload, idempotencyKey }) {
  try {
    const result = await prisma.$transaction(async (tx) => {
      const event = await tx.event.create({
        data: { appId, eventType, payload, idempotencyKey },
      });

      // An endpoint with an empty eventTypes array subscribes to everything.
      const endpoints = await tx.endpoint.findMany({
        where: {
          appId,
          state: 'ENABLED',
          OR: [{ eventTypes: { isEmpty: true } }, { eventTypes: { has: eventType } }],
        },
        select: { id: true },
      });

      if (endpoints.length > 0) {
        await tx.delivery.createMany({
          data: endpoints.map((endpoint) => ({ eventId: event.id, endpointId: endpoint.id })),
        });
      }

      return { event, deliveryCount: endpoints.length, deduplicated: false };
    });

    logger().info(
      { event_id: result.event.id, event_type: eventType, deliveries: result.deliveryCount },
      'event ingested',
    );

    return result;
  } catch (err) {
    // P2002 on this transaction can only be the idempotency key: the delivery
    // uniqueness is (event_id, endpoint_id) and the event is brand new, so its
    // deliveries cannot collide.
    if (err.code === 'P2002' && idempotencyKey) {
      const existing = await prisma.event.findUnique({
        where: { appId_idempotencyKey: { appId, idempotencyKey } },
        include: { _count: { select: { deliveries: true } } },
      });

      // The losing side of a race can arrive here before the winner commits.
      // Surfacing the raw constraint error is more honest than inventing a
      // response for an event we cannot read yet.
      if (!existing) throw err;

      logger().info(
        { event_id: existing.id, idempotency_key: idempotencyKey },
        'duplicate event suppressed by idempotency key',
      );

      return { event: existing, deliveryCount: existing._count.deliveries, deduplicated: true };
    }
    throw err;
  }
}

/**
 * Re-queues an already-delivered (or failed) delivery.
 *
 * Resets the attempt schedule but keeps the delivery ID, so the receiver sees
 * the same X-Relay-Id it saw before and can recognise the replay as a duplicate
 * of something it may already have processed.
 */
export async function replayDelivery(deliveryId) {
  return prisma.delivery.update({
    where: { id: deliveryId },
    data: {
      state: 'PENDING',
      attemptCount: 0,
      nextAttemptAt: new Date(),
      completedAt: null,
      lastError: null,
      lockedUntil: null,
      lockedBy: null,
    },
  });
}
