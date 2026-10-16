import { z } from 'zod';
import { cuid, eventType } from './common.js';

export const MAX_PAYLOAD_BYTES = 256 * 1024;

export const createEventSchema = z.object({
  applicationId: cuid,
  eventType,
  // Objects only, not bare arrays or scalars. A top-level object leaves room to
  // add fields later without breaking every receiver's parser.
  payload: z.record(z.unknown()),
});

export const eventIdempotencyHeader = z
  .string()
  .min(1)
  .max(255)
  .regex(/^[A-Za-z0-9._:-]+$/, 'Idempotency-Key may contain letters, digits, and . _ : -');

export const listDeliveriesQuery = z.object({
  state: z
    .enum(['PENDING', 'IN_FLIGHT', 'SUCCEEDED', 'RETRYING', 'FAILED_PERMANENT', 'DISCARDED'])
    .optional(),
  endpointId: cuid.optional(),
  eventType: eventType.optional(),
});
