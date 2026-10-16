import { z } from 'zod';

export const cuid = z.string().min(20).max(40).regex(/^[a-z0-9]+$/, 'Invalid identifier');

export const idParam = z.object({ id: cuid });

/**
 * Cursor pagination, not offset.
 *
 * OFFSET makes the database scan and discard every skipped row, so deep pages
 * get linearly slower; worse, rows inserted during paging shift the window and
 * the caller silently skips or repeats records. A cursor is a stable position
 * in an indexed ordering, so page 1000 costs the same as page 1.
 */
export const pagination = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(25),
  cursor: cuid.optional(),
});

export const eventType = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[a-z0-9]+(?:[._-][a-z0-9]+)*$/, 'Use dotted lowercase, e.g. "invoice.paid"');
