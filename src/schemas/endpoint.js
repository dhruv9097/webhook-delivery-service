import { z } from 'zod';
import { eventType } from './common.js';

/**
 * Shape-level URL validation only.
 *
 * This rejects obvious nonsense at create time, but it is NOT the security
 * boundary. A hostname that looks public here can resolve to 169.254.169.254
 * at delivery time, so the real check happens per-attempt in
 * src/security/ssrf.js against the resolved IP. Validating only here would be
 * a classic time-of-check/time-of-use hole.
 */
export const deliveryUrl = z
  .string()
  .url()
  .max(2048)
  .refine((value) => {
    const { protocol } = new URL(value);
    return protocol === 'https:' || protocol === 'http:';
  }, 'URL must use http or https')
  .refine((value) => !new URL(value).username && !new URL(value).password,
    'Credentials in the URL are not supported');

export const createEndpointSchema = z.object({
  url: deliveryUrl,
  description: z.string().max(500).optional(),
  // Empty array means "every event type".
  eventTypes: z.array(eventType).max(100).default([]),
});

export const updateEndpointSchema = z
  .object({
    url: deliveryUrl.optional(),
    description: z.string().max(500).nullable().optional(),
    eventTypes: z.array(eventType).max(100).optional(),
    state: z.enum(['ENABLED', 'DISABLED']).optional(),
  })
  .refine((data) => Object.keys(data).length > 0, 'Provide at least one field to update');
