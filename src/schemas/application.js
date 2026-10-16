import { z } from 'zod';

export const createApplicationSchema = z.object({
  name: z.string().min(1).max(80),
  environment: z.enum(['TEST', 'LIVE']).default('TEST'),
});

export const updateApplicationSchema = z.object({
  name: z.string().min(1).max(80).optional(),
});
