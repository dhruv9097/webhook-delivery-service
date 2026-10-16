import { z } from 'zod';

export const signupSchema = z.object({
  organizationName: z.string().min(1).max(120),
  email: z.string().email().max(254).toLowerCase(),
  // Length beats composition rules: a long passphrase resists guessing better
  // than a short string forced to contain a symbol.
  password: z.string().min(12).max(200),
});

export const loginSchema = z.object({
  email: z.string().email().max(254).toLowerCase(),
  password: z.string().min(1).max(200),
});

export const createApiKeySchema = z.object({
  name: z.string().min(1).max(80),
  scopes: z.array(z.enum(['events:write', 'endpoints:write', 'applications:write', 'deliveries:read', '*']))
    .min(1)
    .default(['events:write']),
  expiresAt: z.coerce.date().min(new Date()).optional(),
});
