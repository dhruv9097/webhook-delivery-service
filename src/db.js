import { PrismaClient } from '@prisma/client';
import { config, isProduction } from './config.js';
import { baseLogger } from './logger.js';

export const prisma = new PrismaClient({
  datasources: { db: { url: config.DATABASE_URL } },
  log: isProduction
    ? [{ emit: 'event', level: 'error' }]
    : [
        { emit: 'event', level: 'error' },
        { emit: 'event', level: 'warn' },
      ],
});

prisma.$on('error', (e) => baseLogger.error({ prisma: e }, 'prisma error'));
if (!isProduction) {
  prisma.$on('warn', (e) => baseLogger.warn({ prisma: e }, 'prisma warning'));
}

export async function disconnectDb() {
  await prisma.$disconnect();
}

/** Liveness probe for /health. Cheap enough to call on every check. */
export async function pingDb() {
  await prisma.$queryRaw`SELECT 1`;
}
