import { prisma } from '../db.js';
import { config } from '../config.js';

/**
 * Deletes rotated-out signing secrets whose overlap window has closed.
 *
 * `activeSecrets` already stops using them, so this changes no behaviour. It
 * exists because "we no longer sign with it" and "it is no longer in the
 * database" are different security properties: a secret that is still stored is
 * still exposed by a database dump, a log of a row, or an over-broad query.
 * Once it can never be used again there is no reason to keep it.
 */
export async function purgeExpiredSecrets({ now = new Date() } = {}) {
  const cutoff = new Date(now.getTime() - config.SECRET_OVERLAP_SECONDS * 1000);

  const result = await prisma.endpoint.updateMany({
    where: {
      secretPrevious: { not: null },
      OR: [
        { secretRotatedAt: { lt: cutoff } },
        // Defensive: a previous secret with no rotation timestamp cannot have
        // its window evaluated, and activeSecrets already refuses to use it.
        { secretRotatedAt: null },
      ],
    },
    data: { secretPrevious: null },
  });

  return result.count;
}
