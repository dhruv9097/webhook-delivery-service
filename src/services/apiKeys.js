import { randomBytes } from 'node:crypto';
import { apiKeyPrefix, hashApiKey } from '../http/middleware/auth.js';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const SECRET_LENGTH = 32;

/**
 * Mints an API key.
 *
 * The plaintext is returned exactly once, to be shown to the user and then
 * forgotten. Only the sha256 hash and the non-secret prefix are persisted, so a
 * database dump does not hand an attacker working credentials.
 *
 * sha256 rather than argon2 here on purpose: these are 190 bits of uniform
 * randomness, not user-chosen passwords, so there is nothing to brute force and
 * no reason to pay argon2's cost on every single API request.
 */
export function generateApiKey(environment = 'LIVE') {
  const scope = environment === 'LIVE' ? 'live' : 'test';

  // Rejection-free selection would bias toward the first 4 letters, since 256
  // is not a multiple of 62. Rejecting the tail keeps the distribution uniform.
  const secret = [];
  while (secret.length < SECRET_LENGTH) {
    for (const byte of randomBytes(SECRET_LENGTH)) {
      if (byte >= 248) continue; // 248 = 62 * 4, the largest usable multiple
      secret.push(ALPHABET[byte % ALPHABET.length]);
      if (secret.length === SECRET_LENGTH) break;
    }
  }

  const plaintext = `rly_${scope}_${secret.join('')}`;
  return { plaintext, prefix: apiKeyPrefix(plaintext), keyHash: hashApiKey(plaintext) };
}

/** Endpoint signing secrets follow the same "random, not user-chosen" logic. */
export function generateSigningSecret() {
  return `whsec_${randomBytes(24).toString('base64url')}`;
}
