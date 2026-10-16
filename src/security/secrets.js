import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { config } from '../config.js';

/**
 * Envelope encryption for endpoint signing secrets.
 *
 * Unlike passwords and API keys, these cannot be hashed: Relay needs the actual
 * value to compute an HMAC on every delivery. So the protection available is
 * encryption at rest with a key that lives outside the database — a dump then
 * yields ciphertext instead of the ability to forge webhooks to every customer.
 *
 * AES-256-GCM rather than CBC: GCM is authenticated, so tampering with stored
 * ciphertext is detected at decrypt rather than silently producing a wrong
 * secret and an undiagnosable run of signature failures.
 *
 * Stored format: v1:<iv>:<authTag>:<ciphertext>, all base64url.
 * The version prefix is what makes a future key rotation or algorithm change
 * possible without a flag day — v2 values can coexist with v1.
 */

const VERSION = 'v1';
const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12; // 96 bits, the size GCM is specified for

let cachedKey = null;

function key() {
  if (!cachedKey) cachedKey = Buffer.from(config.SECRET_ENCRYPTION_KEY, 'hex');
  return cachedKey;
}

export function encryptSecret(plaintext) {
  // A fresh IV per encryption is mandatory for GCM: reusing one with the same
  // key breaks confidentiality and lets an attacker forge authentication tags.
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key(), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return [VERSION, iv.toString('base64url'), tag.toString('base64url'), ciphertext.toString('base64url')].join(':');
}

/**
 * Decrypts a stored secret.
 *
 * Values without the version prefix are returned unchanged. That is the
 * migration path: rows written before encryption was introduced are plaintext,
 * and must keep working until they are rewritten. Every write path encrypts, so
 * the plaintext population only shrinks.
 */
export function decryptSecret(stored) {
  if (stored == null) return null;
  if (!stored.startsWith(`${VERSION}:`)) return stored;

  const [, ivPart, tagPart, ciphertextPart] = stored.split(':');
  const decipher = createDecipheriv(ALGORITHM, key(), Buffer.from(ivPart, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagPart, 'base64url'));

  return Buffer.concat([
    decipher.update(Buffer.from(ciphertextPart, 'base64url')),
    decipher.final(),
  ]).toString('utf8');
}

export function isEncrypted(stored) {
  return typeof stored === 'string' && stored.startsWith(`${VERSION}:`);
}
