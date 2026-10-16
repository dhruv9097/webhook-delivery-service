import { createHmac, timingSafeEqual } from 'node:crypto';
import { decryptSecret } from '../security/secrets.js';

export const SIGNATURE_VERSION = 'v1';
export const DEFAULT_TOLERANCE_SECONDS = 300;

/**
 * The signed string is `{timestamp}.{raw body}`.
 *
 * Including the timestamp inside the signed material is what makes replay
 * protection work. If only the body were signed, a captured request could be
 * replayed forever with a valid signature; binding the timestamp means an old
 * capture fails the freshness check and cannot be re-signed without the secret.
 */
function signedPayload(timestamp, rawBody) {
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, 'utf8');
  return Buffer.concat([Buffer.from(`${timestamp}.`, 'utf8'), body]);
}

export function computeSignature(secret, timestamp, rawBody) {
  return createHmac('sha256', secret).update(signedPayload(timestamp, rawBody)).digest('base64');
}

/**
 * Builds the X-Relay-Signature header.
 *
 * Emits one `v1,<sig>` token per active secret, space separated. During the
 * window after a rotation, both the current and previous secrets sign, so a
 * receiver that has not yet switched still verifies. Without that overlap every
 * event in flight across a rotation would fail verification at the receiver —
 * rotation would mean guaranteed data loss, so nobody would ever rotate.
 *
 * The version prefix is what lets the scheme change later without breaking
 * every existing receiver: a v2 token can be added alongside v1.
 */
/**
 * The secrets that may currently sign for an endpoint.
 *
 * The previous secret is included only while its overlap window is open. This
 * is what makes rotation a revocation rather than an accumulation: a customer
 * who rotates because their secret leaked needs the old one to STOP working,
 * and it only stops if something expires it.
 *
 * A null `rotatedAt` with a non-null previous secret is treated as expired
 * rather than eternal — failing closed on missing metadata is the safe
 * direction for a credential.
 */
export function activeSecrets(endpoint, { overlapSeconds, now = Date.now() }) {
  // Secrets are stored encrypted and decrypted here, at the moment of use, so
  // plaintext exists only for the duration of signing.
  const secrets = [decryptSecret(endpoint.secretCurrent)];

  if (endpoint.secretPrevious && endpoint.secretRotatedAt) {
    const expiresAt = new Date(endpoint.secretRotatedAt).getTime() + overlapSeconds * 1000;
    if (now < expiresAt) secrets.push(decryptSecret(endpoint.secretPrevious));
  }

  return secrets;
}

export function buildSignatureHeader({ secrets, timestamp, rawBody }) {
  const active = secrets.filter(Boolean);
  if (active.length === 0) throw new Error('At least one signing secret is required');

  return active
    .map((secret) => `${SIGNATURE_VERSION},${computeSignature(secret, timestamp, rawBody)}`)
    .join(' ');
}

function constantTimeEquals(a, b) {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  // timingSafeEqual throws on length mismatch, which would itself leak length.
  // Compare lengths first and return early — length is not the secret.
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

/**
 * Verifies an inbound Relay webhook. Shipped to customers in the SDK, and used
 * by the test suite to confirm deliveries are signed correctly.
 *
 * Returns { valid, reason } rather than throwing, so callers can log why a
 * verification failed without a try/catch around every check.
 */
export function verifySignature({
  header,
  secret,
  timestamp,
  rawBody,
  toleranceSeconds = DEFAULT_TOLERANCE_SECONDS,
  now = Math.floor(Date.now() / 1000),
}) {
  if (!header) return { valid: false, reason: 'missing_signature_header' };

  const ts = Number(timestamp);
  if (!Number.isInteger(ts)) return { valid: false, reason: 'invalid_timestamp' };

  // Reject both stale and far-future timestamps. A clock-skewed sender is a
  // real case; a timestamp hours in the future is not.
  if (Math.abs(now - ts) > toleranceSeconds) {
    return { valid: false, reason: 'timestamp_outside_tolerance' };
  }

  const expected = computeSignature(secret, ts, rawBody);

  // Any one token matching is a pass — the header carries several during
  // rotation, and the receiver does not know which secret we used.
  const tokens = header.split(' ').filter(Boolean);
  for (const token of tokens) {
    const [version, signature] = token.split(',');
    if (version !== SIGNATURE_VERSION || !signature) continue;
    if (constantTimeEquals(signature, expected)) return { valid: true };
  }

  return { valid: false, reason: 'no_matching_signature' };
}
