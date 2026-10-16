import { describe, expect, it } from 'vitest';
import { decryptSecret, encryptSecret, isEncrypted } from '../../src/security/secrets.js';

describe('encryptSecret / decryptSecret', () => {
  it('round-trips a signing secret', () => {
    const plaintext = 'whsec_dGVzdC1zZWNyZXQtdmFsdWU';
    expect(decryptSecret(encryptSecret(plaintext))).toBe(plaintext);
  });

  it('produces different ciphertext each time for the same input', () => {
    // A fresh IV per encryption. Reusing one under GCM breaks confidentiality
    // and allows tag forgery, and identical ciphertexts would also reveal that
    // two endpoints share a secret.
    const a = encryptSecret('whsec_same');
    const b = encryptSecret('whsec_same');
    expect(a).not.toBe(b);
    expect(decryptSecret(a)).toBe('whsec_same');
    expect(decryptSecret(b)).toBe('whsec_same');
  });

  it('does not leave the plaintext visible in the stored value', () => {
    const stored = encryptSecret('whsec_should_not_appear');
    expect(stored).not.toContain('should_not_appear');
    expect(stored.startsWith('v1:')).toBe(true);
    expect(isEncrypted(stored)).toBe(true);
  });

  it('detects tampering instead of returning a wrong secret', () => {
    // The reason for GCM over CBC: a modified ciphertext must fail loudly, not
    // decrypt to garbage and cause an undiagnosable run of signature failures.
    const stored = encryptSecret('whsec_authentic');
    const [v, iv, tag, ct] = stored.split(':');
    const flipped = Buffer.from(ct, 'base64url');
    flipped[0] ^= 0xff;
    expect(() => decryptSecret([v, iv, tag, flipped.toString('base64url')].join(':'))).toThrow();
  });

  it('rejects a swapped authentication tag', () => {
    const a = encryptSecret('whsec_one').split(':');
    const b = encryptSecret('whsec_two').split(':');
    expect(() => decryptSecret([a[0], a[1], b[2], a[3]].join(':'))).toThrow();
  });

  it('passes through legacy plaintext rows unchanged', () => {
    // Migration path: rows written before encryption existed must keep working
    // until a rewrite re-encrypts them.
    expect(decryptSecret('whsec_legacy_plaintext')).toBe('whsec_legacy_plaintext');
    expect(isEncrypted('whsec_legacy_plaintext')).toBe(false);
  });

  it('handles a null secret', () => {
    expect(decryptSecret(null)).toBeNull();
  });
});
