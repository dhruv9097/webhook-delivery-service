import { describe, expect, it } from 'vitest';
import { activeSecrets, buildSignatureHeader, verifySignature } from '../../src/delivery/signature.js';

const OVERLAP = 86_400; // 24h
const NOW = Date.UTC(2026, 0, 2, 12, 0, 0);
const hoursAgo = (h) => new Date(NOW - h * 3600_000);

const endpoint = (overrides = {}) => ({
  secretCurrent: 'whsec_current',
  secretPrevious: null,
  secretRotatedAt: null,
  ...overrides,
});

describe('activeSecrets', () => {
  it('uses only the current secret when nothing has been rotated', () => {
    expect(activeSecrets(endpoint(), { overlapSeconds: OVERLAP, now: NOW })).toEqual(['whsec_current']);
  });

  it('accepts the previous secret while the window is open', () => {
    const secrets = activeSecrets(
      endpoint({ secretPrevious: 'whsec_old', secretRotatedAt: hoursAgo(1) }),
      { overlapSeconds: OVERLAP, now: NOW },
    );
    expect(secrets).toEqual(['whsec_current', 'whsec_old']);
  });

  it('drops the previous secret once the window closes', () => {
    // The bug this guards: rotation used to keep the old secret valid forever,
    // so rotating after a leak revoked nothing at all.
    const secrets = activeSecrets(
      endpoint({ secretPrevious: 'whsec_leaked', secretRotatedAt: hoursAgo(25) }),
      { overlapSeconds: OVERLAP, now: NOW },
    );
    expect(secrets).toEqual(['whsec_current']);
    expect(secrets).not.toContain('whsec_leaked');
  });

  it('treats the boundary as closed', () => {
    const exactly = new Date(NOW - OVERLAP * 1000);
    expect(
      activeSecrets(endpoint({ secretPrevious: 'whsec_old', secretRotatedAt: exactly }), {
        overlapSeconds: OVERLAP,
        now: NOW,
      }),
    ).toEqual(['whsec_current']);
  });

  it('fails closed when a previous secret has no rotation timestamp', () => {
    // Missing metadata must not mean "valid indefinitely" for a credential.
    expect(
      activeSecrets(endpoint({ secretPrevious: 'whsec_orphan', secretRotatedAt: null }), {
        overlapSeconds: OVERLAP,
        now: NOW,
      }),
    ).toEqual(['whsec_current']);
  });
});

describe('rotation as seen by a receiver', () => {
  const body = JSON.stringify({ id: 'evt_1' });
  const ts = Math.floor(NOW / 1000);

  const headerFor = (ep, now) =>
    buildSignatureHeader({
      secrets: activeSecrets(ep, { overlapSeconds: OVERLAP, now }),
      timestamp: ts,
      rawBody: body,
    });

  it('a receiver on the old secret keeps working during the window', () => {
    const header = headerFor(
      endpoint({ secretPrevious: 'whsec_old', secretRotatedAt: hoursAgo(2) }),
      NOW,
    );
    expect(verifySignature({ header, secret: 'whsec_old', timestamp: ts, rawBody: body, now: ts }).valid).toBe(true);
    expect(verifySignature({ header, secret: 'whsec_current', timestamp: ts, rawBody: body, now: ts }).valid).toBe(true);
  });

  it('the old secret stops verifying after the window — rotation revokes', () => {
    const header = headerFor(
      endpoint({ secretPrevious: 'whsec_old', secretRotatedAt: hoursAgo(30) }),
      NOW,
    );
    expect(verifySignature({ header, secret: 'whsec_old', timestamp: ts, rawBody: body, now: ts }).valid).toBe(false);
    expect(verifySignature({ header, secret: 'whsec_current', timestamp: ts, rawBody: body, now: ts }).valid).toBe(true);
  });
});
