import { describe, expect, it } from 'vitest';
import {
  BlockedAddressError,
  createGuardedLookup,
  inspectAddress,
  inspectUrl,
} from '../../src/security/ssrf.js';

/** Table-driven: each row is an address an attacker might try to reach. */
const BLOCKED = [
  ['169.254.169.254', 'AWS/GCP/Azure instance metadata — the crown jewels'],
  ['169.254.170.2', 'ECS task metadata'],
  ['127.0.0.1', 'loopback'],
  ['127.1.1.1', 'loopback, non-obvious form'],
  ['0.0.0.0', 'this network'],
  ['10.0.0.1', 'RFC1918'],
  ['10.255.255.255', 'RFC1918 upper bound'],
  ['172.16.0.1', 'RFC1918 lower bound of the /12'],
  ['172.31.255.254', 'RFC1918 upper bound of the /12'],
  ['192.168.1.1', 'RFC1918 home network'],
  ['100.64.0.1', 'carrier-grade NAT'],
  ['224.0.0.1', 'multicast'],
  ['255.255.255.255', 'broadcast'],
  ['::1', 'IPv6 loopback'],
  ['::', 'IPv6 unspecified'],
  ['fe80::1', 'IPv6 link-local'],
  ['fd00::1', 'IPv6 unique local'],
  ['ff02::1', 'IPv6 multicast'],
  ['::ffff:169.254.169.254', 'IPv4-mapped metadata — the classic filter bypass'],
  ['::ffff:127.0.0.1', 'IPv4-mapped loopback'],
  ['::ffff:10.0.0.1', 'IPv4-mapped RFC1918'],
  ['64:ff9b::a00:1', 'NAT64-translated RFC1918'],
];

const ALLOWED = [
  ['1.1.1.1', 'public resolver'],
  ['8.8.8.8', 'public resolver'],
  ['93.184.216.34', 'ordinary public host'],
  ['172.32.0.1', 'just above the RFC1918 /12 — must NOT be caught'],
  ['172.15.255.255', 'just below the RFC1918 /12 — must NOT be caught'],
  ['11.0.0.1', 'adjacent to 10/8 — must NOT be caught'],
  ['100.128.0.1', 'above the CGNAT /10 — must NOT be caught'],
  ['2606:4700:4700::1111', 'public IPv6'],
  ['2001:db9::1', 'adjacent to the documentation range — must NOT be caught'],
];

describe('inspectAddress', () => {
  it.each(BLOCKED)('blocks %s (%s)', (ip) => {
    const verdict = inspectAddress(ip);
    expect(verdict.blocked, `${ip} should be blocked`).toBe(true);
    expect(verdict.reason).toBeTruthy();
  });

  it.each(ALLOWED)('allows %s (%s)', (ip) => {
    expect(inspectAddress(ip).blocked, `${ip} should be allowed`).toBe(false);
  });

  // Regression: ::1 and :: also parse as IPv4-compatible forms of 0.0.0.1 and
  // 0.0.0.0. Unwrapping them before consulting the named IPv6 blocks reported
  // "this network" for loopback — still blocked, but the wrong explanation, and
  // that string is shown to the customer.
  it.each([
    ['::1', /loopback/],
    ['::', /unspecified/],
    ['fe80::1', /link-local/],
    ['fd00::1', /unique local/],
    ['::ffff:169.254.169.254', /IPv4-mapped.*metadata/],
  ])('reports the true reason for %s', (ip, pattern) => {
    const verdict = inspectAddress(ip);
    expect(verdict.blocked).toBe(true);
    expect(verdict.reason).toMatch(pattern);
  });

  it('rejects anything it cannot parse rather than defaulting to allow', () => {
    for (const junk of ['', 'not-an-ip', '999.999.999.999', '1.2.3']) {
      expect(inspectAddress(junk).blocked, `${junk} should be blocked`).toBe(true);
    }
  });
});

describe('inspectUrl', () => {
  it('rejects non-HTTP schemes', () => {
    for (const url of ['file:///etc/passwd', 'gopher://x/', 'ftp://x/', 'data:text/plain,hi']) {
      expect(inspectUrl(url).blocked, url).toBe(true);
    }
  });

  it('rejects credentials embedded in the URL', () => {
    expect(inspectUrl('http://user:pass@example.com/hook').blocked).toBe(true);
  });

  it('accepts ordinary delivery URLs', () => {
    expect(inspectUrl('https://example.com/webhooks/relay').blocked).toBe(false);
    expect(inspectUrl('http://example.com:8080/hook?x=1').blocked).toBe(false);
  });
});

describe('createGuardedLookup', () => {
  const resolverReturning = (addresses) => (hostname, options, callback) =>
    callback(null, addresses.map((address) => ({ address, family: address.includes(':') ? 6 : 4 })));

  it('passes through a public address', async () => {
    const lookup = createGuardedLookup({ resolver: resolverReturning(['93.184.216.34']) });
    const result = await new Promise((resolve) =>
      lookup('example.com', {}, (err, address) => resolve({ err, address })),
    );
    expect(result.err).toBeNull();
    expect(result.address).toBe('93.184.216.34');
  });

  it('blocks a public hostname whose A record points at the metadata service', async () => {
    const lookup = createGuardedLookup({ resolver: resolverReturning(['169.254.169.254']) });
    const result = await new Promise((resolve) =>
      lookup('evil.example.com', {}, (err) => resolve({ err })),
    );
    expect(result.err).toBeInstanceOf(BlockedAddressError);
    expect(result.err.code).toBe('ERR_SSRF_BLOCKED');
    expect(result.err.reason).toMatch(/metadata/i);
  });

  it('filters a poisoned address out of a mixed result set', async () => {
    // A host advertising both a public and a private address must not be
    // allowed to connect to the private one just because ordering favours it.
    const lookup = createGuardedLookup({ resolver: resolverReturning(['10.0.0.5', '93.184.216.34']) });
    const result = await new Promise((resolve) =>
      lookup('mixed.example.com', {}, (err, address) => resolve({ err, address })),
    );
    expect(result.err).toBeNull();
    expect(result.address).toBe('93.184.216.34');
  });

  it('blocks when every resolved address is private', async () => {
    const lookup = createGuardedLookup({ resolver: resolverReturning(['10.0.0.5', '192.168.1.1']) });
    const result = await new Promise((resolve) => lookup('internal.example.com', {}, (err) => resolve({ err })));
    expect(result.err).toBeInstanceOf(BlockedAddressError);
  });

  it('defeats DNS rebinding by returning the address it approved', async () => {
    // A rebinding resolver answers public first, private second. A guard that
    // checked once and let the HTTP client resolve again would connect to the
    // second answer. Because undici uses this function AS its resolver, the
    // approved address is the connected address — the second answer is never
    // consulted for this connection.
    let call = 0;
    const rebinding = (hostname, options, callback) => {
      call += 1;
      const address = call === 1 ? '93.184.216.34' : '169.254.169.254';
      callback(null, [{ address, family: 4 }]);
    };

    const lookup = createGuardedLookup({ resolver: rebinding });
    const first = await new Promise((resolve) =>
      lookup('rebind.example.com', {}, (err, address) => resolve({ err, address })),
    );

    expect(first.err).toBeNull();
    expect(first.address).toBe('93.184.216.34');
    expect(call).toBe(1);

    // The later flip is still caught, because every connection re-validates.
    const second = await new Promise((resolve) =>
      lookup('rebind.example.com', {}, (err) => resolve({ err })),
    );
    expect(second.err).toBeInstanceOf(BlockedAddressError);
  });

  it('honours the development escape hatch', async () => {
    const lookup = createGuardedLookup({
      allowPrivate: true,
      resolver: resolverReturning(['127.0.0.1']),
    });
    const result = await new Promise((resolve) =>
      lookup('localhost', {}, (err, address) => resolve({ err, address })),
    );
    expect(result.err).toBeNull();
    expect(result.address).toBe('127.0.0.1');
  });
});

describe('inspectUrl with literal IP hosts', () => {
  // Regression guard. The resolver hook cannot catch these: Node does no DNS
  // lookup for an IP literal, so nothing calls it. Discovered when a live probe
  // to http://169.254.169.254/ produced EHOSTUNREACH — a real connection
  // attempt — instead of a block.
  const HOSTILE_LITERALS = [
    'http://169.254.169.254/latest/meta-data/',
    'http://127.0.0.1:5432/',
    'http://10.0.0.1/admin',
    'http://192.168.1.1/',
    'http://172.16.0.1/',
    'http://[::1]:8080/',
    'http://[::ffff:169.254.169.254]/',
    'http://[fd00::1]/',
    'http://0.0.0.0/',
    'http://255.255.255.255/',
  ];

  it.each(HOSTILE_LITERALS)('blocks %s without any DNS lookup', (url) => {
    const verdict = inspectUrl(url);
    expect(verdict.blocked, url).toBe(true);
    expect(verdict.reason).toMatch(/literal address/);
  });

  it('still allows a public literal address', () => {
    expect(inspectUrl('http://93.184.216.34/hook').blocked).toBe(false);
    expect(inspectUrl('http://[2606:4700:4700::1111]/hook').blocked).toBe(false);
  });

  it('allows ordinary hostnames, which the resolver hook then validates', () => {
    expect(inspectUrl('https://example.com/hook').blocked).toBe(false);
  });
});

describe('inspectUrl escape hatch consistency', () => {
  // Regression: the literal check originally ignored allowPrivate while the
  // resolver hook honoured it, so http://localhost:4210/ worked in development
  // but http://127.0.0.1:4210/ did not. Worse, the resulting "blocked target"
  // classification is deliberately excluded from the circuit breaker, so a
  // failing local endpoint silently never tripped it.
  it('permits private literals when the escape hatch is on', () => {
    for (const url of ['http://127.0.0.1:4210/hook', 'http://10.0.0.1/hook', 'http://[::1]:8080/hook']) {
      expect(inspectUrl(url, { allowPrivate: true }).blocked, url).toBe(false);
    }
  });

  it('still refuses non-HTTP schemes and embedded credentials even then', () => {
    expect(inspectUrl('file:///etc/passwd', { allowPrivate: true }).blocked).toBe(true);
    expect(inspectUrl('http://u:p@127.0.0.1/', { allowPrivate: true }).blocked).toBe(true);
  });

  it('blocks private literals by default', () => {
    expect(inspectUrl('http://127.0.0.1:4210/hook').blocked).toBe(true);
  });
});
