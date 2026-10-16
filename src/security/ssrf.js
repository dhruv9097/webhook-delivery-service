import { lookup as dnsLookup } from 'node:dns';
import { isIP, isIPv4, isIPv6 } from 'node:net';

/**
 * SSRF defence for customer-supplied delivery URLs.
 *
 * Relay makes HTTP requests to addresses its customers choose. Without a guard
 * that is a server-side request forgery machine: point an endpoint at
 * http://169.254.169.254/ and the delivery worker fetches cloud instance
 * credentials and posts the response body into the delivery inspector, where
 * the attacker reads it.
 *
 * Three properties make this guard actually work:
 *
 * 1. It validates the RESOLVED IP, not the hostname. A hostname tells you
 *    nothing — `internal.attacker.com` can have an A record for 10.0.0.1.
 *
 * 2. It resolves exactly once, and hands the validated address to the socket.
 *    The classic bypass is DNS rebinding: resolve for the check, get a public
 *    IP, then let the HTTP client resolve again for the connection and get a
 *    private one. Because this runs as undici's `lookup`, the address we
 *    approved IS the address connected to. There is no second resolution to
 *    poison.
 *
 * 3. It unwraps IPv4-mapped IPv6. `::ffff:169.254.169.254` is a valid IPv6
 *    address that routes to the IPv4 metadata endpoint, and a check that only
 *    understands IPv6 prefixes waves it straight through.
 *
 * Numeric obfuscation (2130706433, 0x7f.0.0.1, 017700000001) needs no special
 * handling: those are decoded during resolution, and what reaches this code is
 * always a canonical address.
 *
 * IMPORTANT: the lookup hook is necessary but NOT sufficient. Node performs no
 * DNS resolution when the host is already an IP literal, so a URL like
 * http://169.254.169.254/ never reaches the resolver and the hook never fires.
 * Literal addresses must therefore be inspected separately, which inspectUrl
 * does. Relying on the hook alone leaves the most obvious attack wide open.
 */

// [network, prefix length, why it is blocked]
const BLOCKED_V4 = [
  ['0.0.0.0', 8, 'this network'],
  ['10.0.0.0', 8, 'private network (RFC1918)'],
  ['100.64.0.0', 10, 'carrier-grade NAT (RFC6598)'],
  ['127.0.0.0', 8, 'loopback'],
  ['169.254.0.0', 16, 'link-local — includes cloud instance metadata'],
  ['172.16.0.0', 12, 'private network (RFC1918)'],
  ['192.0.0.0', 24, 'IETF protocol assignments'],
  ['192.0.2.0', 24, 'documentation (TEST-NET-1)'],
  ['192.88.99.0', 24, '6to4 relay anycast'],
  ['192.168.0.0', 16, 'private network (RFC1918)'],
  ['198.18.0.0', 15, 'benchmarking'],
  ['198.51.100.0', 24, 'documentation (TEST-NET-2)'],
  ['203.0.113.0', 24, 'documentation (TEST-NET-3)'],
  ['224.0.0.0', 4, 'multicast'],
  ['240.0.0.0', 4, 'reserved — includes broadcast'],
];

const BLOCKED_V6 = [
  ['::', 128, 'unspecified address'],
  ['::1', 128, 'loopback'],
  ['64:ff9b::', 96, 'IPv4/IPv6 translation'],
  ['100::', 64, 'discard-only'],
  ['2001:db8::', 32, 'documentation'],
  ['fc00::', 7, 'unique local address'],
  ['fe80::', 10, 'link-local'],
  ['ff00::', 8, 'multicast'],
];

function v4ToBytes(ip) {
  return ip.split('.').map(Number);
}

/** Expands an IPv6 address to its 16 bytes, including any trailing IPv4 part. */
function v6ToBytes(ip) {
  let addr = ip.split('%')[0]; // drop any zone index

  // A trailing dotted-quad (::ffff:1.2.3.4) becomes two hex groups so the rest
  // of the expansion can treat the address uniformly.
  const lastColon = addr.lastIndexOf(':');
  const tail = addr.slice(lastColon + 1);
  if (isIPv4(tail)) {
    const [a, b, c, d] = v4ToBytes(tail);
    addr = `${addr.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }

  let groups;
  if (addr.includes('::')) {
    const [head, rest] = addr.split('::');
    const headGroups = head ? head.split(':').filter(Boolean) : [];
    const tailGroups = rest ? rest.split(':').filter(Boolean) : [];
    const missing = 8 - headGroups.length - tailGroups.length;
    groups = [...headGroups, ...Array(Math.max(missing, 0)).fill('0'), ...tailGroups];
  } else {
    groups = addr.split(':');
  }

  const bytes = [];
  for (const group of groups.slice(0, 8)) {
    const value = Number.parseInt(group || '0', 16);
    bytes.push((value >> 8) & 0xff, value & 0xff);
  }
  while (bytes.length < 16) bytes.push(0);
  return bytes;
}

function withinBlock(bytes, networkBytes, prefixBits) {
  const wholeBytes = prefixBits >> 3;
  for (let i = 0; i < wholeBytes; i += 1) {
    if (bytes[i] !== networkBytes[i]) return false;
  }
  const remainingBits = prefixBits & 7;
  if (remainingBits === 0) return true;
  const mask = (0xff << (8 - remainingBits)) & 0xff;
  return (bytes[wholeBytes] & mask) === (networkBytes[wholeBytes] & mask);
}

/**
 * Classifies a resolved IP address.
 * Returns { blocked: boolean, reason?: string }.
 */
export function inspectAddress(ip) {
  if (isIPv4(ip)) {
    const bytes = v4ToBytes(ip);
    for (const [network, prefix, reason] of BLOCKED_V4) {
      if (withinBlock(bytes, v4ToBytes(network), prefix)) return { blocked: true, reason };
    }
    return { blocked: false };
  }

  if (isIPv6(ip)) {
    const bytes = v6ToBytes(ip);

    // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d) addresses
    // reach IPv4 destinations, so they must be judged by IPv4 rules. Skipping
    // this is the single most common hole in a hand-rolled SSRF filter.
    const firstTenZero = bytes.slice(0, 10).every((b) => b === 0);
    if (firstTenZero && bytes[10] === 0xff && bytes[11] === 0xff) {
      const embedded = bytes.slice(12).join('.');
      const verdict = inspectAddress(embedded);
      return verdict.blocked
        ? { blocked: true, reason: `IPv4-mapped address → ${verdict.reason}` }
        : verdict;
    }
    // The named IPv6 blocks are checked BEFORE the IPv4-compatible unwrapping
    // below. Order matters: ::1 and :: both look like IPv4-compatible forms of
    // 0.0.0.1 and 0.0.0.0, so unwrapping first would report them as "this
    // network" instead of "loopback" and "unspecified address". Both stay
    // blocked either way, but the reason is shown to the customer as the
    // explanation for a failed delivery, so it has to be the true one.
    for (const [network, prefix, reason] of BLOCKED_V6) {
      if (withinBlock(bytes, v6ToBytes(network), prefix)) return { blocked: true, reason };
    }

    // IPv4-compatible (::a.b.c.d). Deprecated by RFC4291 but still routable,
    // and reached only once the named blocks above have had their say.
    if (firstTenZero && bytes[10] === 0 && bytes[11] === 0 && bytes.slice(12).some((b) => b !== 0)) {
      const embedded = bytes.slice(12).join('.');
      const verdict = inspectAddress(embedded);
      return verdict.blocked
        ? { blocked: true, reason: `IPv4-compatible address → ${verdict.reason}` }
        : verdict;
    }

    return { blocked: false };
  }

  return { blocked: true, reason: 'unparseable address' };
}

export class BlockedAddressError extends Error {
  constructor(hostname, reason) {
    super(`Refusing to connect to ${hostname}: ${reason}`);
    this.name = 'BlockedAddressError';
    this.code = 'ERR_SSRF_BLOCKED';
    this.hostname = hostname;
    this.reason = reason;
  }
}

/**
 * Shape-level URL checks that need no DNS.
 *
 * `allowPrivate` must be threaded through here, not just into the resolver
 * hook. The two paths have to agree: a hostname resolving to 127.0.0.1 and the
 * literal 127.0.0.1 are the same destination, so honouring the development
 * escape hatch for one and not the other means local development works for
 * `localhost` but silently fails for `127.0.0.1`.
 *
 * Protocol and credential checks are never relaxed — those are not about
 * private ranges and there is no development case for file:// delivery.
 */
export function inspectUrl(rawUrl, { allowPrivate = false } = {}) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return { blocked: true, reason: 'malformed URL' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { blocked: true, reason: `unsupported protocol ${url.protocol}` };
  }
  // file:// and gopher:// are the obvious ones, but credentials in the URL are
  // also refused: they would be sent to whatever the host resolves to.
  if (url.username || url.password) {
    return { blocked: true, reason: 'credentials in URL are not supported' };
  }

  // An IP literal bypasses DNS entirely, so the resolver hook never sees it.
  // This is the check that actually stops http://169.254.169.254/.
  // URL.hostname wraps IPv6 in brackets; strip them before parsing.
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  if (isIP(hostname) && !allowPrivate) {
    const verdict = inspectAddress(hostname);
    if (verdict.blocked) return { blocked: true, reason: `literal address — ${verdict.reason}` };
  }

  return { blocked: false, url };
}

/**
 * Builds a DNS lookup function for undici's `connect` options.
 *
 * Installing the guard here rather than as a pre-flight check is the entire
 * point: undici calls this to obtain the address it will connect to, so the
 * approved address and the connected address are the same value. A separate
 * "check the URL first, then request it" design leaves a window between the
 * two resolutions, and that window is the vulnerability.
 */
export function createGuardedLookup({ allowPrivate = false, resolver = dnsLookup } = {}) {
  return function guardedLookup(hostname, options, callback) {
    const done = typeof options === 'function' ? options : callback;
    const rawOptions = typeof options === 'function' ? {} : options;
    const opts = typeof rawOptions === 'number' ? { family: rawOptions } : (rawOptions ?? {});

    // `all: true` so every candidate address is inspected. Checking only the
    // first would let a host with one public and one private A record through
    // whenever the resolver happened to order them favourably.
    resolver(hostname, { ...opts, all: true }, (err, addresses) => {
      if (err) return done(err);

      const candidates = Array.isArray(addresses) ? addresses : [addresses];
      const verdicts = candidates.map((entry) => ({ entry, verdict: inspectAddress(entry.address) }));
      const permitted = verdicts.filter(({ verdict }) => allowPrivate || !verdict.blocked);

      if (permitted.length === 0) {
        const reason = verdicts[0]?.verdict.reason ?? 'no addresses resolved';
        return done(new BlockedAddressError(hostname, reason));
      }

      if (opts.all) return done(null, permitted.map(({ entry }) => entry));
      const { entry } = permitted[0];
      return done(null, entry.address, entry.family);
    });
  };
}
