import { request } from 'undici';
import { config } from '../config.js';
import { inspectUrl } from '../security/ssrf.js';
import { activeSecrets, buildSignatureHeader } from './signature.js';

/**
 * Receiver response classification.
 *
 *   success   - 2xx. Done.
 *   permanent - 410 Gone. The receiver is explicitly saying "stop sending".
 *               Retrying is not just useless, it ignores an instruction.
 *   retry     - everything else, including 4xx.
 *
 * Retrying 4xx looks wrong at first glance, but a 401 or 404 from a receiver is
 * usually a deploy in progress or a misconfiguration the customer is about to
 * fix, not a permanent verdict. Treating it as fatal would silently drop events
 * during a routine deploy. 410 exists precisely to say "actually permanent".
 */
function classify(status) {
  if (status >= 200 && status < 300) return 'success';
  if (status === 410) return 'permanent';
  return 'retry';
}

/**
 * Reads at most `limit` bytes of the response for the delivery inspector.
 *
 * Bounded on purpose: the receiver is untrusted and may return a gigabyte of
 * HTML, or stream forever. We want a diagnostic snippet, not their output.
 */
async function readSnippet(body, limit) {
  const chunks = [];
  let total = 0;
  try {
    for await (const chunk of body) {
      chunks.push(chunk);
      total += chunk.length;
      if (total >= limit) break;
    }
  } catch {
    // A body that fails mid-read still leaves whatever arrived worth keeping.
  }
  return Buffer.concat(chunks).subarray(0, limit).toString('utf8');
}

function classifyTransportError(err) {
  const code = err?.code ?? err?.cause?.code;
  switch (code) {
    case 'UND_ERR_HEADERS_TIMEOUT':
    case 'UND_ERR_BODY_TIMEOUT':
    case 'UND_ERR_CONNECT_TIMEOUT':
      return 'timeout';
    case 'ENOTFOUND':
    case 'EAI_AGAIN':
      return 'dns_failure';
    case 'ECONNREFUSED':
      return 'connection_refused';
    case 'ECONNRESET':
    case 'UND_ERR_SOCKET':
      return 'connection_reset';
    case 'CERT_HAS_EXPIRED':
    case 'UNABLE_TO_VERIFY_LEAF_SIGNATURE':
    case 'DEPTH_ZERO_SELF_SIGNED_CERT':
      return 'tls_error';
    default:
      return code ? `transport_${code.toLowerCase()}` : 'transport_error';
  }
}

/**
 * Performs one delivery attempt.
 *
 * Never throws. A delivery attempt failing is ordinary operation, not an
 * exception — the caller needs a classified outcome it can record and schedule
 * from, and forcing a try/catch at every call site would invite one to be
 * missed and a claimed delivery to be stranded IN_FLIGHT until its lease
 * expires.
 *
 * The SSRF guard is installed on the dispatcher's DNS lookup rather than as a
 * check here, so the address approved by the guard is the address connected to.
 * A blocked target surfaces as an ERR_SSRF_BLOCKED transport error.
 */
export async function attemptDelivery({ delivery, dispatcher }) {
  const { endpoint, event } = delivery;

  // Shape-level check first. It needs no DNS, so an unsupported scheme fails
  // instantly instead of after a pointless resolution.
  const urlVerdict = inspectUrl(endpoint.url, {
    allowPrivate: config.ALLOW_PRIVATE_DELIVERY_TARGETS,
  });
  if (urlVerdict.blocked) {
    return {
      outcome: 'blocked',
      status: null,
      latencyMs: 0,
      bodySnippet: null,
      errorKind: 'blocked_target',
      blockReason: urlVerdict.reason,
      requestHeaders: null,
    };
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const rawBody = JSON.stringify({
    id: event.id,
    type: event.eventType,
    created_at: event.createdAt.toISOString(),
    data: event.payload,
  });

  const headers = {
    'content-type': 'application/json',
    'user-agent': 'Relay/1.0',
    // Stable across every retry of this delivery. This is the key receivers
    // deduplicate on, and the reason at-least-once is safe for them.
    'x-relay-id': delivery.id,
    'x-relay-timestamp': String(timestamp),
    'x-relay-attempt': String(delivery.attemptCount),
    'x-relay-event-type': event.eventType,
    'x-relay-signature': buildSignatureHeader({
      // Not simply [current, previous]: the previous secret is dropped once its
      // overlap window closes, so a rotation actually revokes.
      secrets: activeSecrets(endpoint, { overlapSeconds: config.SECRET_OVERLAP_SECONDS }),
      timestamp,
      rawBody,
    }),
  };

  const startedAt = process.hrtime.bigint();
  const elapsedMs = () => Number((process.hrtime.bigint() - startedAt) / 1_000_000n);

  // Two independent bounds. headersTimeout caps how long the receiver may take
  // to start responding; the AbortSignal caps the whole exchange, so a receiver
  // that dribbles bytes forever cannot hold a worker slot indefinitely.
  const signal = AbortSignal.timeout(config.DELIVERY_TOTAL_TIMEOUT_MS);

  try {
    const response = await request(endpoint.url, {
      method: 'POST',
      headers,
      body: rawBody,
      dispatcher,
      signal,
      headersTimeout: config.DELIVERY_CONNECT_TIMEOUT_MS,
      bodyTimeout: config.DELIVERY_TOTAL_TIMEOUT_MS,
      // Redirects are not followed. A 301 to an internal address is a trivial
      // SSRF bypass, and a webhook receiver that redirects is misconfigured.
      maxRedirections: 0,
    });

    const bodySnippet = await readSnippet(response.body, config.DELIVERY_MAX_RESPONSE_BYTES);
    const outcome = classify(response.statusCode);

    return {
      outcome,
      status: response.statusCode,
      latencyMs: elapsedMs(),
      bodySnippet,
      errorKind: outcome === 'success' ? null : `http_${response.statusCode}`,
      requestHeaders: { ...headers, 'x-relay-signature': '[redacted]' },
    };
  } catch (err) {
    const blocked = err?.code === 'ERR_SSRF_BLOCKED' || err?.cause?.code === 'ERR_SSRF_BLOCKED';
    if (blocked) {
      const cause = err.code === 'ERR_SSRF_BLOCKED' ? err : err.cause;
      return {
        outcome: 'blocked',
        status: null,
        latencyMs: elapsedMs(),
        bodySnippet: null,
        errorKind: 'blocked_target',
        blockReason: cause.reason,
        requestHeaders: { ...headers, 'x-relay-signature': '[redacted]' },
      };
    }

    const errorKind =
      err?.name === 'TimeoutError' || err?.name === 'AbortError'
        ? 'timeout'
        : classifyTransportError(err);

    return {
      outcome: 'retry',
      status: null,
      latencyMs: elapsedMs(),
      bodySnippet: null,
      errorKind,
      requestHeaders: { ...headers, 'x-relay-signature': '[redacted]' },
    };
  }
}
