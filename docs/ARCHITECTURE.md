# Relay — Architecture

Written before the delivery engine exists, deliberately. If the design cannot be
explained first, it is not finished.

## Status

Built and covered by tests: ingest with idempotency, transactional fan-out, the
lease-based claim protocol, retries with jitter, HMAC signing with expiring
rotation, the SSRF guard, per-endpoint circuit breaking, rate limiting, tenant
isolation, and graceful shutdown.

Not built yet: the BullMQ fast path and its reconciler, the dashboard,
observability (OpenTelemetry, Prometheus, Grafana), the OpenAPI spec and SDK,
and table partitioning. Each is listed under "Not yet built".

**Everything else in this document describes code that exists.** Anything
aspirational belongs in that section, not in the prose.

## What this is

A multi-tenant webhook delivery service. Customers POST events; Relay delivers
them to their registered HTTP endpoints, signed, retried, and observable.

## The one decision everything else follows from

**`Event` and `Delivery` are separate tables.**

An event is a fact ("invoice.paid happened"). A delivery is one attempt-chain to
one endpoint. One event subscribed to by three endpoints creates three delivery
rows, each with its own state, attempt count, and retry schedule.

This is the failure-isolation boundary. If deliveries were columns on the event,
one customer's dead endpoint would hold the whole event in a retrying state and
couple unrelated tenants' fates together. Separated, a dead endpoint accumulates
retries on its own rows and nobody else notices.

## Process topology

One codebase, two process types — 12-factor, and the reason deploying later is
a configuration change rather than a rewrite.

| Process | Entry | Responsibility |
|---|---|---|
| `api` | `src/server.js` | Ingest, CRUD, SSE feed. Never makes outbound delivery calls. |
| `worker` | `src/worker.js` | Claims due deliveries, signs, delivers, reschedules. |

The API never delivers. A slow receiver must not be able to consume an HTTP
request thread, and ingest latency must stay independent of how healthy any
customer's endpoint is.

## Durability: Postgres is the truth

Postgres holds every piece of delivery state. Workers find due work by polling
it directly — there is no message broker in the delivery path.

The write path is one transaction: the event and its delivery rows commit
together, or neither exists. A worker then claims due rows with the lease
protocol below. Nothing has to be published anywhere for a delivery to happen,
which means there is no window where a committed event is invisible because a
separate enqueue failed.

Redis is used, but never for delivery state. It holds circuit breaker counters
and rate limit buckets — high-churn data that is safe to lose, where the worst
case is one round of re-learning. Losing Redis entirely degrades throughput
shaping and failure detection; it cannot lose a delivery.

**Polling has a real cost, and it is latency.** A delivery becomes due at most
`WORKER_POLL_INTERVAL_MS` before a worker notices (1s by default), and idle
workers issue a query per interval whether or not there is work. At current
scale that is the right trade: the claim query is a single indexed scan against
a partial index, and correctness needs no second system to agree with the first.

A BullMQ fast path is planned to remove the poll delay — enqueue after commit,
with a reconciler sweeping Postgres for rows that are due but missing from Redis,
so Redis stays an accelerator and never becomes the record. **It is not built.**
See "Not yet built" at the end of this document.

## The claim protocol

```sql
UPDATE deliveries SET
  state = 'IN_FLIGHT',
  locked_until = now() + interval '60 seconds',
  locked_by = $worker_id
WHERE id IN (
  SELECT id FROM deliveries
  WHERE state IN ('PENDING','RETRYING') AND next_attempt_at <= now()
  ORDER BY next_attempt_at
  LIMIT $batch
  FOR UPDATE SKIP LOCKED
)
RETURNING *;
```

`SKIP LOCKED` lets N workers pull disjoint batches with no coordination, no
leader election, and no distributed lock.

`locked_until` is a **lease**, and it is the entire answer to "what happens when
a worker is SIGKILLed mid-delivery". The row stays `IN_FLIGHT` with an expiry;
the reaper finds expired leases and returns them to `RETRYING`. No cleanup
handshake, no heartbeat protocol — recovery is a consequence of the data model.

This is why `WORKER_LEASE_SECONDS` must exceed `DELIVERY_TOTAL_TIMEOUT_MS`.
If it does not, a slow-but-healthy delivery has its lease expire mid-flight and
a second worker delivers it again. `src/config.js` refuses to start on that
misconfiguration rather than letting it surface as a duplicate-delivery mystery.

Both scan patterns are served by **partial** indexes
(`prisma/migrations/*_delivery_claim_indexes`). Most rows are terminal and will
never be scanned again; indexing only live states keeps the index proportional
to the backlog rather than to total history.

## Delivery semantics

**At-least-once, not exactly-once.** Exactly-once across a network boundary is
not achievable: a receiver can process a request and then have the response lost
in transit, and no amount of protocol fixes that ambiguity.

What Relay guarantees instead:
- Every delivery reaches a terminal state, including across worker crashes.
- Every attempt carries a stable `X-Relay-Id`, constant across retries.
- Receivers deduplicate on that ID. This is documented, not implied.

## Retry policy

`5s → 30s → 2m → 10m → 1h → 3h → 6h → 12h`, then `FAILED_PERMANENT` (~24h).

Applied with **equal jitter**: `delay = cap/2 + random(0, cap/2)`.

Fixed backoff synchronises every delivery that failed during an outage into one
thundering herd the moment the receiver recovers — re-killing it. Jitter spreads
the recovery load.

Equal jitter rather than AWS-style full jitter (`random(0, cap)`), which this
document originally specified. Full jitter can schedule a retry microseconds
after a failure, so a receiver that is genuinely down gets hammered instead of
backed off, and it makes the total retry window wildly variable when that window
is a promise to the customer. Equal jitter keeps a guaranteed minimum spacing
while still spreading the herd. Measured window: 16.7h median, bounded 11.1h to
33.3h.

## Classification of receiver responses

| Response | Outcome |
|---|---|
| 2xx | success |
| 410 Gone | permanent — the receiver explicitly asked us to stop |
| everything else, 4xx included | retry |

Retrying 4xx looks wrong until you consider what actually produces one: a 401 or
404 from a receiver is usually a deploy in progress or a misconfiguration about
to be fixed, not a permanent verdict. Treating it as fatal would silently drop
events during a routine deploy. 410 exists precisely to say "actually
permanent", and is honoured.

## Security boundaries

**Tenant isolation lives in the query.** Every read filters on `orgId`; every
write is an `updateMany` scoped by `orgId` so a foreign ID matches zero rows.
Never fetch-then-check — that leaves a path where the check can be forgotten.

Cross-tenant access returns **404, not 403**. A 403 confirms the ID exists,
which leaks the existence of other tenants' records to anyone who can guess.

**Credentials are hashed, never stored.** API keys as `sha256` (they are 190
bits of uniform randomness — nothing to brute force, and argon2 on every request
would be pure latency). User passwords as argon2id (chosen by humans, therefore
guessable, therefore deliberately slow).

**Two credential types, one guard.** `requireRole` models humans, `requireScope`
models machines, and they cannot be stacked — `requireRole('ADMIN')` rejects
every API key and makes an adjacent `requireScope` unreachable. Routes serving
both use `requireWrite`. Minting API keys stays human-only: a key that can mint
keys can escalate its own scopes and outlive revocation of the original.

**SSRF is the defining risk.** Customers supply the URLs we make requests to.
`src/security/ssrf.js` defends it on two independent paths, and both are
required:

1. **Hostnames** go through a guard installed as undici's `connect.lookup`. It
   resolves once, inspects every returned address, and hands back only approved
   ones. Because the pool uses this function *as* its resolver, the address
   approved is the address connected to — there is no second resolution to
   poison, which is what closes DNS rebinding.

2. **IP literals** are inspected by `inspectUrl` before the request is made.
   This path exists because Node performs no DNS lookup at all when the host is
   already an IP, so the resolver hook never fires for `http://169.254.169.254/`
   — the most obvious attack in the class. A live probe caught this: it produced
   `EHOSTUNREACH`, a real connection attempt, rather than a block. On a laptop
   that fails for lack of a route; on a cloud instance it would have succeeded.

IPv4-mapped IPv6 (`::ffff:169.254.169.254`) is unwrapped and re-judged by IPv4
rules. Numeric obfuscation needs no special handling — those forms are decoded
during resolution, so what the classifier sees is always canonical.

A blocked target fails permanently rather than retrying: the denylist will not
change on its own, and it deliberately does not feed the circuit breaker, since
a configuration fault is not a receiver outage.

**Circuit breaker, per endpoint.** Twenty consecutive failures opens the
circuit; the cooldown doubles on each re-open up to an hour; a single half-open
probe (claimed with `SET NX`, so concurrent workers cannot stampede a
recovering receiver) decides whether to close. After twelve re-opens the
endpoint is disabled in Postgres — durable, because the breaker alone never
gives up and some endpoints are simply gone.

A deferral by an open circuit does **not** consume retry budget and writes no
attempt row. Without that, a delivery behind an open circuit burns all eight
attempts on deferrals and reaches `FAILED_PERMANENT` having never been sent.

**Rate limiting** is a token bucket evaluated in a single Lua script. Atomicity
is the whole point: a read-modify-write limiter lets concurrent callers each
observe the same token count and all proceed, so the limit is exceeded by
roughly the concurrency level exactly when it matters. Buckets are per API key
and per tenant, never global, so one noisy customer cannot spend everyone
else's budget. The limiter fails open — a limiter that rejects everything when
Redis is unavailable turns a blip into an outage.

## Signing

HMAC-SHA256 over `{timestamp}.{raw_body}`, sent as:

```
X-Relay-Id:        del_...        stable across retries — the dedup key
X-Relay-Timestamp: 1758700000     receivers reject >5min skew (replay defence)
X-Relay-Attempt:   3
X-Relay-Signature: v1,<sig> v1,<sig-from-previous-secret>
```

Two signatures is what makes rotation zero-downtime: both verify during the
overlap window, so events in flight during a rotation do not fail verification.

The overlap window **expires** (`SECRET_OVERLAP_SECONDS`, 24h by default), and
that expiry is the point. An earlier version stored the previous secret and
never retired it, so both secrets signed forever and rotating after a leak
revoked nothing — the one thing rotation exists to do. The expired secret is
also purged from the database by the maintenance sweep, because "no longer used"
and "no longer stored" are different security properties. A previous secret with
no rotation timestamp is treated as already expired: for a credential, missing
metadata must fail closed.

Signing covers the **raw bytes**. Re-serializing parsed JSON can reorder keys
and produce a signature the receiver can never reproduce, which is why
`src/http/app.js` retains `req.rawBody`.

## Health vs readiness

`/health` is liveness and deliberately touches no dependency. A Postgres outage
should not cause an orchestrator to kill and restart every healthy process,
which only adds load to an already-struggling system.

`/ready` is readiness and does check dependencies. Both return 503 while
draining, so a load balancer stops routing before the listener closes.

## Rejected alternatives

| Considered | Why not |
|---|---|
| Redis/BullMQ as source of truth | Not durable enough to be the only record of a delivery. |
| Deliver inline from the API request | Couples ingest latency to the slowest customer endpoint. |
| Offset pagination | Degrades on deep pages; concurrent inserts shift the window and silently skip rows. |
| Guaranteeing ordered delivery | Head-of-line blocking: one stuck event stalls every later one for that endpoint. Opt-in per partition key is the right shape if it is ever needed. |
| 403 on cross-tenant access | Confirms the ID exists. 404 leaks nothing. |
| Exactly-once delivery | Not achievable across a network. At-least-once plus a documented dedup key is honest. |

## Not yet built

| Item | Why it matters | Planned |
|---|---|---|
| BullMQ fast path + reconciler | Removes up to one poll interval of delivery latency | Week 3 remainder |
| Dashboard | Delivery inspector, live feed, replay | Week 4 |
| OpenTelemetry / Prometheus / Grafana | No metrics or traces are emitted today | Week 5 |
| Hermetic integration tests (testcontainers) | The suite currently needs a hand-started stack and shares the dev database | Week 5 |
| OpenAPI spec, JS SDK, SLO.md, RUNBOOK.md | No published contract or operational docs yet | Week 6 |
| `delivery_attempts` partitioning | Retention is unbounded; the table grows forever | Week 6 |

## Known limitations

- **No ordering guarantee** between deliveries to the same endpoint. Deliveries
  are independent by design; opt-in FIFO per partition key is the right shape if
  it is ever needed, with the head-of-line-blocking cost made explicit.
- **Signing secrets are stored in plaintext.** They cannot be hashed — we need
  the value to sign with — so a database dump lets an attacker forge webhooks to
  every customer. Envelope encryption with a key held outside the database is
  the fix; it is not implemented.
- **`WORKER_CLAIM_BATCH` can outrun the connection pool.** `config.js` validates
  that the lease exceeds a single delivery's timeout, but not that a claimed
  batch fits the undici pool (128 connections per origin). Claiming far more
  than that for one host leaves deliveries queued behind the pool long enough to
  lose their lease and be delivered twice. Defaults (20 vs 128) are safe.
- **Circuit breaker state is per-fleet in Redis**; a flush re-learns it.
- **Deployment is local Docker only** — no live URL, no real uptime data.
