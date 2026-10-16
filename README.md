# Relay

A multi-tenant webhook delivery service with at-least-once semantics. Customers
POST events; Relay delivers them to their registered HTTP endpoints, signed,
retried, and observable.

Full design rationale lives in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Architecture

One codebase, two process types:

| Process | Entry | Responsibility |
|---|---|---|
| `api` | `src/server.js` | Ingest, CRUD. Never makes outbound delivery calls. |
| `worker` | `src/worker.js` | Claims due deliveries, signs, delivers, reschedules. |

- **Postgres is the source of truth.** An event and its delivery rows commit in
  one transaction. `Event` and `Delivery` are separate tables, so one dead
  endpoint accumulates retries on its own rows without affecting anyone else.
- **Redis holds only disposable state:** circuit breaker counters and rate limit
  buckets. Losing Redis degrades throughput shaping; it cannot lose a delivery.
- **Delivery is at-least-once.** Every attempt carries a stable `X-Relay-Id`
  that receivers use to deduplicate.
- **Signing** is HMAC-SHA256 over `{timestamp}.{raw_body}`, with expiring
  secret rotation (both secrets verify during an overlap window).
- **SSRF guard** on both hostnames (resolver hook) and IP literals.
- **Per-endpoint circuit breaker**, token-bucket rate limiting, strict tenant
  isolation (cross-tenant access returns 404).

## Queue

Today the queue *is* Postgres. Workers claim due rows with a lease:

```sql
UPDATE deliveries SET state = 'IN_FLIGHT', locked_until = now() + interval '60 seconds', ...
WHERE id IN (SELECT id FROM deliveries
             WHERE state IN ('PENDING','RETRYING') AND next_attempt_at <= now()
             ORDER BY next_attempt_at LIMIT $batch
             FOR UPDATE SKIP LOCKED)
```

- `SKIP LOCKED` lets N workers pull disjoint batches with no coordination.
- `locked_until` is a lease: if a worker is killed mid-delivery, the reaper
  returns the expired row to `RETRYING`.
- The cost is latency: a delivery waits up to `WORKER_POLL_INTERVAL_MS` (1s by
  default) before a worker notices it.

**In progress (milestone 3): BullMQ fast path.** Enqueue to Redis after commit
so workers pick up new deliveries without waiting for the poll, plus a
reconciler that sweeps Postgres for rows that are due but missing from Redis.
Redis stays an accelerator, never the record. This is not built yet; the
Postgres claim path above is what runs today and will remain the fallback.

## Roadmap

| Milestone | Scope | Status |
|---|---|---|
| 1-2 | Ingest, fan-out, lease-based claiming, retries, signing, SSRF guard, circuit breaker, rate limiting, tenant isolation, graceful shutdown | Done |
| 3 | BullMQ fast path and reconciler | In progress |
| 4 | Dashboard: delivery inspector, live feed, replay | Planned |
| 5 | OpenTelemetry / Prometheus / Grafana; hermetic integration tests (testcontainers) | Planned |
| 6 | OpenAPI spec, JS SDK, SLO.md, RUNBOOK.md, `delivery_attempts` partitioning | Planned |

## Running locally

Requires Node 22+ and Docker.

```sh
cp .env.example .env          # then fill in secrets (see comments in the file)
docker compose up -d          # postgres, redis, migrations, api, worker
npm ci
npm run seed
```

Postgres and Redis are exposed on host ports 5442 and 6389.

## Tests

```sh
npm test                # unit tests (vitest)
npm run lint
npm run test:all        # unit + integration + chaos; needs the stack running
```

The integration and chaos scripts expect the API and the mock receiver
(`mock-receiver/`) to be running, and they share the dev database. Hermetic
tests are planned for milestone 5.
