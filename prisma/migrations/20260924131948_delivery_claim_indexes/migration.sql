-- Partial indexes for the worker's two scan patterns. Prisma's schema language
-- cannot express a WHERE clause on an index, so these are written by hand.
--
-- Both are partial on purpose. The vast majority of rows in `deliveries` are
-- terminal (SUCCEEDED or FAILED_PERMANENT) and will never be scanned again.
-- Indexing only the live states keeps these indexes proportional to the current
-- backlog rather than to total history, so they stay in memory and the claim
-- query does not degrade as the table grows to millions of rows.

-- The claim query: due deliveries, oldest first.
--   WHERE state IN ('PENDING','RETRYING') AND next_attempt_at <= now()
--   ORDER BY next_attempt_at
--   FOR UPDATE SKIP LOCKED
CREATE INDEX "deliveries_due_idx"
  ON "deliveries" ("next_attempt_at")
  WHERE "state" IN ('PENDING', 'RETRYING');

-- The reaper: leases abandoned by workers that died mid-delivery.
--   WHERE state = 'IN_FLIGHT' AND locked_until < now()
CREATE INDEX "deliveries_expired_lease_idx"
  ON "deliveries" ("locked_until")
  WHERE "state" = 'IN_FLIGHT';
