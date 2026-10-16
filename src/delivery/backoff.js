/**
 * Retry scheduling.
 *
 * The ceiling for each successive attempt. Eight attempts spanning roughly 24
 * hours: long enough that a receiver can survive a night of downtime without
 * losing events, short enough that a permanently dead endpoint stops consuming
 * worker capacity within a day.
 */
const SCHEDULE_MS = [
  5_000, //      5s
  30_000, //    30s
  120_000, //    2m
  600_000, //   10m
  3_600_000, //  1h
  10_800_000, // 3h
  21_600_000, // 6h
  43_200_000, // 12h
];

export const MAX_ATTEMPTS = SCHEDULE_MS.length;

/**
 * Delay before the next attempt, with equal jitter:
 *
 *   delay = cap/2 + random(0, cap/2)
 *
 * Jitter of some kind is mandatory. Without it, every delivery that failed
 * during an outage retries at the same instant the receiver recovers, and the
 * synchronised thundering herd knocks it straight back over.
 *
 * Equal jitter rather than AWS-style full jitter (`random(0, cap)`), which the
 * architecture notes originally called for. Full jitter can schedule a retry
 * microseconds after a failure, so a receiver that is genuinely down gets
 * hammered instead of backed off. It also makes the total retry window wildly
 * variable, when the window is a promise to the customer. Equal jitter keeps
 * the guaranteed minimum spacing while still spreading the herd.
 *
 * `random` is injectable so tests can pin the distribution instead of asserting
 * on ranges.
 */
export function nextAttemptDelayMs(attemptsMade, random = Math.random) {
  if (!Number.isInteger(attemptsMade) || attemptsMade < 1) {
    throw new RangeError(`attemptsMade must be a positive integer, received ${attemptsMade}`);
  }

  // attemptsMade counts attempts already completed, so the delay *after* the
  // first failure uses the first schedule entry.
  const cap = SCHEDULE_MS[Math.min(attemptsMade - 1, SCHEDULE_MS.length - 1)];
  const half = cap / 2;
  return Math.floor(half + random() * half);
}

/** Whether a failure at this attempt count exhausts the schedule. */
export function isExhausted(attemptsMade) {
  return attemptsMade >= MAX_ATTEMPTS;
}

export function nextAttemptAt(attemptsMade, now = Date.now(), random = Math.random) {
  return new Date(now + nextAttemptDelayMs(attemptsMade, random));
}

export const scheduleForTesting = SCHEDULE_MS;
