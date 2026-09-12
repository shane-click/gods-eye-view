/**
 * @module access-gate-rate-limit
 *
 * Failed-login throttle for the access gate. Counts failures per client and
 * across all clients inside a sliding window; a client over either limit is
 * refused until the oldest failure in its window ages out. In-memory and
 * process-local, which is the right scope for a single-instance deployment.
 */

export const LOGIN_WINDOW_MS = 15 * 60 * 1000;
export const MAX_FAILURES_PER_CLIENT = 5;
export const MAX_FAILURES_GLOBAL = 60;
const MAX_TRACKED_CLIENTS = 10000;

/**
 * @typedef {object} LoginRateLimiter
 * @property {(clientKey: string) => {allowed: boolean, retryAfterMs: number}} check
 * @property {(clientKey: string) => void} recordFailure
 * @property {(clientKey: string) => void} recordSuccess
 */

/**
 * Create a limiter. `now` is injectable so tests can move time.
 *
 * @param {object} [options]
 * @param {number} [options.windowMs]
 * @param {number} [options.maxPerClient]
 * @param {number} [options.maxGlobal]
 * @param {() => number} [options.now]
 * @returns {LoginRateLimiter}
 */
export function createLoginRateLimiter({
  windowMs = LOGIN_WINDOW_MS,
  maxPerClient = MAX_FAILURES_PER_CLIENT,
  maxGlobal = MAX_FAILURES_GLOBAL,
  now = () => Date.now(),
} = {}) {
  /** @type {Map<string, number[]>} failure timestamps per client key */
  const failuresByClient = new Map();
  /** @type {number[]} failure timestamps across every client */
  const globalFailures = [];

  function dropExpired(timestamps, current) {
    const cutoff = current - windowMs;
    while (timestamps.length && timestamps[0] <= cutoff) timestamps.shift();
  }

  function retryAfterFrom(timestamps, current) {
    return Math.max(0, timestamps[0] + windowMs - current);
  }

  function forgetIdleClients(current) {
    if (failuresByClient.size <= MAX_TRACKED_CLIENTS) return;
    for (const [key, timestamps] of failuresByClient) {
      dropExpired(timestamps, current);
      if (!timestamps.length) failuresByClient.delete(key);
    }
  }

  return {
    check(clientKey) {
      const current = now();
      dropExpired(globalFailures, current);
      if (globalFailures.length >= maxGlobal) {
        return { allowed: false, retryAfterMs: retryAfterFrom(globalFailures, current) };
      }
      const timestamps = failuresByClient.get(clientKey);
      if (!timestamps) return { allowed: true, retryAfterMs: 0 };
      dropExpired(timestamps, current);
      if (timestamps.length >= maxPerClient) {
        return { allowed: false, retryAfterMs: retryAfterFrom(timestamps, current) };
      }
      return { allowed: true, retryAfterMs: 0 };
    },

    recordFailure(clientKey) {
      const current = now();
      forgetIdleClients(current);
      const timestamps = failuresByClient.get(clientKey) || [];
      timestamps.push(current);
      failuresByClient.set(clientKey, timestamps);
      globalFailures.push(current);
    },

    recordSuccess(clientKey) {
      failuresByClient.delete(clientKey);
    },
  };
}
