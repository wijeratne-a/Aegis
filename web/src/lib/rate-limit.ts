/**
 * In-memory sliding-window rate limiter.
 *
 * PRODUCTION NOTE -- Distributed Rate Limiting with Redis
 * -------------------------------------------------------
 * This in-memory implementation works for single-instance deployments. For
 * production clusters with multiple replicas, replace with a Redis-backed
 * sliding window using MULTI/EXEC + ZRANGEBYSCORE (sorted-set pattern) or
 * the token-bucket Lua script approach.
 *
 * When REDIS_URL is set in the environment, install `ioredis` and swap the
 * Map-based store below for Redis sorted sets keyed by identifier. Example:
 *
 *   import Redis from "ioredis";
 *   const redis = new Redis(process.env.REDIS_URL);
 *   // ZADD <key> <now> <now>   -- add timestamp
 *   // ZREMRANGEBYSCORE <key> 0 <now - windowMs>  -- trim old
 *   // ZCARD <key>              -- count in window
 *   // EXPIRE <key> <windowSec> -- auto-cleanup
 *
 * The docker-compose stack and Helm chart include a Redis service gated
 * behind `redis.enabled`. Set REDIS_URL=redis://aegis-redis:6379 in the
 * deployment environment to activate it.
 *
 * When behind a trusted proxy, configure trust proxy and use a single
 * forwarded header only (e.g. X-Forwarded-For) to mitigate spoofing.
 */

const windowMs = 60 * 1000; // 1 minute

const timestamps = new Map<string, number[]>();

function cleanup(now: number) {
  for (const [key, times] of timestamps.entries()) {
    const within = times.filter((t) => now - t < windowMs);
    if (within.length === 0) {
      timestamps.delete(key);
    } else {
      timestamps.set(key, within);
    }
  }
}

function checkLimit(
  identifier: string,
  maxRequests: number
): { allowed: boolean; remaining: number } {
  const now = Date.now();
  cleanup(now);

  const times = timestamps.get(identifier) ?? [];
  const withinWindow = times.filter((t) => now - t < windowMs);

  if (withinWindow.length >= maxRequests) {
    return { allowed: false, remaining: 0 };
  }

  withinWindow.push(now);
  timestamps.set(identifier, withinWindow);
  return { allowed: true, remaining: maxRequests - withinWindow.length };
}

/** 30/min per identifier (register, verify). */
export function checkRateLimit(identifier: string): { allowed: boolean; remaining: number } {
  return checkLimit(identifier, 30);
}

/** 60/min per identifier (receipt ingest). */
export function checkReceiptIngestLimit(identifier: string): {
  allowed: boolean;
  remaining: number;
} {
  return checkLimit(identifier, 60);
}

/** 5/min per IP (login). */
export function checkLoginLimit(identifier: string): { allowed: boolean; remaining: number } {
  return checkLimit(identifier, 5);
}
