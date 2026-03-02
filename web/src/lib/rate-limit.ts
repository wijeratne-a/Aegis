/**
 * In-memory sliding-window rate limiter for the verify proxy.
 * In production, use Redis or Upstash for distributed rate limiting.
 * Callers should use a session-based identifier (e.g. session:userId) when
 * available so the limit cannot be bypassed by spoofing X-Forwarded-For.
 */

const windowMs = 60 * 1000; // 1 minute
const maxRequests = 30; // X verifications per minute per identifier

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

export function checkRateLimit(identifier: string): { allowed: boolean; remaining: number } {
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
