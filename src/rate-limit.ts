/**
 * Fixed-window rate limiter: a strict per-IP bound PLUS a GLOBAL ceiling — the
 * real economic bound on the hot moderation key, which signs + pays a mainnet
 * tx on every CLEAN verdict.
 *
 * Design ported from agenc.ag's `lib/server/rate-limit.ts`, trimmed for this
 * service: when the Upstash REST env vars are set the counters live in shared
 * storage (one INCR+EXPIRE round trip, global across serverless instances);
 * otherwise it degrades to a bounded per-instance in-memory window — weaker
 * but never an unprotected pass. Redis errors fail OPEN to the in-memory
 * fallback (availability over a hard deny) which still bounds abuse.
 */

import type { ServiceConfig } from "./config.js";

export interface RateDecision {
  allowed: boolean;
  /** Seconds the caller should wait before retrying (when denied). */
  retryAfterSeconds: number;
  /** Which bound denied: "ip" | "global" | null. */
  deniedBy: "ip" | "global" | null;
}

/* ----------------------------- in-memory window --------------------------- */

interface WindowEntry {
  count: number;
  resetAt: number;
}

const localWindows = new Map<string, WindowEntry>();

function localIncr(key: string, windowMs: number): { count: number; resetAt: number } {
  const now = Date.now();
  const existing = localWindows.get(key);
  if (!existing || existing.resetAt <= now) {
    const entry = { count: 1, resetAt: now + windowMs };
    localWindows.set(key, entry);
    if (localWindows.size > 10_000) {
      // Bounded memory: drop expired entries when the map grows.
      for (const [k, v] of localWindows) {
        if (v.resetAt <= now) localWindows.delete(k);
      }
    }
    return entry;
  }
  existing.count += 1;
  return existing;
}

/* ------------------------------ Upstash REST ------------------------------ */

/**
 * One shared-storage INCR with TTL via the Upstash REST pipeline. Returns the
 * post-increment count, or null on any transport/shape error (caller falls
 * back to the in-memory window).
 */
async function upstashIncr(
  url: string,
  token: string,
  key: string,
  windowMs: number,
): Promise<number | null> {
  try {
    const response = await fetch(`${url}/pipeline`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify([
        ["INCR", key],
        ["PEXPIRE", key, String(windowMs), "NX"],
      ]),
      signal: AbortSignal.timeout(2_000),
    });
    if (!response.ok) return null;
    const parsed = (await response.json()) as Array<{ result?: unknown }>;
    const count = parsed?.[0]?.result;
    return typeof count === "number" && Number.isFinite(count) ? count : null;
  } catch {
    return null;
  }
}

/* --------------------------------- limiter -------------------------------- */

async function consume(
  config: ServiceConfig,
  key: string,
): Promise<{ count: number; retryAfterSeconds: number }> {
  const windowMs = config.rateLimitWindowMs;
  if (config.upstashUrl && config.upstashToken) {
    const bucket = Math.floor(Date.now() / windowMs);
    const shared = await upstashIncr(
      config.upstashUrl,
      config.upstashToken,
      `agenc-moderation:${key}:${bucket}`,
      windowMs,
    );
    if (shared !== null) {
      return {
        count: shared,
        retryAfterSeconds: Math.max(1, Math.ceil(((bucket + 1) * windowMs - Date.now()) / 1000)),
      };
    }
    // fall through to local on Redis failure
  }
  const entry = localIncr(key, windowMs);
  return {
    count: entry.count,
    retryAfterSeconds: Math.max(1, Math.ceil((entry.resetAt - Date.now()) / 1000)),
  };
}

/**
 * Consume one request against BOTH the per-IP bound and the global ceiling.
 * Exceeding either denies.
 */
export async function rateLimit(config: ServiceConfig, ip: string): Promise<RateDecision> {
  const perIp = await consume(config, `ip:${ip}`);
  if (perIp.count > config.rateLimitPerIp) {
    return { allowed: false, retryAfterSeconds: perIp.retryAfterSeconds, deniedBy: "ip" };
  }
  const global = await consume(config, "global");
  if (global.count > config.rateLimitGlobal) {
    return { allowed: false, retryAfterSeconds: global.retryAfterSeconds, deniedBy: "global" };
  }
  return { allowed: true, retryAfterSeconds: 0, deniedBy: null };
}

/** Best-effort client IP from proxy headers (Vercel sets x-forwarded-for). */
export function clientIp(request: Request): string {
  const fwd = request.headers.get("x-forwarded-for");
  if (fwd) {
    const first = fwd.split(",")[0]?.trim();
    if (first) return first;
  }
  return request.headers.get("x-real-ip")?.trim() || "unknown";
}

/** Test hook. */
export function __resetRateLimiterForTests(): void {
  localWindows.clear();
}
