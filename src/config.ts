/**
 * Environment-driven service configuration. Everything has a safe default so a
 * self-hoster can boot with nothing but a signer key; every knob is disclosed
 * (minus secrets) at `GET /v1/info`.
 */

export interface ServiceConfig {
  /** Solana RPC endpoint the service reads state from and sends attest txs to. */
  rpcUrl: string;
  /** Human label for the cluster (info/reporting only; the RPC is the truth). */
  cluster: string;
  /**
   * Attestation TTL in seconds. `expires_at = recordedAt + ttl`; 0 disables
   * expiry (matches the historical first-party behavior). Default 30 days.
   */
  attestationTtlSeconds: number;
  /**
   * Optional bearer API keys. When non-empty, POST endpoints require
   * `Authorization: Bearer <key>` with a listed key. GET endpoints stay open.
   * NOT kit-entitlement gating — any key holder is a first-class caller.
   */
  apiKeys: string[];
  /** Per-IP requests per window for POST endpoints. */
  rateLimitPerIp: number;
  /**
   * GLOBAL POST ceiling per window across all callers — the economic bound on
   * the hot signer key (each CLEAN attest signs + pays a mainnet tx).
   */
  rateLimitGlobal: number;
  /** Rate-limit window in milliseconds. */
  rateLimitWindowMs: number;
  /** Optional Upstash REST binding for a cross-instance shared limiter. */
  upstashUrl: string | null;
  upstashToken: string | null;
}

function intEnv(name: string, fallback: number, min = 0): number {
  const raw = process.env[name];
  if (!raw || !raw.trim()) return fallback;
  const parsed = Number.parseInt(raw.trim(), 10);
  if (!Number.isFinite(parsed) || parsed < min) return fallback;
  return parsed;
}

function nonEmpty(value: string | undefined): string | null {
  const trimmed = value?.trim();
  return trimmed ? trimmed : null;
}

export const DEFAULT_ATTESTATION_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days

export function loadConfig(): ServiceConfig {
  return {
    rpcUrl: nonEmpty(process.env.RPC_URL) ?? "https://api.mainnet-beta.solana.com",
    cluster: nonEmpty(process.env.CLUSTER_LABEL) ?? "mainnet",
    attestationTtlSeconds: intEnv(
      "ATTESTATION_TTL_SECONDS",
      DEFAULT_ATTESTATION_TTL_SECONDS,
    ),
    apiKeys: (process.env.ATTEST_API_KEYS ?? "")
      .split(",")
      .map((k) => k.trim())
      .filter(Boolean),
    rateLimitPerIp: intEnv("RATE_LIMIT_PER_IP", 6, 1),
    rateLimitGlobal: intEnv("RATE_LIMIT_GLOBAL", 60, 1),
    rateLimitWindowMs: intEnv("RATE_LIMIT_WINDOW_MS", 60_000, 1_000),
    upstashUrl: nonEmpty(process.env.KV_REST_API_URL ?? process.env.UPSTASH_REDIS_REST_URL),
    upstashToken: nonEmpty(process.env.KV_REST_API_TOKEN ?? process.env.UPSTASH_REDIS_REST_TOKEN),
  };
}
