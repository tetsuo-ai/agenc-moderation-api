/** Non-secret environment configuration for the single-host attestor. */

import { DEFAULT_JOB_SPEC_REGISTRY_URL } from "./retrievability.js";

export interface ServiceConfig {
  /** Solana RPC endpoint the service reads state from and sends attest txs to. */
  rpcUrl: string;
  pinEnabled: boolean;
  storePath: string;
  spendLimits: import('./store.js').SpendLimits;
  /** Human label for the cluster (info/reporting only; the RPC is the truth). */
  cluster: string;
  /**
   * Job-spec registry base URL for the retrievability gate — every attestation
   * must reference content retrievable here, at an https specUri, or pinned by
   * this service. Default: the official marketplace registry.
   */
  jobSpecRegistryUrl: string;
  /** Operator token for explicitly enabled, creator-authenticated pins. */
  jobSpecRegistryToken: string | null;
  /** Fixed 72-hour intake TTL. */
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

export const DEFAULT_ATTESTATION_TTL_SECONDS = 72 * 60 * 60; // 72 hours

export function loadConfig(): ServiceConfig {
  return {
    pinEnabled: process.env.ENABLE_SPEC_PINNING === '1',
    storePath: process.env.ATTESTATION_DB_PATH ?? './data/attestations.sqlite',
    spendLimits: {hourlyLamports:intEnv('SPEND_HOURLY_LAMPORTS',30_000_000),dailyLamports:intEnv('SPEND_DAILY_LAMPORTS',150_000_000),dailyIntakes:intEnv('CREATOR_DAILY_INTAKES',20),hourlyTasks:intEnv('CREATOR_HOURLY_TASKS',5),walletFloor:intEnv('WALLET_FLOOR_LAMPORTS',100_000_000)},
    rpcUrl: nonEmpty(process.env.RPC_URL) ?? "https://api.mainnet-beta.solana.com",
    cluster: nonEmpty(process.env.CLUSTER_LABEL) ?? "mainnet",
    jobSpecRegistryUrl: nonEmpty(process.env.JOB_SPEC_REGISTRY_URL) ?? DEFAULT_JOB_SPEC_REGISTRY_URL,
    jobSpecRegistryToken: nonEmpty(process.env.JOB_SPEC_REGISTRY_TOKEN),
    attestationTtlSeconds: DEFAULT_ATTESTATION_TTL_SECONDS,
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
