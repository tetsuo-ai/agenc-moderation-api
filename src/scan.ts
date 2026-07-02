/**
 * Deterministic moderation scanner (`task-safety-policy-v1`).
 *
 * Ported rule-for-rule from the agenc.ag first-party signer
 * (`agenc-ag/apps/web/lib/server/moderation-signer.ts`), whose rules were in
 * turn ported verbatim from the storefront reference
 * (`agenc-services-storefront/server/verifiedTasks.ts`). The scan is
 * deliberately deterministic (regex deny rules, no ML): identical input text
 * always produces the identical verdict, so a verifier can re-run it.
 *
 * The scanner NEVER attests partially-scanned content: exceeding the text-input
 * cap degrades to `blocked` (a hold), not to a pass.
 */

import { createHash } from "node:crypto";

/**
 * `task_moderation_status::*` (agenc-coordination `state.rs`). The on-chain
 * consumption/hire gates accept only CLEAN | HUMAN_APPROVED; this service
 * auto-attests CLEAN and HOLDS (never signs) everything else.
 */
export const MODERATION_STATUS = {
  CLEAN: 0,
  SUSPICIOUS: 1,
  BLOCKED: 2,
  SCANNER_UNAVAILABLE: 3,
  HUMAN_APPROVED: 4,
  HUMAN_REJECTED: 5,
} as const;

export type Verdict = "clean" | "suspicious" | "blocked";

/** Heuristic riskScore by verdict (blocked 100, suspicious 60, clean 0). */
const HEURISTIC_RISK_SCORE: Record<Verdict, number> = {
  blocked: 100,
  suspicious: 60,
  clean: 0,
};

type PolicySeverity = "reject" | "warning" | "info";

interface PolicyRule {
  ruleId: string;
  severity: PolicySeverity;
  category: string;
  /** Bit in the on-chain `category_mask` u64 this rule contributes when matched. */
  categoryBit: bigint;
  patterns: RegExp[];
}

/**
 * Deterministic policy rules (`task-safety-policy-v1`), ported VERBATIM
 * (patterns + severities). All five are reject-severity → a match blocks.
 */
const POLICY_RULES: PolicyRule[] = [
  {
    ruleId: "PROMPT_INJECTION_OVERRIDE",
    severity: "reject",
    category: "prompt_injection",
    categoryBit: 1n << 0n,
    patterns: [
      /ignore\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions/i,
      /ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:system|developer)\s+instructions/i,
      /disregard\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions/i,
      /disregard\s+(?:all\s+)?(?:previous|prior)\s+(?:system|developer)\s+instructions/i,
      /override\s+(?:the\s+)?(?:policy|instructions|guardrails|system prompt)/i,
      /you\s+are\s+now\s+(?:in\s+)?developer\s+mode/i,
      /follow\s+only\s+my\s+instructions/i,
    ],
  },
  {
    ruleId: "PROMPT_OR_SECRET_EXFILTRATION",
    severity: "reject",
    category: "secrets",
    categoryBit: 1n << 1n,
    patterns: [
      /reveal\s+(?:the\s+)?(?:system|developer|hidden)\s+prompt/i,
      /(?:read|print|dump|show|exfiltrate|upload|copy)\s+(?:the\s+)?(?:\.env|env\s+file|api\s*key|token|password|private\s+key|ssh\s+key|seed\s+phrase|wallet\s+seed|secret)/i,
      /\b(?:api\s*key|private\s+key|ssh\s+key|seed\s+phrase|wallet\s+seed)\b/i,
      /\b[A-Z0-9_]*(?:SECRET|TOKEN|PRIVATE_KEY|API_KEY|PASSWORD)[A-Z0-9_]*\b/,
    ],
  },
  {
    ruleId: "AUTH_OR_ACCESS_BYPASS",
    severity: "reject",
    category: "abuse",
    categoryBit: 1n << 2n,
    patterns: [
      /\bbypass\s+(?:auth|authentication|authorization|access\s+control|paywall|captcha|rate\s+limit|robots)/i,
      /\b(?:evade|disable)\s+(?:captcha|rate\s+limit|access\s+control|security)/i,
      /\bscrape\s+behind\s+(?:a\s+)?(?:login|paywall)/i,
    ],
  },
  {
    ruleId: "MALWARE_OR_EXPLOIT",
    severity: "reject",
    category: "malware",
    categoryBit: 1n << 3n,
    patterns: [
      /\b(?:malware|ransomware|keylogger|phishing|credential\s+harvest|steal\s+credentials)\b/i,
      /\b(?:exploit|reverse\s+shell|privilege\s+escalation|sql\s+injection|xss)\b/i,
      /\b(?:spam|mass\s+email|bulk\s+dm|bot\s+accounts)\b/i,
    ],
  },
  {
    ruleId: "SHELL_OR_HOST_ACCESS",
    severity: "reject",
    category: "tools",
    categoryBit: 1n << 4n,
    patterns: [
      /\b(?:run|execute)\s+(?:a\s+)?(?:shell|bash|terminal|command|script)\b/i,
      /\b(?:rm\s+-rf|curl\s+[^|]+\|\s*(?:sh|bash)|chmod\s+\+x|sudo\s+)/i,
      /\b(?:read|write|modify|delete)\s+(?:local\s+)?(?:files?|filesystem|home\s+directory)\b/i,
    ],
  },
];

/**
 * Scanner descriptor for THIS service. Versioned distinctly from the storefront
 * (`agenc-moderation-api:scanner:policy-rules:<v>:v1`) and the agenc.ag
 * first-party signer (`agenc-ag-moderation:...:listing-task:v1`) so a verifier
 * can tell which scanner produced an attestation from `scanner_hash` alone.
 */
const TASK_SAFETY_POLICY_VERSION = "task-safety-policy-v1";
export const SCANNER_DESCRIPTOR = `agenc-moderation-api:scanner:policy-rules:${TASK_SAFETY_POLICY_VERSION}:public-service:v1`;

/** sha256 of the stable scanner descriptor — the on-chain `scanner_hash` (32 bytes). */
export function scannerHashBytes(): Uint8Array {
  return new Uint8Array(createHash("sha256").update(SCANNER_DESCRIPTOR).digest());
}

export function scannerHashHex(): string {
  return Buffer.from(scannerHashBytes()).toString("hex");
}

const MAX_TEXT_INPUTS = 256;
const TRUNCATED_INPUT_CATEGORY_BIT = 1n << 5n;

/**
 * Structured execution-plan fields excluded from prose scanning. These fields
 * legitimately name secret/env/shell patterns in deny lists or transport
 * config. Unexpected `execution.*` fields are still scanned.
 */
const KIT_SPEC_UNSCANNED_EXECUTION_KEYS = new Set([
  "adapter",
  "allowedDomains",
  "allowedHostnames",
  "allowedHosts",
  "allowedTools",
  "args",
  "blockedCommands",
  "blockedEnvPrefixes",
  "blockedHosts",
  "command",
  "container",
  "deniedTools",
  "env",
  "environment",
  "forbiddenCommands",
  "forbiddenToolGroups",
  "image",
  "network",
  "permissions",
  "resourceLimits",
  "runtime",
  "sandbox",
  "timeout",
  "timeoutMs",
  "toolAllowlist",
  "toolDenylist",
  "transport",
]);

interface SpecTextInput {
  source: string;
  value: string;
}

interface SpecTextCollection {
  inputs: SpecTextInput[];
  truncated: boolean;
}

function collectStringsRecursively(value: unknown, path: string, out: SpecTextInput[]): boolean {
  if (typeof value === "string") {
    if (!value.trim()) return false;
    if (out.length >= MAX_TEXT_INPUTS) return true;
    out.push({ source: path, value });
    return false;
  }
  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) {
      if (collectStringsRecursively(item, `${path}[${index}]`, out)) return true;
    }
    return false;
  }
  if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (collectStringsRecursively(item, `${path}.${key}`, out)) return true;
    }
  }
  return false;
}

/**
 * The text surface the scanner sees: every string value in the PAYLOAD
 * recursively, except known execution-plan config fields on kit-shaped
 * payloads. Non-kit payloads are scanned over all string values recursively.
 */
function collectSpecTextInputReport(payload: Record<string, unknown>): SpecTextCollection {
  const out: SpecTextInput[] = [];
  const kitShaped =
    payload.kind === "agenc.marketplace.jobSpec" ||
    typeof payload.title === "string" ||
    typeof payload.shortDescription === "string";
  if (!kitShaped) {
    return { inputs: out, truncated: collectStringsRecursively(payload, "spec", out) };
  }
  let truncated = false;
  for (const [key, value] of Object.entries(payload)) {
    if (key === "execution" && value && typeof value === "object" && !Array.isArray(value)) {
      for (const [executionKey, executionValue] of Object.entries(value as Record<string, unknown>)) {
        if (KIT_SPEC_UNSCANNED_EXECUTION_KEYS.has(executionKey)) continue;
        truncated ||= collectStringsRecursively(
          executionValue,
          `spec.execution.${executionKey}`,
          out,
        );
        if (truncated) break;
      }
      if (truncated) break;
      continue;
    }
    truncated ||= collectStringsRecursively(value, `spec.${key}`, out);
    if (truncated) break;
  }
  return { inputs: out, truncated };
}

export function collectSpecTextInputs(payload: Record<string, unknown>): SpecTextInput[] {
  return collectSpecTextInputReport(payload).inputs;
}

export interface ScanResult {
  verdict: Verdict;
  /** On-chain `status` u8 (CLEAN/SUSPICIOUS/BLOCKED). */
  status: number;
  /** On-chain `risk_score` u8 (≤100). */
  riskScore: number;
  /** On-chain `category_mask` u64 (OR of matched rule bits; 0 when clean). */
  categoryMask: bigint;
  /** True when the scanner refused to attest because the text surface exceeded its cap. */
  truncated: boolean;
}

/**
 * Deterministic scan. Any reject-severity match → blocked; any warning-severity
 * match → suspicious; else clean. `category_mask` is the OR of every matched
 * rule's bit (0 when clean). Over-cap input → blocked (hold), never a partial
 * pass.
 */
export function scanPayload(payload: Record<string, unknown>): ScanResult {
  const { inputs, truncated } = collectSpecTextInputReport(payload);
  if (truncated) {
    return {
      verdict: "blocked",
      status: MODERATION_STATUS.BLOCKED,
      riskScore: HEURISTIC_RISK_SCORE.blocked,
      categoryMask: TRUNCATED_INPUT_CATEGORY_BIT,
      truncated: true,
    };
  }
  let hasReject = false;
  let hasWarning = false;
  let categoryMask = 0n;
  for (const input of inputs) {
    for (const rule of POLICY_RULES) {
      if (!rule.patterns.some((pattern) => pattern.test(input.value))) continue;
      categoryMask |= rule.categoryBit;
      if (rule.severity === "reject") hasReject = true;
      else if (rule.severity === "warning") hasWarning = true;
    }
  }
  const verdict: Verdict = hasReject ? "blocked" : hasWarning ? "suspicious" : "clean";
  const status =
    verdict === "blocked"
      ? MODERATION_STATUS.BLOCKED
      : verdict === "suspicious"
        ? MODERATION_STATUS.SUSPICIOUS
        : MODERATION_STATUS.CLEAN;
  return {
    verdict,
    status,
    riskScore: HEURISTIC_RISK_SCORE[verdict],
    categoryMask,
    truncated: false,
  };
}
