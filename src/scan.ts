/** Deterministic desktop intake scan over normalized keys and values. */

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
  {ruleId:'ROLE_OVERRIDE',severity:'reject',category:'role_override',categoryBit:1n<<6n,patterns:[/\b(?:system|developer|assistant)\s*:\s*/i, /(?:act|behave)\s+as\s+(?:a\s+)?(?:system|developer|unrestricted)/i, /you\s+are\s+now/i]},
  {ruleId:'SIGNER_POLICY_MUTATION',severity:'reject',category:'signer_policy',categoryBit:1n<<7n,patterns:[/(?:modify|change|replace|disable|rotate|set|overwrite)\s+(?:the\s+)?(?:signer|attestor|policy|guardrails|moderator|signing\s+key)/i]},
  {ruleId:'SETTLEMENT_MANIPULATION',severity:'reject',category:'settlement',categoryBit:1n<<8n,patterns:[/(?:fake|forge|bypass|manipulate|force|override)\s+(?:the\s+)?(?:settlement|completion|approval|verdict|validation)/i]},
  {ruleId:'FUND_MOVEMENT',severity:'reject',category:'fund_movement',categoryBit:1n<<9n,patterns:[/(?:transfer|send|withdraw|drain|move)\s+(?:all\s+|the\s+)?(?:funds|sol|lamports|tokens|money|balance)/i, /(?:solana|spl-token)\s+transfer/i]},
  {ruleId:'HIDDEN_CONTENT',severity:'reject',category:'hidden_content',categoryBit:1n<<10n,patterns:[/display\s*:\s*none|visibility\s*:\s*hidden|<!--|<script/i]},
  {ruleId:'ENCODED_BLOB',severity:'reject',category:'encoded_blob',categoryBit:1n<<11n,patterns:[/\b(?:base64|hex)\s*[:=(]/i, /(?:%[0-9a-f]{2}){4,}/i, /\b(?:[0-9a-f]{2}){16,}\b/i, /\b(?=[A-Za-z0-9+/]*[A-Z])(?=[A-Za-z0-9+/]*[a-z])[A-Za-z0-9+/]{24,}={0,2}\b/]},
];

// Every byte of the executable regex bundle and preprocessing version is committed.
export const SCANNER_DESCRIPTOR = 'agenc-desktop:scanner:v1';
const NORMALIZATION_VERSION = 'nfkc-controls-keys-values-decode-v1';
export function scannerBundle(): string {
  return JSON.stringify({ normalization: NORMALIZATION_VERSION, maxDepth:32, maxTextInputs:512, distinctTextInputs:true, quotedBaseCommit:true, camelCaseIdentifiersNotBlobs:true, sandboxDeniedEnvNames:true, decodeRounds:3, decodeSurfaces:32, repoHexMetadata:["baseCommit","treeSha","allowedPathsHash","testCommandHash"], githubBaseCommitMetadata:true, workerImageDigest: process.env.WORKER_IMAGE_DIGEST ?? null,
    rules: POLICY_RULES.map(r => ({id:r.ruleId,severity:r.severity,category:r.category,bit:r.categoryBit.toString(),patterns:r.patterns.map(p=>({source:p.source,flags:p.flags}))})) });
}
export function scannerHashBytes(): Uint8Array { return createHash('sha256').update(scannerBundle()).digest(); }
export function scannerHashHex(): string { return Buffer.from(scannerHashBytes()).toString('hex'); }
// Distinct strings only: a kit job spec repeats the same keys and values in every
// execution criterion, and scanning one string twice gives the same answer.
const MAX_TEXT_INPUTS = 512;
const BLOCKED_ENV_PATH = /^spec\.execution\.sandbox\.environment\.blockedEnvPrefixes\[\d+\]$/;
const IDENTIFIER = /\b(?:[a-z]+|[A-Z][a-z]+)(?:[A-Z][a-z]+)+\b/g;
function declaredBaseCommits(payload: Record<string, unknown>): string[] {
  const pick = (value: unknown) => {
    const commit = value && typeof value === 'object' ? (value as {baseCommit?: unknown}).baseCommit : undefined;
    return typeof commit === 'string' && /^[0-9a-f]{40}$/.test(commit) ? [commit] : [];
  };
  const custom = payload.custom && typeof payload.custom === 'object' ? (payload.custom as {github?: unknown}).github : undefined;
  return [...new Set([...pick(custom), ...pick(payload.repo)])];
}
const HEX_METADATA_PATH = /^spec\.(?:repo\.(?:baseCommit|treeSha|allowedPathsHash|testCommandHash)|custom\.github\.baseCommit)$/;
const TRUNCATED_INPUT_CATEGORY_BIT = 1n << 5n;
const CONTROLS = /[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g;
function normalized(s: string): string { return s.normalize('NFKC').replace(CONTROLS,''); }
function surfaces(s: string): string[] {
  const out = [normalized(s)];
  // Bounded decoding; any encoded blob also independently blocks below.
  for(let round=0; round<3; round++) {
    for(const text of [...out]) {
      try { const decoded = normalized(decodeURIComponent(text)); if(!out.includes(decoded)) out.push(decoded); } catch { /* malformed */ }
      for(const token of text.match(/[A-Za-z0-9+/]{16,}={0,2}|(?:[0-9a-fA-F]{2}){8,}/g) ?? []) {
        for(const encoding of ['base64','hex'] as const) {
          const decoded = normalized(Buffer.from(token,encoding).toString('utf8'));
          if(decoded && !out.includes(decoded)) out.push(decoded);
        }
      }
      if(out.length > 32) return out.slice(0,32);
    }
  }
  return out;
}

interface SpecTextInput {
  source: string;
  value: string;
}

interface SpecTextCollection {
  inputs: SpecTextInput[];
  truncated: boolean;
  categories?: string[];
  reasons?: string[];
}

function collectStringsRecursively(value: unknown, path: string, out: SpecTextInput[], depth = 0, seen = new Set<string>()): boolean {
  if(depth > 32) return true;
  if (typeof value === "string") {
    // Hex metadata fields are exempt from the encoded-blob rule only at their own path, so the
    // same string anywhere else must still be scanned on its own.
    const metadata = HEX_METADATA_PATH.test(path);
    if (!value.trim() || (!metadata && seen.has(value))) return false;
    if (out.length >= MAX_TEXT_INPUTS) return true;
    if (!metadata) seen.add(value);
    out.push({ source: path, value });
    return false;
  }
  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) {
      if (collectStringsRecursively(item, `${path}[${index}]`, out, depth+1, seen)) return true;
    }
    return false;
  }
  if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (collectStringsRecursively(key, `${path}.${key}#key`, out, depth+1, seen)) return true;
      if (collectStringsRecursively(item, `${path}.${key}`, out, depth+1, seen)) return true;
    }
  }
  return false;
}

/** All payload keys and string values, including execution configuration. */
function collectSpecTextInputReport(payload: Record<string, unknown>): SpecTextCollection {
  const out: SpecTextInput[] = [];
  return {inputs:out,truncated:collectStringsRecursively(payload,'spec',out)};
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
  categories?: string[];
  reasons?: string[];
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
      reasons: ['INPUT_LIMIT'],
      truncated: true,
    };
  }
  let hasReject = false;
  let hasWarning = false;
  let categoryMask = 0n;
  const categories = new Set<string>(); const reasons = new Set<string>();
  const commits = declaredBaseCommits(payload);
  for (const input of inputs) {
    const metadataHash = (/^spec\.repo\.(baseCommit|treeSha|allowedPathsHash|testCommandHash)$/.test(input.source) && /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(input.value)) ||
      (input.source === 'spec.custom.github.baseCommit' && /^[0-9a-f]{40}$/.test(input.value));
    // An env var name in the sandbox deny-list names what the worker must never see.
    const deniedEnvName = BLOCKED_ENV_PATH.test(input.source) && /^[A-Z][A-Z0-9_]{1,63}$/.test(input.value);
    // The declared base commit may be quoted in prose; any other hex run is still a blob.
    const text = commits.reduce((current, commit) => current.split(commit).join('base-commit'), input.value);
    for (const rule of POLICY_RULES) {
      if(metadataHash && rule.ruleId === 'ENCODED_BLOB') continue;
      if(deniedEnvName && rule.ruleId === 'PROMPT_OR_SECRET_EXFILTRATION') continue;
      // camelCase schema identifiers are not base64; their decoded surfaces still face every other rule.
      const subject = rule.ruleId === 'ENCODED_BLOB' ? text.replace(IDENTIFIER, ' ') : text;
      if (!surfaces(subject).some(value => rule.patterns.some(pattern => pattern.test(value)))) continue;
      categories.add(rule.category); reasons.add(rule.ruleId);
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
    categories: [...categories].sort(), reasons: [...reasons].sort(),
  };
}
