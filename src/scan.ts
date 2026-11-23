/**
 * Deterministic marketplace moderation (task-safety-policy-v2).
 * Scan requests for abusive actions. Workers run ordinary development tasks
 * in sealed VMs without network access or secrets.
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
  /** Exclude a benign use of the matched phrase and continue scanning. */
  allowContext?: (match: RegExpExecArray) => boolean;
}

// Match affirmative requests. A prohibition in one clause cannot excuse a
// separate request in the same field.
function intent(phrase: RegExp | string): RegExp {
  const source = typeof phrase === "string" ? phrase : phrase.source;
  const prohibition = /(?<!\b(?:not|never|cannot|without|avoid|prevent|don['’]t|can['’]t|mustn['’]t)(?:\s+ever)?\s+)/;
  return new RegExp(String.raw`\b${prohibition.source}(?:${source})\b`, "gi");
}

const transferVerb = /hand\s+over|send|give|provide|paste|share|submit|post|email|upload|reveal|leak|include|attach|forward|dump|exfiltrate|collect|harvest|steal|print/;
const secretNoun = /api\s*keys?|private\s+keys?|ssh\s+keys?|wallet\s+seeds?|(?:seed|recovery)\s+phrases?|mnemonics?|passwords?|(?:access|session|bearer)\s+tokens?|cookies?|\.env(?:\s+files?)?|credentials?/;
const envName = /[A-Z0-9_]*(?:SECRET|TOKEN|PRIVATE_KEY|API_KEY|PASSWORD)[A-Z0-9_]*/;
const codePrefix = /[`'"]?(?:\$\{?)?/;

// Recognize the direct object of the transfer. Free-form intervening words
// would join "submit changes removing hardcoded passwords" into a request
// for passwords. Possessives can name any individual or organization.
const secretModifiers = [
  /me|us|with|a|an|the|all|any|every|each|of|copy|screenshot|contents?|values?|list/,
  /my|our|your|their|his|her|its|own|other|[\w.-]+['’]s?/,
  /raw|actual|real|live|saved|stored|personal|production|prod|master|root|admin/,
  /accounts?|users?|customers?|employees?|victims?|login|browser|database|banking|cloud|wallet/,
  /(?:12|24)[ -]word/,
].map((part) => part.source).join("|");
const serviceName = /(?<service>[a-z][a-z0-9.-]*)/;
const secretPrefix = String.raw`(?:${transferVerb.source})\s+(?:(?:${secretModifiers})\s+){0,6}(?:${serviceName.source}\s+)?${codePrefix.source}`;

function afterMatch(match: RegExpExecArray): string {
  return match.input.slice(match.index + match[0].length);
}

// Only ignore a quoted example with an adjacent teaching or review cue.
// Repeated occurrences are examined independently by firstMatch.
function isQuotedExample(match: RegExpExecArray): boolean {
  const lead = beforeMatch(match);
  const tail = afterMatch(match);
  const delimiter = lead.slice(-1);
  const pairs: Record<string, string> = { "'": "'", '"': '"', "‘": "’", "“": "”" };
  if (!pairs[delimiter] || tail[0] !== pairs[delimiter]) return false;
  const labeled = /\b(?:quoted (?:fixture|example)|literal (?:text|string))\s+$/i.test(lead.slice(0, -1));
  const context = lead + " " + tail.slice(1).split(/[.!?;\n]/, 1)[0].slice(0, 100);
  const educational = /\b(?:regression tests?|test cases?|tutorials?|training|handouts?|documentation)\b/i.test(context);
  if (/\b(?:obey|execute|follow)\s+(?:the|this)\s+quoted (?:example|fixture)\s+['"‘“]$/i.test(lead)) return false;
  return (labeled && educational)
    || /^\s+(?:as an example of (?:a scam|an? (?:unsafe request|override attempt))|is an? (?:unsafe request|override attempt))\b/i.test(tail.slice(1));
}

function isSecretReference(match: RegExpExecArray): boolean {
  const lead = beforeMatch(match);
  if (isQuotedExample(match)) return true;
  // A coordinated prohibition applies only to verbs in the same list.
  if (/\b(?:do not|must not|never)\s+(?:(?:steal|dump|request|expose|read|print|send|share|upload|copy|reveal|leak)\s*,\s*)+(?:(?:or|and)\s+)?$/i.test(lead)) return true;
  if (/\b(?:never|must not|do not)\s+(?:to\s+)?(?:ask|tell)\s+(?:(?:a|an|the|our)\s+)?(?:users?|customers?|employees?)\s+to\s+$/i.test(lead)) return true;
  if (/\b(?:review|audit|check)\b[^.!?;\n]{0,65}\bfor (?:language|wording) that (?:might|could) encourage (?:users|customers) to\s+$/i.test(lead)) return true;
  const service = match.groups?.service;
  if (service) {
    const placeholder = /^(?:mock|dummy|example|sample|fake|test|without|no|not)$/i.test(service);
    if (placeholder || !/^[A-Z]/.test(service)) return true;
  }
  const env = match.groups?.env;
  // Verbs are case-insensitive. Environment identifiers must be all caps.
  if (env && env !== env.toUpperCase()) return true;
  return /^(?:\.(?:example|sample|template)\b|[`'"]?\s+(?:names?|paths?|lengths?|placeholders?|rotation|polic(?:y|ies)|reset|validation|hashing|fields?|formats?|documentation)\b)/i.test(afterMatch(match));
}

const malwareVerb = /build(?:ing)?|writ(?:e|ing)|creat(?:e|ing)|develop(?:ing)?|deploy(?:ing)?|spread(?:ing)?|distribut(?:e|ing)|install(?:ing)?|us(?:e|ing)|launch(?:ing)?|run(?:ning)?|operat(?:e|ing)|make|code|set\s+up/;
const malwareNoun = /malware|ransomware|keyloggers?|spyware|credential[ -]stealers?|credential[ -]harvesting\s+sites?|phishing\s+(?:pages?|kits?|sites?|campaigns?)|botnets?/;
const accessTarget = /auth(?:entication|orization)?|logins?|access\s+controls?|paywalls?|captchas?|robots(?:\.txt)?|security/;
const targetOwner = /a|an|the|their|(?:someone\s+else|[\w.-]+)['’]s/;

const ownSystem = /(?:our|my)\s+(?:own\s+)?(?:(?:local|dev(?:elopment)?|staging|test)\s+){0,2}(?:website|site|app|api|service|server|system|config(?:uration)?|environment|staging|tests?)/;
const testScope = /(?:a\s+|the\s+)?(?:local\s+|unit\s+|integration\s+)?test(?:s|ing)?/;
const localScope = String.raw`(?:on|in|for|during)\s+(?:${ownSystem.source}|${testScope.source}|localhost)\b`;
const localScopeAfter = new RegExp(String.raw`^\s+(?:checks?\s+)?(?:locally\b|${localScope})`, "i");
const localScopeBefore = new RegExp(String.raw`\b${localScope},?\s*$`, "i");

function beforeMatch(match: RegExpExecArray): string {
  // Qualifiers must be adjacent. Bound the lookback on large, repetitive specs.
  return match.input.slice(Math.max(0, match.index - 120), match.index);
}

function isLocalScope(match: RegExpExecArray): boolean {
  const after = afterMatch(match);
  return localScopeAfter.test(after)
    || /^\s+(?:on|in|for)\s+(?:a\s+|the\s+)?(?:site|app|server|system)\s+(?:that\s+)?(?:we|I)\s+own\b/i.test(after)
    || localScopeBefore.test(beforeMatch(match));
}

function isAllowedAccess(match: RegExpExecArray): boolean {
  if (/\b(?:detect|block|prevent|stop)\s+attempts?\s+to\s+$/i.test(beforeMatch(match))) return true;
  const after = afterMatch(match);
  if (/\b(?:their|[\w.-]+['’]s)\s/i.test(match[0])) return false;
  if (/^\s+(?:on|in|for)\s+(?:their|someone\s+else['’]s|[\w-]+\.[\w-]+)\b/i.test(after)) return false;
  const lead = beforeMatch(match);
  if (/^\s+(?:in|on|for)\s+(?:our|my|the)\s+(?:(?:isolated|local|unit|integration|test)\s+){1,4}(?:server|(?:login )?fixture)\b/i.test(after)) return true;
  if (/\b(?:check|test|review)\s+(?:our|my)\b[^.!?;\n]{0,70}\b(?:regression|bug) that (?:might|could) let (?:users|readers)\s+$/i.test(lead)) return true;
  if (/\b(?:our|my)\s+(?:mobile |web )?(?:app|site|client) can\s+$/i.test(lead)
    && /^[^.!?;\n]{0,70}[.!?]\s*(?:fix|close|patch|repair)\s+(?:that|the|this)\b/i.test(after)) return true;
  return /^\s+(?:checks?\s+)?(?:warnings?|tests?|lint(?:ing)?)\b/i.test(after) || isLocalScope(match);
}

function isDefensiveWork(match: RegExpExecArray): boolean {
  if (/fake\s+accounts?$/i.test(match[0])) return isLocalScope(match);
  return /^\s+(?:detect(?:or|ion)s?|filters?|scanners?|removal|simulat(?:or|ion)s?|analysis|prevention|protection|training|awareness|recovery|reports?|incident\s+response)\b/i.test(afterMatch(match));
}

const POLICY_RULES: PolicyRule[] = [
  {
    ruleId: "PROMPT_INJECTION_OVERRIDE",
    severity: "reject",
    category: "prompt_injection",
    categoryBit: 1n << 0n,
    patterns: [
      /ignore\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions/gi,
      /ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:system|developer)\s+instructions/gi,
      /disregard\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions/gi,
      /disregard\s+(?:all\s+)?(?:previous|prior)\s+(?:system|developer)\s+instructions/gi,
      /override\s+(?:the\s+)?(?:policy|instructions|guardrails|system prompt)/gi,
      /you\s+are\s+now\s+(?:in\s+)?developer\s+mode/gi,
      /follow\s+only\s+my\s+instructions/gi,
      intent(/replace\s+(?:your|the)\s+(?:governing|system|developer)\s+instructions\s+with\s+(?:mine|my\s+instructions)/),
      intent(/(?:platform|system|developer)\s+rules\s+no longer apply to you[.!]\s*(?:obey|follow)\b[^.!?;\n]{0,65}\babove all else/),
    ],
    allowContext: isQuotedExample,
  },
  {
    ruleId: "SECRET_EXFILTRATION",
    severity: "reject",
    category: "secrets",
    categoryBit: 1n << 1n,
    patterns: [
      intent(/reveal\s+(?:the\s+)?(?:system|developer|hidden)\s+prompt/),
      intent(String.raw`${secretPrefix}(?:${secretNoun.source})`),
      intent(String.raw`${secretPrefix}(?<env>${envName.source})`),
      // Ambiguous display/copy/export verbs require third-party ownership or a handoff.
      intent(/(?:copy|show|export)\s+(?:the\s+)?(?:seed phrase|ssh key|private key|secret values?|password|bearer token)(?=[^.!?;\n]{0,100}\b(?:from (?:a |an |another )?(?:customer|coworker|employee|stranger)['’]s|(?:send|give|forward) (?:it|them) to (?:me|us)|my handover document)\b)/),
      intent(/(?:want|need)\s+(?:the\s+)?(?:live|actual|production)\s+(?:bearer token|session token|private key|password)\s+from\s+(?:another|someone else['’]s|a coworker['’]s)/),
    ],
    allowContext: isSecretReference,
  },
  {
    ruleId: "ACCESS_BYPASS",
    severity: "reject",
    category: "abuse",
    categoryBit: 1n << 2n,
    patterns: [
      intent(String.raw`(?:bypass|evade|disable)\s+(?:(?:${targetOwner.source})\s+){0,2}(?:${accessTarget.source})`),
      intent(String.raw`(?:bypass|evade|disable)\s+(?:(?:${targetOwner.source})\s+){0,2}(?:rate[ -]limit(?:s|ing)?|(?:ip\s+)?bans?)`),
      intent(/scrape\s+behind\s+(?:(?:a|the|their|someone\s+else['’]s)\s+)?(?:login|paywall)/),
      intent(/remove\s+(?:the\s+)?subscription check\s+on\s+(?:a |an )?(?:publisher|competitor|rival)['’]s\s+(?:site|app)(?=[^.!?;\n]{0,80}\b(?:without (?:permission|paying)|premium (?:articles|content) for free)\b)/),
      intent(/(?:get past|defeat)\s+(?:a|the)\s+(?:members-only\s+)?login(?: requirement)?\s+(?:without permission|on (?:a |an )?(?:third-party|competitor['’]s))/),
    ],
    allowContext: isAllowedAccess,
  },
  {
    ruleId: "CREDENTIAL_THEFT_OR_MALWARE",
    severity: "reject",
    category: "malware",
    categoryBit: 1n << 3n,
    patterns: [
      intent(String.raw`(?:${malwareVerb.source})\s+(?:(?:a|an|the|new|custom|working)\s+){0,3}(?:${malwareNoun.source})`),
      intent(/steal(?:ing)?\s+(?:(?:their|user|users['’]?|other\s+people['’]s)\s+)?(?:credentials?|accounts?)/),
      intent(/(?:send|run|launch|start|organize|create|automate)\s+(?:(?:a|the)\s+)?(?:mass[ -]spam|bulk[ -](?:dms?|direct\s+messages?))(?:\s+campaigns?)?/),
      intent(/(?:create|generate|register|use|buy)\s+(?:(?:a|an|multiple|many|\d[\d,]*k?)\s+)?fake\s+accounts?/),
      intent(/(?:create|build|develop|write)\s+(?:a\s+)?trojan(?=\s+(?:that|to)\s+(?:steals?|records?|spies|spy|encrypts?)\b)/),
      intent(/(?:want|need|pay for)\s+(?:a\s+)?(?:spyware|keylogger|phishing kit)(?=\s+(?:that secretly|whose purpose is (?:stealing|to steal))\b)/),
      intent(/(?:build|create|make)\s+(?:a\s+)?fake login page(?=[^.!?;\n]{0,70}\b(?:trick|steal)\b[^.!?;\n]{0,55}\b(?:passwords?|credentials?)\b)/),
      intent(/(?:run|launch|organize|start)\s+(?:a\s+)?spam campaigns?/),
      intent(/(?:need|want|buy)\s+(?:a\s+)?spam service\s+to flood/),
      intent(/(?:set up|create|buy)\s+(?:a network of\s+)?bot accounts\s+to (?:inflate|manipulate|fake)/),
      intent(/(?:build|buy|create)\s+(?:a network of\s+)?fake reviewers\s+to (?:manipulate|inflate)/),
      intent(/send\s+mass email advertisements(?=[^.!?;\n]{0,100}\b(?:without consent|did not consent|never opted in)\b)/),
      intent(/flood\s+(?:strangers|users|customers)['’]\s+inboxes\s+with\s+(?:my|our)\s+(?:referral|promotional|affiliate)/),
      intent(/(?:run|send|launch)\s+unsolicited bulk (?:messaging|messages|email)/),
    ],
    allowContext: isDefensiveWork,
  },
];

/**
 * Scanner descriptor for THIS service. Versioned distinctly from the storefront
 * (`agenc-moderation-api:scanner:policy-rules:<v>:v1`) and the agenc.ag
 * first-party signer (`agenc-ag-moderation:...:listing-task:v1`) so a verifier
 * can tell which scanner produced an attestation from `scanner_hash` alone.
 */
const TASK_SAFETY_POLICY_VERSION = "task-safety-policy-v2";
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

export interface ModerationReason {
  ruleId: string;
  category: string;
  excerpt: string;
}

export interface ScanResult {
  reasons: ModerationReason[];
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

/** One representative match per rule keeps the response bounded for repeated text. */
function firstMatch(rule: PolicyRule, inputs: SpecTextInput[]): string | undefined {
  for (const { value } of inputs) {
    for (const pattern of rule.patterns) {
      // Global patterns can find a separate instruction after an allowed example.
      const matches = pattern.global ? value.matchAll(pattern) : [pattern.exec(value)];
      for (const match of matches) {
        if (match && !rule.allowContext?.(match)) return match[0];
      }
    }
  }
  return undefined;
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
      reasons: [{ ruleId: "INPUT_TRUNCATED", category: "input_limit", excerpt: "" }],
    };
  }
  let hasReject = false;
  let hasWarning = false;
  let categoryMask = 0n;
  const reasons: ModerationReason[] = [];
  for (const rule of POLICY_RULES) {
    const excerpt = firstMatch(rule, inputs);
    if (excerpt === undefined) continue;
    reasons.push({ ruleId: rule.ruleId, category: rule.category, excerpt: excerpt.slice(0, 80) });
    categoryMask |= rule.categoryBit;
    if (rule.severity === "reject") hasReject = true;
    else if (rule.severity === "warning") hasWarning = true;
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
    reasons,
  };
}
