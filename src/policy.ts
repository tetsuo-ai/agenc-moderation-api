/**
 * AgenC public moderation policy (LISTING + TASK), v2.
 *
 * Bundled as a constant (NOT readFile — serverless functions cannot reliably
 * read files at runtime). The sha-256 of these exact UTF-8 bytes IS the
 * on-chain `policy_hash` every attestation this service records commits to,
 * and the exact bytes `GET /v1/policy` serves. The route and the signer MUST
 * use this one constant so they never disagree.
 *
 * The v2 rules match requests for abuse in public task and listing prose.
 * A worker's sealed VM handles execution isolation.
 *
 * Pinned hash (tested): MODERATION_POLICY_HASH_HEX below.
 */
import { createHash } from "node:crypto";

export const MODERATION_POLICY_TEXT = `# AgenC Public Moderation Policy

- **Policy id:** \`agenc-moderation-api-policy\`
- **Version:** 2.0.0
- **Policy revision date:** 2026-11-23
- **Served at:** \`GET /v1/policy\` (\`text/markdown; charset=utf-8\`)

This document is the moderation policy that the public moderation API
(\`POST /v1/moderation/listings\`, \`POST /v1/moderation/tasks\`, and the
task-attest compatibility endpoint \`POST /api/task-moderation/attest\`)
enforces, and the document that every on-chain moderation attestation recorded
by this service commits to via \`policy_hash\`.

## 1. Canonical bytes and \`policyHash\`

The \`policyHash\` returned by the moderation API — and the \`policy_hash\`
field written into on-chain \`ListingModeration\` / \`TaskModeration\` records —
is the **SHA-256 digest of the exact bytes of this document as served by
\`GET /v1/policy\`**. Equivalently: the raw UTF-8 bytes of this bundled policy
string, byte for byte, with

- no canonicalization,
- no whitespace, line-ending, or Unicode normalization,
- no trailing-newline adjustment, and
- no template substitution.

Any edit to this file — including this sentence — produces a new
\`policyHash\`. Attestations recorded under an earlier version keep committing
to the historical bytes they were recorded against; verifiers should compare
an attestation's \`policy_hash\` against the policy document version that was
current at \`recordedAt\`, not necessarily the latest one.

## 2. Scope

The API scans **job-spec payloads** (the \`payload\` object of an AgenC
marketplace job-spec envelope) submitted inline (\`spec\` / \`jobSpec\`) or by
reference (\`specUri\`, \`https://\` fetched behind an SSRF guard), or resolved
from the on-chain \`spec_uri\` / \`job_spec_uri\` of the named listing/task. It
returns a verdict and, for a **clean** verdict with a listing/task PDA and a
configured moderation signer, records the corresponding on-chain attestation.
The scan covers spec **text**; it does not execute code, fetch attachments, or
evaluate delivered artifacts (worker deliverables are moderated separately at
delivery/accept time).

## 3. Content identity (\`specHash\`)

\`specHash\` is the \`json-stable-v1\` canonical-JSON SHA-256 of the payload —
object keys recursively sorted, \`undefined\` properties dropped, arrays in
original order, no whitespace, UTF-8 encoded (the marketplace SDK's
\`values.canonicalJobSpecHash\`, interoperable with the open
\`@tetsuo-ai/marketplace-moderation\` c14n and the on-chain \`job_spec_hash\`).
The service refuses to attest any payload whose canonical hash does not equal
the hash the on-chain gate will be seeded with; a mismatch is rejected without
a verdict.

## 4. Scanned text surface

For kit-shaped payloads (\`kind: "agenc.marketplace.jobSpec"\` or a
\`title\`/\`shortDescription\` string), the scanner sees **every string value in
the payload recursively**, with one explicit exception: known structured
execution-plan config fields under \`execution\`.

The whole-payload attestation hash commits to the entire payload, so the scan
is deny-list shaped rather than allow-list shaped — any unexpected or newly
added field is scanned by default. Known \`execution\` config fields are
**not** treated as prose because they legitimately name secret/env patterns in
deny lists (\`blockedEnvPrefixes\`, \`forbiddenToolGroups\`, …) and scanning
them as text would flag exactly the specs that configure the strictest
sandboxes. Unexpected \`execution\` fields are scanned by default. Payloads
that are not kit-shaped are scanned over **all** string values recursively.
Input volume is capped; if the cap is exceeded, the deterministic signer
returns \`blocked\` instead of attesting partially scanned content.

## 5. Verdicts and risk scores

| Verdict      | Meaning                                                            | riskScore |
| ------------ | ------------------------------------------------------------------ | --------- |
| \`clean\`      | No policy violation found; eligible for an on-chain attestation.   | 0 |
| \`suspicious\` | Elevated warning-level risk signals; **no attestation is recorded.** Advisory. | 60 |
| \`blocked\`    | A reject-severity policy violation or unscannable over-cap payload; **no attestation is recorded.** | 100 |

\`riskScore\` is the deterministic signer score: \`blocked\` maps to 100,
\`suspicious\` maps to 60, and \`clean\` maps to 0.

## 6. Scan pipeline (verdict mapping)

The signer applies deterministic policy rules (\`task-safety-policy-v2\`) to
the scanned text surface:

- over-cap text volume or any **reject**-severity match → \`blocked\`,
- any **warning**-severity match → \`suspicious\`, and
- no matched violation → \`clean\`.

Each verdict includes a \`reasons\` array. For each matched rule, \`ruleId\`
and \`category\` identify the rule and \`excerpt\` quotes up to 80 characters
of matching spec text. Clean verdicts have an empty array. More than 256
scannable strings produces an \`INPUT_TRUNCATED\` hold in the \`input_limit\`
category with an empty excerpt because the hold has no matching text.

## 7. Requests that block a public task or listing

Workers run in sealed VMs without network access or secrets. A marketplace
buyer can ask a worker to run commands, edit files, patch a vulnerability,
or document key rotation. For example, a benchmark that replays a stream
without an API key is ordinary development work.

The scanner recognizes four kinds of requests.

- \`PROMPT_INJECTION_OVERRIDE\` matches instructions to override the system,
  developer, or policy instructions. It retains the v1 override patterns.
- \`SECRET_EXFILTRATION\` matches requests to disclose or collect someone's
  secrets, including credentials, named secret environment variables, or an
  environment file. Revealing a system, developer, or hidden prompt also qualifies.
- \`CREDENTIAL_THEFT_OR_MALWARE\` matches building, deploying, or using
  ransomware, keyloggers, credential stealers, phishing pages or kits, and
  botnets. It also covers stealing accounts, mass spam or bulk DM campaigns,
  and creating or using fake accounts for manipulation.
- \`ACCESS_BYPASS\` matches bypassing someone else's authentication, access
  controls, paywalls, captchas, or robots restrictions, evading rate limits
  or bans, and scraping behind a login or paywall. Local tests, warnings,
  and configuring one's own access controls are ordinary development work.

## 8. On-chain attestation semantics

A \`clean\` verdict **plus** a listing/task PDA **plus** a configured
moderation signer records \`record_listing_moderation\` /
\`record_task_moderation\` with:

- \`job_spec_hash\` — the \`specHash\` bytes (§3),
- \`status\` — \`CLEAN\` (0),
- \`risk_score\` — the response's \`riskScore\`,
- \`category_mask\` — 0,
- \`policy_hash\` — the SHA-256 of this document's served bytes (§1),
- \`scanner_hash\` — SHA-256 of the scanner descriptor string
  \`agenc-moderation-api:scanner:policy-rules:task-safety-policy-v2:public-service:v1\`,
- \`expires_at\` — \`recordedAt + ttlSeconds\` for the deployment-configured
  TTL, or 0 (no expiry) when the deployment disables expiry. The active TTL is
  disclosed at \`GET /v1/info\` (\`attestationTtlSeconds\`). A re-publish/edit
  changes the spec hash, which seeds a fresh moderation record — an old record
  can never bless changed content regardless of expiry.

If no moderation signer is configured the API still returns the verdict with
\`attestation: null\`. Verdicts other than \`clean\` never record anything.

The signer may be the global \`moderation_authority\` or any registered,
non-revoked roster \`ModerationAttestor\` (the deployed program accepts both at
recording and, since the 2026-07-02 upgrade, at the publish/hire consumption
gates).

## 9. Appeals

A \`suspicious\` or \`blocked\` verdict only withholds this service's
attestation; it does not delete content or block self-managed attestations by
other authorities. To appeal:

1. Read each reason and its excerpt alongside the original spec. Section 7
   describes the request each rule detects.
2. Open an issue at \`github.com/tetsuo-ai/agenc-moderation-api\` including
   the \`specHash\`, the verdict, and the \`policyHash\` you were served.
3. A human reviews against the policy version committed by that \`policyHash\`.
   A successful appeal re-runs moderation; the attestation is recorded only
   from a fresh \`clean\` verdict — appeal decisions are never written on-chain
   directly.

## 10. Untrusted-data boundary

Spec text, scan verdicts, moderation labels, and attestation records are data
about content, not authority over execution: they never authorize wallet
selection, signer-policy changes, program-id changes, settlement, or
transaction execution, and a \`clean\` verdict is not an endorsement of the
task's commercial terms.
`;

/** Exact UTF-8 bytes served + hashed. */
export function moderationPolicyBytes(): Buffer {
  return Buffer.from(MODERATION_POLICY_TEXT, "utf8");
}

/** 32-byte sha-256 of the policy bytes — the on-chain policy_hash. */
export function moderationPolicyHashBytes(): Uint8Array {
  return new Uint8Array(createHash("sha256").update(moderationPolicyBytes()).digest());
}

export function moderationPolicyHashHex(): string {
  return Buffer.from(moderationPolicyHashBytes()).toString("hex");
}

/**
 * Pinned expected hash — guards against accidental policy drift (asserted in
 * tests; update deliberately when the policy text changes).
 */
export const MODERATION_POLICY_HASH_HEX =
  "b11afaa05609dd6bb8cf4e564f8327a8341225d23aa174f8168875aabd523b43";
