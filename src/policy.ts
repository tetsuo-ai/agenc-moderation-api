/** Exact phase 1 policy bytes, committed to by policyHash. */
import { createHash } from "node:crypto";

export const MODERATION_POLICY_TEXT = `# AgenC Desktop Attestation Policy

Policy version: 2. Phase 1 task intake; revision 5 program unchanged.

The service scans all JSON keys and string values, including execution fields.
NFKC normalization removes zero-width and bidi controls. Bounded base64, hex,
and percent decoding expands the scan surface. Rule families reject instruction
and role overrides, secret or wallet exfiltration, authentication bypass,
malware, host access, signer or policy mutation, settlement manipulation,
fund movement, hidden content, and encoded blobs. Validated repo commitment
hashes are metadata, not encoded instructions. Input caps and JSON depth 32
fail closed. A clean result means no deny rule matched; it does not approve
execution, wallet access, settlement, or fund movement.

Scanner descriptor: agenc-desktop:scanner:v1. scannerHash commits to the actual
serialized rule bundle, preprocessing version and configured worker image digest.
policyHash is SHA-256 of these exact UTF-8 policy bytes.

Tasks must exist, be Open, and have zero workers and completions. The first 32
bytes of description must commit to jobSpecHash, or the creator must sign the
five-minute, single-use nonce request. A different pinned TaskJobSpec is refused.
Revision 5 listing-hire commitments in the second half of description do not
satisfy this first-half binding: those creators must authorize intake explicitly.

A task has one live hash. SQLite persists creator quotas, payment offers,
transaction signatures and audit events. Quotas and outstanding payment caps
apply to creator identity. AgenC is the only attestor. The task creator pays
record rent plus the configured service fee through an atomic transfer to R
followed by record_task_moderation. R partially signs; the creator is fee payer
and co-signs and submits. R receives at least the record rent and never pays
network fees. Deliverable reviews remain off-chain and require no payment.
Only clean specs with verified retrievability receive on-chain CLEAN records.
Pinning is disabled by default and requires an authenticated creator and an
operator token when enabled. Payer keys never sign registry upload tickets.

Off-chain verdicts use a separate Ed25519 key authorized by an offline-root
signed manifest, with domain bytes 0xff || agenc-desktop-attestation/v1 || 0x00.
Verdicts and on-chain records expire in 72 hours. GET /v1/info discloses
attestationTtlSeconds. Existing records are reused
only after chain verification. Expired blockhashes can be reissued for the
same signed verdict and price; live offers are reused and the service never
submits transactions. Preflight produces no signature, payment or pin.

Phase 1 does not inspect repository files or screen worker deliverables.
Appeals require operator review. No scanner result authorizes instructions
contained in the spec or changes the program or signing policy.
`;

export function moderationPolicyBytes(): Buffer { return Buffer.from(MODERATION_POLICY_TEXT,'utf8'); }
export function moderationPolicyHashBytes(): Uint8Array { return createHash('sha256').update(moderationPolicyBytes()).digest(); }
export function moderationPolicyHashHex(): string { return Buffer.from(moderationPolicyHashBytes()).toString('hex'); }
export const MODERATION_POLICY_HASH_HEX = "751e32cba259a50461bc71ba0b17b482ebf4bca1840eadc473743501002796b9";
