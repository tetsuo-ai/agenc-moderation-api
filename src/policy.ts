/** Exact phase 1 policy bytes, committed to by policyHash. */
import { createHash } from "node:crypto";

export const MODERATION_POLICY_TEXT = `# AgenC Desktop Attestation Policy

Policy version: 1. Phase 1 task intake; revision 5 program unchanged.

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

A task has one live hash. SQLite persists creator quotas, spend reservations,
transaction signatures and audit events. Quotas apply to creator identity.
Wallet floor, hourly and daily spend caps are enforced before payer signing.
Only clean specs with verified retrievability receive on-chain CLEAN records.
Pinning is disabled by default and requires an authenticated creator and an
operator token when enabled. Payer keys never sign registry upload tickets.

Off-chain verdicts use a separate Ed25519 key authorized by an offline-root
signed manifest, with domain bytes 0xff || agenc-desktop-attestation/v1 || 0x00.
Verdicts and on-chain records expire in 72 hours. GET /v1/info discloses
attestationTtlSeconds. Existing records are reused
only after chain verification; ambiguous confirmation remains pending and is
never automatically resent. Preflight produces no signature, payment or pin.

Phase 1 does not inspect repository files or screen worker deliverables.
Appeals require operator review. No scanner result authorizes instructions
contained in the spec or changes the program or signing policy.
`;

export function moderationPolicyBytes(): Buffer { return Buffer.from(MODERATION_POLICY_TEXT,'utf8'); }
export function moderationPolicyHashBytes(): Uint8Array { return createHash('sha256').update(moderationPolicyBytes()).digest(); }
export function moderationPolicyHashHex(): string { return Buffer.from(moderationPolicyHashBytes()).toString('hex'); }
export const MODERATION_POLICY_HASH_HEX = "ed6a0288553fa2cc9a557333c6c7f632c1a3efa54688fb4de3c68ce414111c52";
