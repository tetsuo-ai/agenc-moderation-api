/**
 * Attestation core: fail-closed moderation signer.
 *
 * Ported from the agenc.ag first-party signer
 * (`agenc-ag/apps/web/lib/server/moderation-signer.ts`) and generalized for a
 * standalone public service:
 *
 *  - the on-chain spec hash (ServiceListing.spec_hash / TaskJobSpec
 *    .job_spec_hash / the caller-declared pre-pin hash) is re-derived from the
 *    actual payload and MUST equal it, else we reject WITHOUT signing (a hash
 *    mismatch means the moderation PDA seed would not match what the
 *    publish/hire gate checks);
 *  - remote specs are fetched only through the SSRF-guarded pinned-address
 *    fetcher (`ssrf-fetch.ts`);
 *  - only CLEAN (status 0) is ever recorded; blocked/suspicious verdicts are
 *    HELD (returned without a signature);
 *  - signing is kit-native (`@solana/kit` + the marketplace SDK facade);
 *  - the signer may be the global `moderation_authority` OR a registered
 *    roster `ModerationAttestor` — when the loaded key differs from the
 *    on-chain global authority the roster PDA is attached automatically.
 *
 * THIS SERVICE SIGNS AND PAYS REAL TRANSACTIONS on whatever cluster RPC_URL
 * points at. The router's per-IP + global rate limits are the economic bound.
 */

import { createHash } from "node:crypto";
import {
  address,
  appendTransactionMessageInstructions,
  createKeyPairSignerFromBytes,
  createSolanaRpc,
  createTransactionMessage,
  getBase64EncodedWireTransaction,
  pipe,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  signature as solanaSignature,
  type Address,
  type Instruction,
  type TransactionSigner,
} from "@solana/kit";
import {
  facade,
  fetchMaybeServiceListing,
  fetchMaybeTask,
  fetchMaybeTaskJobSpec,
  fetchMaybeModerationConfig,
  fetchMaybeModerationAttestor,
  findTaskJobSpecPda,
  findModerationConfigPda,
  findModerationAttestorPda,
  values,
} from "@tetsuo-ai/marketplace-sdk";
import { base58Decode, base58Encode } from "./base58.js";
import { fetchJobSpecBody, JobSpecCheckError } from "./ssrf-fetch.js";
import { moderationPolicyHashBytes, moderationPolicyHashHex } from "./policy.js";
import { MODERATION_STATUS, scanPayload, scannerHashBytes, type Verdict } from "./scan.js";

/* ================================ errors ================================= */

/** Thrown when the moderation signer secret is unset/invalid (callers → 503). */
export class ModerationSignerUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ModerationSignerUnavailableError";
  }
}

/** Thrown when the request is well-formed but the spec can't be honestly attested (callers → 4xx). */
export class ModerationRejectError extends Error {
  constructor(
    public readonly httpStatus: number,
    message: string,
  ) {
    super(message);
    this.name = "ModerationRejectError";
  }
}

/* ============================== signer key =============================== */

/**
 * Parse the signer secret. Accepts either a base58 string (64-byte secret key)
 * OR a JSON `[n,...]` 64-byte array (the Solana keypair-file format). NEVER
 * logs the key or its parse error detail.
 */
function decodeSecretKeyBytes(raw: string): Uint8Array {
  const trimmed = raw.trim();
  if (trimmed.startsWith("[")) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      throw new ModerationSignerUnavailableError(
        "MODERATION_SIGNER_SECRET is a malformed JSON byte array.",
      );
    }
    if (
      !Array.isArray(parsed) ||
      parsed.length !== 64 ||
      !parsed.every((n) => typeof n === "number" && Number.isInteger(n) && n >= 0 && n <= 255)
    ) {
      throw new ModerationSignerUnavailableError(
        "MODERATION_SIGNER_SECRET JSON array must be exactly 64 byte values (0-255).",
      );
    }
    return Uint8Array.from(parsed as number[]);
  }
  let bytes: Uint8Array;
  try {
    bytes = base58Decode(trimmed);
  } catch {
    throw new ModerationSignerUnavailableError(
      "MODERATION_SIGNER_SECRET is not valid base58 or a 64-byte JSON array.",
    );
  }
  if (bytes.length !== 64) {
    throw new ModerationSignerUnavailableError(
      "MODERATION_SIGNER_SECRET base58 must decode to a 64-byte secret key.",
    );
  }
  return bytes;
}

/**
 * Load the moderation signer from `MODERATION_SIGNER_SECRET` (compatibility
 * fallback: `MODERATION_AUTHORITY_SECRET`, the agenc.ag env name). Throws
 * {@link ModerationSignerUnavailableError} (→ 503) when unset/invalid. NEVER
 * logs the key.
 */
export async function loadModeratorSigner(): Promise<TransactionSigner> {
  const raw =
    process.env.MODERATION_SIGNER_SECRET ?? process.env.MODERATION_AUTHORITY_SECRET;
  if (!raw || !raw.trim()) {
    throw new ModerationSignerUnavailableError(
      "MODERATION_SIGNER_SECRET is not configured; the moderation signer is unavailable.",
    );
  }
  const secretBytes = decodeSecretKeyBytes(raw);
  try {
    return await createKeyPairSignerFromBytes(secretBytes);
  } catch {
    throw new ModerationSignerUnavailableError(
      "MODERATION_SIGNER_SECRET could not be loaded as a Solana keypair.",
    );
  }
}

/**
 * Verdict-only seam: `null` when NO key is configured at all (the service
 * scans and reports but records nothing — disclosed at /v1/info). A key that
 * is PRESENT but malformed still throws (a deployment that intended to sign
 * must fail loudly, not silently degrade).
 */
export async function tryLoadModeratorSigner(): Promise<TransactionSigner | null> {
  const raw =
    process.env.MODERATION_SIGNER_SECRET ?? process.env.MODERATION_AUTHORITY_SECRET;
  if (!raw || !raw.trim()) return null;
  return loadModeratorSigner();
}

/* ====================== roster-attestor auto-detection =================== */

interface SignerMode {
  /** The roster PDA to attach, or null when signing as the global authority. */
  moderationAttestor: Address | null;
}

/**
 * Decide how the loaded signer is authorized: as the on-chain global
 * `moderation_authority` (no extra account) or as a roster `ModerationAttestor`
 * (attach its non-revoked assignment PDA). Fail-closed: a signer that is
 * NEITHER is rejected before any scan work, with a message telling the
 * self-hoster exactly what registration they need.
 */
async function resolveSignerMode(
  rpc: ReturnType<typeof createSolanaRpc>,
  moderator: TransactionSigner,
): Promise<SignerMode> {
  const [configPda] = await findModerationConfigPda();
  const config = await fetchMaybeModerationConfig(rpc, configPda);
  if (!config.exists) {
    throw new ModerationRejectError(
      503,
      "ModerationConfig is not initialized on this cluster; nothing can consume attestations here.",
    );
  }
  if (config.data.moderationAuthority === moderator.address) {
    return { moderationAttestor: null };
  }
  const [attestorPda] = await findModerationAttestorPda({ attestor: moderator.address });
  // Revocation CLOSES the assignment PDA (revoke_moderation_attestor), so
  // existence == registered and non-revoked.
  const attestor = await fetchMaybeModerationAttestor(rpc, attestorPda);
  if (attestor.exists) {
    return { moderationAttestor: attestorPda };
  }
  throw new ModerationRejectError(
    503,
    "The configured signer is neither the global moderation authority nor a registered, non-revoked roster ModerationAttestor on this cluster. Ask the moderation authority to register it (assign_moderation_attestor) or configure the correct key.",
  );
}

/* ============================ spec resolution ============================ */

/** Lowercase hex of a 32-byte array. */
function toHex(bytes: Uint8Array | ReadonlyArray<number>): string {
  return values.bytesToHex(bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes));
}

export interface ResolvedSpec {
  /** The spec hash the gate will be seeded with, hex. */
  specHashHex: string;
  /** The same hash as 32 raw bytes (the `jobSpecHash` instruction arg). */
  specHashBytes: Uint8Array;
  /** The parsed payload that was scanned. */
  payload: Record<string, unknown>;
}

/** Fetch a remote spec body behind the SSRF guard, mapping errors to a typed reject. */
async function fetchSpecBody(specUri: string): Promise<{ text: string; rawSha256Hex: string }> {
  if (typeof specUri !== "string" || !/^https:\/\//i.test(specUri.trim())) {
    throw new ModerationRejectError(422, "Spec URI is not an https URL the signer can fetch.");
  }
  try {
    const body = await fetchJobSpecBody(specUri.trim());
    return { text: body.text, rawSha256Hex: body.sha256 };
  } catch (error) {
    if (error instanceof JobSpecCheckError) {
      throw new ModerationRejectError(502, `Could not fetch the hosted spec: ${error.message}.`);
    }
    throw error;
  }
}

/** Parse a fetched spec body to a JSON object, mapping errors to a typed reject. */
function parseSpecDocument(text: string): Record<string, unknown> {
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch {
    throw new ModerationRejectError(422, "Hosted spec is not valid JSON.");
  }
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    throw new ModerationRejectError(422, "Hosted spec must be a JSON object.");
  }
  return document as Record<string, unknown>;
}

/** Unwrap a job-spec envelope to its payload; a bare payload passes through. */
function unwrapPayload(document: Record<string, unknown>): Record<string, unknown> {
  const inner = document.payload;
  return inner && typeof inner === "object" && !Array.isArray(inner)
    ? (inner as Record<string, unknown>)
    : document;
}

/**
 * Resolve a spec against a REQUIRED target hash from an inline payload or a
 * remote URI. Fail-closed: the canonical `json-stable-v1` payload hash (or,
 * legacy, the raw served bytes' sha-256 for URI specs) MUST equal the target
 * hash or we refuse to attest — the moderation PDA the gate derives is seeded
 * by that hash, so attesting a non-matching payload would bless content the
 * gate never checks.
 */
export async function resolveSpecAgainstHash(params: {
  targetHashHex: string;
  spec?: Record<string, unknown> | undefined;
  specUri?: string | undefined;
  /**
   * The exact raw text the payload was parsed from, when the caller submitted
   * text (compat endpoint). Supports the legacy content-addressed binding:
   * sha256(raw bytes) == target, mirroring the URI path's raw-byte acceptance.
   */
  rawText?: string | undefined;
  /** What to call the mismatch in errors ("listing spec" / "task spec"). */
  what: string;
}): Promise<ResolvedSpec> {
  const target = params.targetHashHex.toLowerCase();
  if (params.spec) {
    const payload = unwrapPayload(params.spec);
    let canonical: { hex: string; bytes: Uint8Array } | null = null;
    try {
      canonical = await values.canonicalJobSpecHash(payload);
    } catch {
      if (!params.rawText) {
        throw new ModerationRejectError(
          422,
          `Inline ${params.what} payload is not JSON-canonicalizable (json-stable-v1).`,
        );
      }
    }
    if (canonical?.hex.toLowerCase() === target) {
      return { specHashHex: target, specHashBytes: canonical.bytes, payload };
    }
    if (params.rawText !== undefined) {
      const rawHex = createHash("sha256")
        .update(Buffer.from(params.rawText, "utf8"))
        .digest("hex");
      if (rawHex === target) {
        return { specHashHex: target, specHashBytes: values.hexToBytes(target), payload };
      }
    }
    throw new ModerationRejectError(
      422,
      `Inline ${params.what} payload does not hash to the expected spec hash; refusing to attest a non-matching spec.`,
    );
  }

  if (!params.specUri) {
    throw new ModerationRejectError(400, `Provide the ${params.what} inline (spec) or by URI (specUri).`);
  }
  const { text, rawSha256Hex } = await fetchSpecBody(params.specUri);
  const document = parseSpecDocument(text);
  const payload = unwrapPayload(document);

  let canonical: { hex: string; bytes: Uint8Array } | null = null;
  try {
    canonical = await values.canonicalJobSpecHash(payload);
  } catch {
    // Fall through to legacy raw-byte validation below.
  }
  if (canonical?.hex.toLowerCase() === target) {
    return { specHashHex: target, specHashBytes: canonical.bytes, payload };
  }
  if (rawSha256Hex.toLowerCase() === target) {
    return { specHashHex: target, specHashBytes: values.hexToBytes(target), payload };
  }
  throw new ModerationRejectError(
    422,
    `Hosted ${params.what} payload or bytes do not hash to the expected spec hash; refusing to attest a non-matching spec.`,
  );
}

/* ============================== attest core ============================== */

/** The response shape (SDK `ListingModerationResult` / `TaskModerationResult`). */
export interface ModerationResult {
  verdict: Verdict;
  riskScore: number;
  /** Canonical spec hash (hex) — equals the on-chain spec_hash. */
  specHash: string;
  /** Present only on a CLEAN verdict that was signed + sent; null when held. */
  attestation: { signature: string; recordedAt: string; expiresAt: string | null } | null;
  /** sha256 of the moderation policy document (hex) the attestation commits to. */
  policyHash: string;
}

function firstTransactionSignatureBase58(signed: {
  signatures: Readonly<Record<string, Uint8Array | null>>;
}): string {
  const sig = Object.values(signed.signatures).find(
    (value): value is Uint8Array => value instanceof Uint8Array,
  );
  if (!sig) throw new Error("Moderation attestation transaction was not signed.");
  return base58Encode(sig);
}

/**
 * Build + sign + send one moderation attestation transaction. The moderator is
 * the fee payer + the only signer. Returns the confirmed signature.
 */
async function signAndSend(
  rpcUrl: string,
  instruction: Instruction,
  moderator: TransactionSigner,
): Promise<string> {
  const rpc = createSolanaRpc(rpcUrl);
  const { value: latestBlockhash } = await rpc
    .getLatestBlockhash({ commitment: "confirmed" })
    .send();
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayerSigner(moderator, m),
    (m) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, m),
    (m) => appendTransactionMessageInstructions([instruction], m),
  );
  const signed = await signTransactionMessageWithSigners(message);
  const sig = firstTransactionSignatureBase58(signed);
  const rpcSignature = solanaSignature(sig);
  const wire = getBase64EncodedWireTransaction(signed);
  await rpc
    .sendTransaction(wire, { encoding: "base64", preflightCommitment: "confirmed" })
    .send();

  const deadline = Date.now() + 90_000;
  for (;;) {
    const { value } = await rpc.getSignatureStatuses([rpcSignature]).send();
    const status = value[0];
    if (status) {
      if (status.err != null) {
        throw new Error(`Moderation attestation failed on-chain (signature ${sig}).`);
      }
      if (status.confirmationStatus === "confirmed" || status.confirmationStatus === "finalized") {
        return sig;
      }
    }
    if (Date.now() >= deadline) {
      throw new Error(
        `Moderation attestation confirmation timed out (signature ${sig}). It may still land.`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 1_500));
  }
}

/** Compute the on-chain `expires_at` (unix secs) for the configured TTL. */
function expiresAt(ttlSeconds: number): { onChain: bigint; iso: string | null } {
  if (!ttlSeconds || ttlSeconds <= 0) return { onChain: 0n, iso: null };
  const at = Math.floor(Date.now() / 1000) + ttlSeconds;
  return { onChain: BigInt(at), iso: new Date(at * 1000).toISOString() };
}

export interface AttestDeps {
  rpcUrl: string;
  attestationTtlSeconds: number;
}

/**
 * Moderate + (when CLEAN) attest a LISTING. Reads the on-chain ServiceListing
 * for its spec_hash (+ spec_uri fallback), resolves the payload (inline > URI
 * param > on-chain spec_uri), fail-closed hash-matches it, scans, and on a
 * clean verdict records `record_listing_moderation`. A blocked/suspicious
 * verdict is HELD (no signature).
 */
export async function attestListing(
  deps: AttestDeps,
  params: { listing: string; spec?: Record<string, unknown>; specUri?: string },
): Promise<ModerationResult> {
  const moderator = await tryLoadModeratorSigner();
  const rpc = createSolanaRpc(deps.rpcUrl);
  const listingAddr = address(params.listing);

  const maybe = await fetchMaybeServiceListing(rpc, listingAddr);
  if (!maybe.exists) {
    throw new ModerationRejectError(404, "This listing does not exist on-chain.");
  }
  const onChainSpecHashHex = toHex(maybe.data.specHash as Uint8Array);
  const resolved = await resolveSpecAgainstHash({
    targetHashHex: onChainSpecHashHex,
    spec: params.spec,
    specUri: params.specUri ?? (maybe.data.specUri as string),
    what: "listing spec",
  });
  const scan = scanPayload(resolved.payload);

  const policyHash = moderationPolicyHashHex();
  if (scan.verdict !== "clean" || moderator === null) {
    // Held verdict, or verdict-only mode (no signer configured — disclosed at /v1/info).
    return {
      verdict: scan.verdict,
      riskScore: scan.riskScore,
      specHash: resolved.specHashHex,
      attestation: null,
      policyHash,
    };
  }

  const mode = await resolveSignerMode(rpc, moderator);
  const ttl = expiresAt(deps.attestationTtlSeconds);
  const instruction = (await facade.recordListingModeration({
    listing: listingAddr,
    moderator,
    ...(mode.moderationAttestor ? { moderationAttestor: mode.moderationAttestor } : {}),
    jobSpecHash: resolved.specHashBytes,
    status: MODERATION_STATUS.CLEAN,
    riskScore: scan.riskScore,
    categoryMask: scan.categoryMask,
    policyHash: moderationPolicyHashBytes(),
    scannerHash: scannerHashBytes(),
    expiresAt: ttl.onChain,
  })) as Instruction;

  const signature = await signAndSend(deps.rpcUrl, instruction, moderator);
  return {
    verdict: scan.verdict,
    riskScore: scan.riskScore,
    specHash: resolved.specHashHex,
    attestation: { signature, recordedAt: new Date().toISOString(), expiresAt: ttl.iso },
    policyHash,
  };
}

/**
 * Moderate + (when CLEAN) attest a TASK.
 *
 * PRE-PIN mode (`jobSpecHash` + inline `spec` or `specUri` provided): the
 * caller declares the hash they will pin via `set_task_job_spec`; the payload
 * must hash to it. This is the flow external marketplaces need — the
 * TaskModeration PDA (seeded by task + job_spec_hash) must exist before the
 * pin's moderation gate will pass.
 *
 * POST-PIN mode (neither provided): reads the pinned TaskJobSpec PDA
 * (job_spec_hash + job_spec_uri) like the first-party signer.
 */
export async function attestTask(
  deps: AttestDeps,
  params: {
    task: string;
    jobSpecHash?: string;
    spec?: Record<string, unknown>;
    specUri?: string;
    /** Raw submitted text for the legacy content-addressed binding (compat endpoint). */
    rawText?: string;
  },
): Promise<ModerationResult> {
  const moderator = await tryLoadModeratorSigner();
  const rpc = createSolanaRpc(deps.rpcUrl);
  const taskAddr = address(params.task);

  // Verdict-only mode records nothing, so the on-chain existence check adds
  // no protection — skip the read for self-contained (pre-pin) requests.
  if (moderator !== null || !(params.spec || params.specUri)) {
    const taskAccount = await fetchMaybeTask(rpc, taskAddr);
    if (!taskAccount.exists) {
      throw new ModerationRejectError(404, "This task does not exist on-chain.");
    }
  }

  let resolved: ResolvedSpec;
  if (params.jobSpecHash || params.spec || params.specUri) {
    // PRE-PIN: the target hash comes from the caller. When only a spec is
    // given, its canonical hash IS the target (self-declared, still exact —
    // the gate seeds from whatever the creator later pins, and the creator's
    // client refuses to pin a hash without a matching attestation).
    let target = params.jobSpecHash?.trim().toLowerCase() ?? "";
    if (!target) {
      if (!params.spec) {
        throw new ModerationRejectError(
          400,
          "Pre-pin task moderation needs jobSpecHash (with spec or specUri), or an inline spec.",
        );
      }
      try {
        target = (await values.canonicalJobSpecHash(unwrapPayload(params.spec))).hex;
      } catch {
        throw new ModerationRejectError(
          422,
          "Inline task spec payload is not JSON-canonicalizable (json-stable-v1).",
        );
      }
    }
    if (!/^[0-9a-f]{64}$/.test(target)) {
      throw new ModerationRejectError(400, "jobSpecHash must be 64 lowercase hex chars.");
    }
    resolved = await resolveSpecAgainstHash({
      targetHashHex: target,
      spec: params.spec,
      specUri: params.specUri,
      rawText: params.rawText,
      what: "task spec",
    });
  } else {
    const [jobSpecPda] = await findTaskJobSpecPda({ task: taskAddr });
    const jobSpec = await fetchMaybeTaskJobSpec(rpc, jobSpecPda);
    if (!jobSpec.exists) {
      throw new ModerationRejectError(
        409,
        "This task has no job spec pinned yet and no spec was provided — nothing to moderate. Provide jobSpecHash + spec/specUri (pre-pin) or pin the job spec first.",
      );
    }
    resolved = await resolveSpecAgainstHash({
      targetHashHex: toHex(jobSpec.data.jobSpecHash as Uint8Array),
      specUri: jobSpec.data.jobSpecUri as string,
      what: "task spec",
    });
  }

  const scan = scanPayload(resolved.payload);
  const policyHash = moderationPolicyHashHex();
  if (scan.verdict !== "clean" || moderator === null) {
    // Held verdict, or verdict-only mode (no signer configured — disclosed at /v1/info).
    return {
      verdict: scan.verdict,
      riskScore: scan.riskScore,
      specHash: resolved.specHashHex,
      attestation: null,
      policyHash,
    };
  }

  const mode = await resolveSignerMode(rpc, moderator);
  const ttl = expiresAt(deps.attestationTtlSeconds);
  const instruction = (await facade.recordTaskModeration({
    task: taskAddr,
    moderator,
    ...(mode.moderationAttestor ? { moderationAttestor: mode.moderationAttestor } : {}),
    jobSpecHash: resolved.specHashBytes,
    status: MODERATION_STATUS.CLEAN,
    riskScore: scan.riskScore,
    categoryMask: scan.categoryMask,
    policyHash: moderationPolicyHashBytes(),
    scannerHash: scannerHashBytes(),
    expiresAt: ttl.onChain,
  })) as Instruction;

  const signature = await signAndSend(deps.rpcUrl, instruction, moderator);
  return {
    verdict: scan.verdict,
    riskScore: scan.riskScore,
    specHash: resolved.specHashHex,
    attestation: { signature, recordedAt: new Date().toISOString(), expiresAt: ttl.iso },
    policyHash,
  };
}
