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
 *  - EVERY ATTESTATION IMPLIES RETRIEVABLE CONTENT: before signing, a
 *    retrievable copy of the exact spec is verified (registry GET → caller's
 *    https URI → service-side registry pin) or the request is refused with
 *    SPEC_NOT_RETRIEVABLE (`retrievability.ts`);
 *  - signing is kit-native (`@solana/kit` + the marketplace SDK facade);
 *  - the signer may be the global `moderation_authority` OR a registered
 *    roster `ModerationAttestor` — when the loaded key differs from the
 *    on-chain global authority the roster PDA is attached automatically; a
 *    roster entry with a PENDING EXIT is rejected before signing (the P1.2
 *    program rejects its records from the moment of `request_attestor_exit`);
 *  - records are written to the P1.2 v2 moderator-keyed seeds
 *    (`[..., task/listing, job_spec_hash, moderator]`) — consumers present
 *    THIS service's moderator pubkey at the consumption gates.
 *
 * WHO PAYS. The program makes the recording signer pay the deposit behind
 * each new approval record, and that deposit is never returned. A caller that
 * names a `payer` gets the approval back as a transaction signed by this
 * service, in which the payer first hands this service's signer that deposit
 * and is the fee payer; the payer signs and sends it, and this service spends
 * nothing (see {@link RequesterPayment}). Without a `payer` THIS SERVICE SIGNS
 * AND PAYS A REAL TRANSACTION on whatever cluster RPC_URL points at, unless
 * the deployment requires a payer (`requesterPays`), in which case the request
 * is refused. The router's per-IP + global rate limits bound the rest.
 */

import { createHash } from "node:crypto";
import {
  AccountRole,
  address,
  appendTransactionMessageInstructions,
  createKeyPairSignerFromBytes,
  createNoopSigner,
  createSolanaRpc,
  createTransactionMessage,
  getBase64EncodedWireTransaction,
  partiallySignTransactionMessageWithSigners,
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
  fetchMaybeHireRecord,
  fetchMaybeServiceListing,
  fetchMaybeTask,
  fetchMaybeTaskJobSpec,
  fetchMaybeModerationConfig,
  fetchMaybeModerationAttestor,
  findHireRecordPda,
  findTaskJobSpecPda,
  findModerationConfigPda,
  findModerationAttestorPda,
  findListingModerationPda,
  findTaskModerationPda,
  getListingModerationSize,
  getTaskModerationSize,
  values,
} from "@tetsuo-ai/marketplace-sdk";
import { base58Decode, base58Encode } from "./base58.js";
import { fetchJobSpecBody, JobSpecCheckError } from "./ssrf-fetch.js";
import { moderationPolicyHashBytes, moderationPolicyHashHex } from "./policy.js";
import { MODERATION_STATUS, scanPayload, scannerHashBytes, type Verdict } from "./scan.js";
import {
  ModerationRejectError,
  ModerationSignerUnavailableError,
  SpecNotRetrievableError,
} from "./errors.js";
import {
  DEFAULT_JOB_SPEC_REGISTRY_URL,
  ensureSpecRetrievable,
  unwrapPayload,
  type SpecRetrievability,
} from "./retrievability.js";

/* ================================ errors ================================= */

// Defined in errors.ts (shared with the retrievability gate); re-exported here
// to keep the public API surface unchanged.
export { ModerationRejectError, ModerationSignerUnavailableError, SpecNotRetrievableError };

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
  // Revocation (deputized entries) and FINALIZED exits close the roster PDA, so
  // existence == registered. A REQUESTED-but-unfinalized exit still exists on
  // chain, but the program rejects its records (`AttestorExiting`) from the
  // moment of the request — mirror that fail-closed here instead of burning a
  // transaction fee on a doomed record.
  const attestor = await fetchMaybeModerationAttestor(rpc, attestorPda);
  if (attestor.exists) {
    if (attestor.data.exitAt !== 0n) {
      throw new ModerationRejectError(
        503,
        "The configured signer has a pending roster exit (request_attestor_exit); the program rejects its attestations from the moment of the request. Finalize the exit and re-register, or configure a different key.",
      );
    }
    return { moderationAttestor: attestorPda };
  }
  throw new ModerationRejectError(
    503,
    "The configured signer is neither the global moderation authority nor a registered roster ModerationAttestor on this cluster. Self-register it permissionlessly (register_moderation_attestor, refundable bond) or have the moderation authority deputize it (assign_moderation_attestor), or configure the correct key.",
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
  /**
   * Set when the payload was fetched (and hash-verified) from this https URI —
   * retrievability is then proven by construction.
   */
  retrievedFromUri?: string;
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
      if (params.rawText === undefined) {
        throw new ModerationRejectError(
          422,
          `Inline ${params.what} payload is not JSON-canonicalizable (json-stable-v1).`,
        );
      }
    }
    if (canonical?.hex.toLowerCase() === target) {
      return { specHashHex: target, specHashBytes: canonical.bytes, payload };
    }
    // Legacy content-addressed binding: sha256(raw document bytes) == target.
    // CRITICAL: the scanned payload MUST come from those exact bytes, not from
    // the separately-supplied `spec` (which an untrusted caller can make
    // diverge from `rawText`). We therefore RE-PARSE the payload from rawText
    // and scan that — the hash we bind and the content we scan are one source.
    if (params.rawText !== undefined) {
      const rawHex = createHash("sha256")
        .update(Buffer.from(params.rawText, "utf8"))
        .digest("hex");
      if (rawHex === target) {
        const fromText = unwrapPayload(parseSpecDocument(params.rawText));
        return {
          specHashHex: target,
          specHashBytes: values.hexToBytes(target),
          payload: fromText,
        };
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
  const retrievedFromUri = params.specUri.trim();
  const document = parseSpecDocument(text);
  const payload = unwrapPayload(document);

  let canonical: { hex: string; bytes: Uint8Array } | null = null;
  try {
    canonical = await values.canonicalJobSpecHash(payload);
  } catch {
    // Fall through to legacy raw-byte validation below.
  }
  if (canonical?.hex.toLowerCase() === target) {
    return { specHashHex: target, specHashBytes: canonical.bytes, payload, retrievedFromUri };
  }
  if (rawSha256Hex.toLowerCase() === target) {
    return { specHashHex: target, specHashBytes: values.hexToBytes(target), payload, retrievedFromUri };
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
  /**
   * The signer whose on-chain record a consumption gate must name as its
   * P1.2 `moderator` argument. Null in verdict-only mode (no signer).
   */
  moderator: string | null;
  /**
   * Present only on a CLEAN verdict that this service signed + sent itself;
   * null when held, and null when the caller pays (see `payment`).
   */
  attestation: { signature: string; recordedAt: string; expiresAt: string | null } | null;
  /** sha256 of the moderation policy document (hex) the attestation commits to. */
  policyHash: string;
  /**
   * Present only on attested results: a retrievable copy of the exact spec
   * content was verified (or pinned) BEFORE the attestation was recorded.
   */
  retrievable?: true;
  /** Present only on attested results: this service published the spec itself. */
  pinned?: boolean;
  /** Present only on attested results: https URL where the spec is retrievable. */
  specRegistryUri?: string;
  /**
   * Present on a CLEAN verdict when the caller named a `payer`. The approval is
   * NOT recorded yet: the payer signs and sends the transaction in here, and
   * the approval exists once that lands. `attestation` is null in this case;
   * the retrievability fields are present as on an attested result.
   */
  payment?: RequesterPayment;
}

/**
 * A CLEAN approval the requester pays for.
 *
 * One transaction, signed by this service, with the payer as fee payer. It
 * first moves the deposit behind the new approval record from the payer to
 * this service's signer, then records the approval (the program takes that
 * same deposit from the signer). Both happen or neither does, so this service
 * is never out of pocket and a payer never pays for an approval it does not
 * get. Nothing is sent from here.
 */
export interface RequesterPayment {
  /** Base64 wire transaction signed by this service. The payer signs and sends it. */
  transaction: string;
  /** The wallet that pays: the fee payer and the source of the deposit. */
  payer: string;
  /**
   * Lamports the transaction moves from the payer to this service's signer:
   * what the new approval record's deposit takes. "0" (and no transfer in the
   * transaction) when the record already exists and is only being renewed.
   */
  depositLamports: string;
  /** The transaction can land until the chain passes this block height. */
  lastValidBlockHeight: string;
  /** When the approval itself runs out; null when this deployment disables expiry. */
  expiresAt: string | null;
}

const SYSTEM_PROGRAM_ADDRESS = address("11111111111111111111111111111111");
const PAYER_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

/** A System Program transfer, built by hand so no extra package is needed. */
function systemTransfer(from: TransactionSigner, to: Address, lamports: bigint): Instruction {
  const data = new Uint8Array(12);
  const view = new DataView(data.buffer);
  view.setUint32(0, 2, true); // SystemInstruction::Transfer
  view.setBigUint64(4, lamports, true);
  return {
    programAddress: SYSTEM_PROGRAM_ADDRESS,
    accounts: [
      { address: from.address, role: AccountRole.WRITABLE_SIGNER, signer: from } as never,
      { address: to, role: AccountRole.WRITABLE },
    ],
    data,
  };
}

/**
 * Vet the caller-named payer, and refuse a request that names none when this
 * deployment does not pay for approvals. Runs before any chain read, scan or
 * registry write is spent on the request. A deployment with no signer records
 * nothing, so there is nothing to pay for and no payer is asked of it.
 */
function resolvePayer(
  deps: AttestDeps,
  raw: string | undefined,
  moderator: TransactionSigner | null,
): Address | null {
  if (raw === undefined) {
    if (moderator !== null && deps.requesterPays === true) {
      throw new ModerationRejectError(
        402,
        "This service does not pay for approvals. Send the wallet that will pay as `payer`: the answer then carries the approval as a transaction for that wallet to sign and send.",
      );
    }
    return null;
  }
  const trimmed = raw.trim();
  let payer: Address | null = null;
  if (PAYER_RE.test(trimmed)) {
    try {
      payer = address(trimmed);
    } catch {
      payer = null;
    }
  }
  if (payer === null) {
    throw new ModerationRejectError(
      400,
      "payer must be the base58 address of the wallet that will pay for the approval.",
    );
  }
  if (moderator !== null && payer === moderator.address) {
    throw new ModerationRejectError(400, "payer cannot be this service's own signer.");
  }
  return payer;
}

/**
 * What recording into `record` will take from the recording signer.
 *
 * A record that does not exist costs the full deposit. A record this program
 * already owns is reused at no cost. An address somebody sent lamports to
 * first is topped up to the full deposit by the program, so only the shortfall
 * is due. Those lamports cannot leave the address again, so the real cost at
 * send time is never above what is computed here.
 */
async function recordDepositLamports(
  rpc: ReturnType<typeof createSolanaRpc>,
  record: Address,
  recordSpace: number,
): Promise<bigint> {
  const [{ value: account }, rent] = await Promise.all([
    rpc.getAccountInfo(record, { commitment: "confirmed", encoding: "base64" }).send(),
    rpc
      .getMinimumBalanceForRentExemption(BigInt(recordSpace), { commitment: "confirmed" })
      .send(),
  ]);
  const full = BigInt(rent);
  if (account === null) return full;
  if (account.owner !== SYSTEM_PROGRAM_ADDRESS) return 0n;
  const held = BigInt(account.lamports);
  return held >= full ? 0n : full - held;
}

/**
 * Build the requester-paid transaction for a CLEAN approval and sign this
 * service's half of it. Nothing is sent and no SOL leaves this service.
 */
async function prepareRequesterPayment(params: {
  rpcUrl: string;
  instruction: Instruction;
  moderator: TransactionSigner;
  payer: Address;
  /** The approval record the instruction writes. */
  record: Address;
  recordSpace: number;
  expiresAtIso: string | null;
}): Promise<RequesterPayment> {
  const rpc = createSolanaRpc(params.rpcUrl);
  const deposit = await recordDepositLamports(rpc, params.record, params.recordSpace);
  const { value: latestBlockhash } = await rpc
    .getLatestBlockhash({ commitment: "confirmed" })
    .send();
  // The payer signs later, on its own machine: here it is only named.
  const payer = createNoopSigner(params.payer);
  const instructions =
    deposit > 0n
      ? [systemTransfer(payer, params.moderator.address, deposit), params.instruction]
      : [params.instruction];
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayerSigner(payer, m),
    (m) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, m),
    (m) => appendTransactionMessageInstructions(instructions, m),
  );
  const partial = await partiallySignTransactionMessageWithSigners(message);
  if (!(partial.signatures[params.moderator.address] instanceof Uint8Array)) {
    throw new Error("Moderation attestation transaction was not signed.");
  }
  return {
    transaction: getBase64EncodedWireTransaction(partial),
    payer: params.payer,
    depositLamports: deposit.toString(),
    lastValidBlockHeight: latestBlockhash.lastValidBlockHeight.toString(),
    expiresAt: params.expiresAtIso,
  };
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
  /** Job-spec registry base for the retrievability gate (default: official). */
  jobSpecRegistryUrl?: string;
  /** Operator registry write token; wallet upload tickets are used when null. */
  jobSpecRegistryToken?: string | null;
  /**
   * When true this service never pays for an approval: a request that names
   * no `payer` is refused (402). A request that names one is always answered
   * with a transaction for that payer, whatever this is set to. The HTTP
   * service turns this on unless REQUESTER_PAYS says otherwise.
   */
  requesterPays?: boolean;
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
  params: {
    listing: string;
    spec?: Record<string, unknown>;
    specUri?: string;
    /** The wallet that pays for the approval and sends it (see {@link RequesterPayment}). */
    payer?: string;
  },
): Promise<ModerationResult> {
  const moderator = await tryLoadModeratorSigner();
  const payer = resolvePayer(deps, params.payer, moderator);
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
      moderator: moderator?.address ?? null,
      attestation: null,
      policyHash,
    };
  }

  const mode = await resolveSignerMode(rpc, moderator);

  // Every attestation implies retrievable content — fail-closed before signing
  // (after signer-mode validation, so a misconfigured deployment never spends
  // registry writes).
  const retrievability = await ensureSpecRetrievable({
    registryUrl: deps.jobSpecRegistryUrl ?? DEFAULT_JOB_SPEC_REGISTRY_URL,
    registryToken: deps.jobSpecRegistryToken ?? null,
    targetHashHex: resolved.specHashHex,
    payload: resolved.payload,
    candidateUris: [params.specUri, maybe.data.specUri as string],
    resolvedFromUri: resolved.retrievedFromUri,
    moderator,
    what: "listing spec",
  });

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

  if (payer !== null) {
    const [record] = await findListingModerationPda({
      listing: listingAddr,
      jobSpecHash: resolved.specHashBytes,
      moderator: moderator.address,
    });
    return {
      verdict: scan.verdict,
      riskScore: scan.riskScore,
      specHash: resolved.specHashHex,
      moderator: moderator.address,
      attestation: null,
      policyHash,
      ...attestedRetrievabilityFields(retrievability),
      payment: await prepareRequesterPayment({
        rpcUrl: deps.rpcUrl,
        instruction,
        moderator,
        payer,
        record,
        recordSpace: getListingModerationSize(),
        expiresAtIso: ttl.iso,
      }),
    };
  }

  const signature = await signAndSend(deps.rpcUrl, instruction, moderator);
  return {
    verdict: scan.verdict,
    riskScore: scan.riskScore,
    specHash: resolved.specHashHex,
    moderator: moderator.address,
    attestation: { signature, recordedAt: new Date().toISOString(), expiresAt: ttl.iso },
    policyHash,
    ...attestedRetrievabilityFields(retrievability),
  };
}

/** Spread helper: the retrievability fields carried on attested results. */
function attestedRetrievabilityFields(
  retrievability: SpecRetrievability,
): Pick<ModerationResult, "retrievable" | "pinned" | "specRegistryUri"> {
  return {
    retrievable: retrievability.retrievable,
    pinned: retrievability.pinned,
    specRegistryUri: retrievability.specRegistryUri,
  };
}

/**
 * Moderate + (when CLEAN) attest a TASK.
 *
 * PRE-PIN mode (`jobSpecHash` + inline `spec` or `specUri` provided): the
 * caller declares the hash they will pin via `set_task_job_spec`; the payload
 * must hash to it. For listing hires on revision 5+, that hash must also equal
 * the immutable task commitment funded by `hire_from_listing`. This is the
 * flow external marketplaces need — the
 * TaskModeration PDA (P1.2 v2: seeded by task + job_spec_hash + moderator)
 * must exist before the pin's moderation gate will pass, and the pin
 * transaction must present this service's moderator pubkey.
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
    /** The wallet that pays for the approval and sends it (see {@link RequesterPayment}). */
    payer?: string;
  },
): Promise<ModerationResult> {
  const moderator = await tryLoadModeratorSigner();
  const payer = resolvePayer(deps, params.payer, moderator);
  const rpc = createSolanaRpc(deps.rpcUrl);
  const taskAddr = address(params.task);
  let taskAccount: Awaited<ReturnType<typeof fetchMaybeTask>> | null = null;

  // Verdict-only mode records nothing, so the on-chain existence check adds
  // no protection — skip the read for self-contained (pre-pin) requests.
  if (moderator !== null || !(params.spec || params.specUri)) {
    taskAccount = await fetchMaybeTask(rpc, taskAddr);
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

    // A revision-5 listing hire commits its task-specific job-spec hash before
    // funds move. Do not spend registry bandwidth or record an unusable
    // attestation for a caller-substituted hash. Direct tasks have no
    // HireRecord and therefore continue to bind at set_task_job_spec time.
    if (moderator !== null && taskAccount?.exists) {
      const [hireRecordPda] = await findHireRecordPda({ task: taskAddr });
      const hireRecord = await fetchMaybeHireRecord(rpc, hireRecordPda);
      if (hireRecord.exists) {
        if (String(hireRecord.data.task) !== String(taskAddr)) {
          throw new ModerationRejectError(
            422,
            "The canonical HireRecord does not belong to this task; refusing to attest.",
          );
        }
        const description = taskAccount.data.description as Uint8Array;
        if (!(description instanceof Uint8Array) || description.length !== 64) {
          throw new ModerationRejectError(
            422,
            "The hired task has a malformed on-chain commitment; refusing to attest.",
          );
        }
        const fundedHash = description.subarray(32, 64);
        const fundedHashHex = toHex(fundedHash);
        if (fundedHashHex === "0".repeat(64)) {
          throw new ModerationRejectError(
            409,
            "This legacy listing hire has no funded task job-spec commitment. Cancel and re-hire it with a revision-5 client before requesting attestation.",
          );
        }
        if (fundedHashHex !== target) {
          throw new ModerationRejectError(
            422,
            "jobSpecHash does not match the immutable task job-spec commitment funded by hire_from_listing.",
          );
        }
      }
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
      moderator: moderator?.address ?? null,
      attestation: null,
      policyHash,
    };
  }

  const mode = await resolveSignerMode(rpc, moderator);

  // Every attestation implies retrievable content — fail-closed before
  // signing. A CLEAN record for a spec nobody can fetch produces a task
  // workers can claim but never read (the dead-spec incident shape). Runs
  // after signer-mode validation so a misconfigured deployment never spends
  // registry writes.
  const retrievability = await ensureSpecRetrievable({
    registryUrl: deps.jobSpecRegistryUrl ?? DEFAULT_JOB_SPEC_REGISTRY_URL,
    registryToken: deps.jobSpecRegistryToken ?? null,
    targetHashHex: resolved.specHashHex,
    payload: resolved.payload,
    candidateUris: [params.specUri],
    resolvedFromUri: resolved.retrievedFromUri,
    moderator,
    what: "task spec",
  });

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

  if (payer !== null) {
    const [record] = await findTaskModerationPda({
      task: taskAddr,
      jobSpecHash: resolved.specHashBytes,
      moderator: moderator.address,
    });
    return {
      verdict: scan.verdict,
      riskScore: scan.riskScore,
      specHash: resolved.specHashHex,
      moderator: moderator.address,
      attestation: null,
      policyHash,
      ...attestedRetrievabilityFields(retrievability),
      payment: await prepareRequesterPayment({
        rpcUrl: deps.rpcUrl,
        instruction,
        moderator,
        payer,
        record,
        recordSpace: getTaskModerationSize(),
        expiresAtIso: ttl.iso,
      }),
    };
  }

  const signature = await signAndSend(deps.rpcUrl, instruction, moderator);
  return {
    verdict: scan.verdict,
    riskScore: scan.riskScore,
    specHash: resolved.specHashHex,
    moderator: moderator.address,
    attestation: { signature, recordedAt: new Date().toISOString(), expiresAt: ttl.iso },
    policyHash,
    ...attestedRetrievabilityFields(retrievability),
  };
}
