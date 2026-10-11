import { scannerHash as repositoryScannerHash } from '../worker/rules.js';
import { validateJob, type GithubSpec } from '../worker/types.js';
import type { GithubClient } from '../worker/github.js';
import { assertJsonDepth } from './json-depth.js';
/** Creator-bound revision 5 task intake. All network boundaries are mockable in tests. */

import { readFileSync } from "node:fs";
import { bindRequester, type CreatorAuthorization } from "./binding.js";
import { getStore, DEFAULT_SPEND_LIMITS, type AttestationStore, type SpendLimits } from "./store.js";
import { authorizedVerdictKey, signDocument, type SignedDocument } from "./verdict.js";
import { createHash, randomBytes } from "node:crypto";
import {
  address,
  compileTransaction,
  getBase64Decoder,
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
  type TransactionMessageBytesBase64,
  type Instruction,
  type TransactionSigner,
} from "@solana/kit";
import {
  facade,
  AGENC_COORDINATION_PROGRAM_ADDRESS,
  fetchMaybeTaskModeration,
  findTaskModerationPda,
  getTaskModerationSize,
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
import { scanPayload, scannerHashBytes, scannerHashHex, type Verdict } from "./scan.js";
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
 * Load R from MODERATION_SIGNER_SECRET_FILE (systemd credentials). Development
 * alone permits legacy environment secrets. Throws
 * {@link ModerationSignerUnavailableError} (→ 503) when unset/invalid. NEVER
 * logs the key.
 */
export async function loadModeratorSigner(): Promise<TransactionSigner> {
  if (process.env.NODE_ENV === 'production' && (process.env.MODERATION_SIGNER_SECRET || process.env.MODERATION_AUTHORITY_SECRET)) throw new ModerationSignerUnavailableError('Environment secrets forbidden in production.');
  const raw = process.env.MODERATION_SIGNER_SECRET_FILE ? readFileSync(process.env.MODERATION_SIGNER_SECRET_FILE,'utf8') :
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
  if (process.env.NODE_ENV === 'production' && (process.env.MODERATION_SIGNER_SECRET || process.env.MODERATION_AUTHORITY_SECRET)) throw new ModerationSignerUnavailableError('Environment secrets forbidden in production.');
  const raw = process.env.MODERATION_SIGNER_SECRET_FILE ? readFileSync(process.env.MODERATION_SIGNER_SECRET_FILE,'utf8') :
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
  assertJsonDepth(document);
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
    assertJsonDepth(params.spec);
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
  /** Present only on a CLEAN verdict that was signed + sent; null when held. */
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
  pending?: boolean;
  jobId?: string;
  retryAfterSeconds?: number;
  preflightOnly?: boolean;
  wouldAttest?: boolean;
  signedVerdict?: SignedDocument;
  recordPda?: string;
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
export async function signAndSend(
  rpcUrl: string, instruction: Instruction, moderator: TransactionSigner,
  journal: {store: AttestationStore; task: string; reserve: (cost: number,balance: number)=>void},
): Promise<{signature: string; pending: boolean}> {
  const rpc = createSolanaRpc(rpcUrl);
  const { value: latestBlockhash } = await rpc.getLatestBlockhash({commitment:'confirmed'}).send();
  const computeProgram = address('ComputeBudget111111111111111111111111111111');
  const limit = Buffer.alloc(5); limit[0]=2; limit.writeUInt32LE(200_000,1);
  const fee = Buffer.alloc(9); fee[0]=3; fee.writeBigUInt64LE(1_000n,1);
  const message = pipe(createTransactionMessage({version:0}),
    m=>setTransactionMessageFeePayerSigner(moderator,m),
    m=>setTransactionMessageLifetimeUsingBlockhash(latestBlockhash,m),
    m=>appendTransactionMessageInstructions([{programAddress:computeProgram,data:limit},{programAddress:computeProgram,data:fee},instruction],m));
  if(!journal) throw new ModerationRejectError(503,'Durable spend journal required.');
  {
    const encoded = getBase64Decoder().decode(compileTransaction(message).messageBytes);
    const {value: networkFee} = await rpc.getFeeForMessage(encoded as TransactionMessageBytesBase64,{commitment:'confirmed'}).send();
    if(networkFee === null || networkFee < 0n || networkFee > 100_000n) throw new ModerationRejectError(503,'Fee exceeds bound.');
    const rent = await rpc.getMinimumBalanceForRentExemption(BigInt(getTaskModerationSize())).send();
    const {value:balance} = await rpc.getBalance(moderator.address,{commitment:'confirmed'}).send();
    const cost = Number(rent+networkFee);
    if(!Number.isSafeInteger(cost) || !Number.isSafeInteger(Number(balance))) throw new ModerationRejectError(503,'Invalid balance.');
    journal.reserve(cost,Number(balance));
  }
  const signed = await signTransactionMessageWithSigners(message);
  const signature = firstTransactionSignatureBase58(signed);
  // Journal BEFORE submission: errors after submission are ambiguous, never resend.
  journal.store.submitted(journal.task,signature);
  try {
    await rpc.sendTransaction(getBase64EncodedWireTransaction(signed),{encoding:'base64',preflightCommitment:'confirmed',maxRetries:0n}).send();
  } catch { return {signature,pending:true}; }
  const deadline = Date.now()+Number(process.env.CONFIRMATION_TIMEOUT_MS ?? 90_000);
  for (;;) {
    try {
      const {value} = await rpc.getSignatureStatuses([solanaSignature(signature)],{searchTransactionHistory:true}).send();
      const status = value[0];
      if(status?.err != null) { journal.store.audit('chain-failed',{task:journal.task,signature}); throw new ModerationRejectError(502,'Transaction failed.'); }
      if(status?.confirmationStatus === 'confirmed' || status?.confirmationStatus === 'finalized') return {signature,pending:false};
      if(await rpc.getBlockHeight({commitment:'confirmed'}).send() > latestBlockhash.lastValidBlockHeight) return {signature,pending:true};
    } catch(e) { if(e instanceof ModerationRejectError) throw e; return {signature,pending:true}; }
    if(Date.now() >= deadline) return {signature,pending:true};
    await new Promise(resolve=>setTimeout(resolve,1500));
  }
}

export interface AttestDeps {
  rpcUrl: string;
  attestationTtlSeconds: number;
  /** Job-spec registry base for the retrievability gate (default: official). */
  jobSpecRegistryUrl?: string;
  /** Operator registry write token; required for enabled pins. */
  jobSpecRegistryToken?: string | null;
  pinEnabled?: boolean;
  cluster?: string;
  store?: AttestationStore;
  spendLimits?: SpendLimits;
  repository?: { workers: Readonly<Record<string,string>>; imageDigest: string; github?: GithubClient };
}

/** Removed desktop listing-write surface. */
export async function attestListing(_deps: AttestDeps, _params: {listing: string; spec?: Record<string,unknown>; specUri?: string}): Promise<ModerationResult> {
  throw new ModerationRejectError(410,'Desktop attestor supports task intake only.');
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

/** Validate binding, scan, journal, then pay once and sign a separate verdict. */
export async function attestTask(deps: AttestDeps, params: {
  task: string; jobSpecHash?: string; spec?: Record<string,unknown>; specUri?: string; rawText?: string;
  creatorAuthorization?: CreatorAuthorization; preflightOnly?: boolean;
}): Promise<ModerationResult> {
  if(params.spec) assertJsonDepth(params.spec);
  const moderator = await tryLoadModeratorSigner();
  const rpc = createSolanaRpc(deps.rpcUrl);
  const taskAddr = address(params.task);
  const task = await fetchMaybeTask(rpc,taskAddr);
  if(!task.exists) throw new ModerationRejectError(404,'Task does not exist.');
  const [jobSpecPda] = await findTaskJobSpecPda({task:taskAddr});
  const pinned = await fetchMaybeTaskJobSpec(rpc,jobSpecPda);
  const target = params.jobSpecHash?.toLowerCase() ?? (params.spec ? (await values.canonicalJobSpecHash(unwrapPayload(params.spec))).hex : pinned.exists ? toHex(pinned.data.jobSpecHash as Uint8Array) : '');
  if(!/^[0-9a-f]{64}$/.test(target)) throw new ModerationRejectError(400,'Invalid hash.');
  if(pinned.exists && toHex(pinned.data.jobSpecHash as Uint8Array) !== target) throw new ModerationRejectError(409,'Different hash already pinned.');
  const store = deps.store ?? getStore();
  const queuedJob = store.intakeJob(params.task,target);
  const queuedContext = queuedJob ? JSON.parse(queuedJob.context) as import('./store.js').QueueContext : undefined;
  const priorAuthorization = queuedContext?.authenticatedCreator && queuedContext.creator === task.data.creator;
  const admittedAuthorization = queuedContext?.creatorAuthorization && JSON.stringify(queuedContext.creatorAuthorization) === JSON.stringify(params.creatorAuthorization);
  const authenticatedCreator = priorAuthorization && (!params.creatorAuthorization || admittedAuthorization)
    ? (task.data.status === 0 && task.data.currentWorkers === 0 && task.data.completions === 0 ? true : (()=>{throw new ModerationRejectError(409,'Task changed.');})())
    : bindRequester(task.data,params.task,target,params.creatorAuthorization,store,params.preflightOnly);
  const existing = store.get(params.task);
  if(existing && (existing.expires > Date.now() || ['queued','reserved','pending'].includes(existing.state)) && existing.hash !== target) throw new ModerationRejectError(409,'One live hash per task.');
  const resolved = await resolveSpecAgainstHash({targetHashHex:target,spec:params.spec,specUri:params.specUri ?? (pinned.exists ? pinned.data.jobSpecUri : undefined),rawText:params.rawText,what:'task spec'});
  let repo = resolved.payload.repo;
  const custom = resolved.payload.custom as {github?:unknown} | undefined;
  let reviewed: SignedDocument | undefined;
  if (custom?.github !== undefined) {
    if(params.preflightOnly) return {verdict:'suspicious',riskScore:60,specHash:target,moderator:moderator?.address ?? null,attestation:null,policyHash:moderationPolicyHashHex(),preflightOnly:true,wouldAttest:false};
    if((await values.canonicalJobSpecHash(resolved.payload)).hex !== target) throw new ModerationRejectError(422,'Repository intake requires the canonical job spec hash.');
    if(!deps.repository || !Object.keys(deps.repository.workers).length || !moderator) throw new ModerationRejectError(503,'Repository worker and R required.');
    if(queuedJob?.reviewed) {
      reviewed = JSON.parse(queuedJob.reviewed) as SignedDocument;
      if(reviewed.body.scannerHash !== repositoryScannerHash(deps.repository.imageDigest) || reviewed.body.policyHash !== moderationPolicyHashHex() || Date.parse(String(reviewed.body.expiresAt)) <= Date.now()) throw new ModerationRejectError(409,'Repository review changed or expired.');
      repo = reviewed.body.repo;
      if(reviewed.body.verdict === 'clean' && !repo) throw new ModerationRejectError(409,'Missing repository binding.');
    } else {
      let job;
      try { job = validateJob({kind:'repo-intake',taskPda:params.task,jobSpecHash:target,github:custom.github as GithubSpec}); }
      catch { throw new ModerationRejectError(422,'Invalid repository spec.'); }
      if(!queuedJob) {
        authorizedVerdictKey(moderator.address);
        await resolveSignerMode(rpc,moderator);
        const rent=await rpc.getMinimumBalanceForRentExemption(BigInt(getTaskModerationSize())).send();
        const {value:balance}=await rpc.getBalance(moderator.address,{commitment:'confirmed'}).send();
        const cost=Number(rent+100_000n);
        if(!Number.isSafeInteger(cost) || !Number.isSafeInteger(Number(balance))) throw new ModerationRejectError(503,'Invalid balance.');
        store.reserve(params.task,target,task.data.creator,cost,Number(balance),deps.spendLimits ?? DEFAULT_SPEND_LIMITS,Date.now(),{job,context:{payload:resolved.payload,creator:task.data.creator,authenticatedCreator,creatorAuthorization:params.creatorAuthorization,specUri:params.specUri ?? (pinned.exists ? pinned.data.jobSpecUri : undefined)}});
      }
      return {verdict:'suspicious',riskScore:60,specHash:target,moderator:moderator.address,attestation:null,policyHash:moderationPolicyHashHex(),pending:true,jobId:store.intakeJob(params.task,target)!.id,retryAfterSeconds:5};
    }
  }
  const repoFields = ['id','owner','name','licenseSpdx','baseCommit','treeSha','allowedPathsHash','maxDiffBytes','testCommandHash'];
  if(repo === null && !reviewed) throw new ModerationRejectError(422,'Invalid repo metadata.');
  if(repo != null) {
    if(!repo || typeof repo !== 'object' || Array.isArray(repo)) throw new ModerationRejectError(422,'Invalid repo metadata.');
    const r = repo as Record<string,unknown>;
    if(repoFields.some(f=> f === 'maxDiffBytes' ? !Number.isSafeInteger(r[f]) || Number(r[f])<=0 : f === 'id' && reviewed ? !Number.isSafeInteger(r[f]) || Number(r[f])<=0 : typeof r[f] !== 'string' || !r[f])) throw new ModerationRejectError(422,'Incomplete repo metadata.');
    if(!/^[0-9a-f]{40}$/.test(String(r.baseCommit)) || !/^[0-9a-f]{40}$/.test(String(r.treeSha)) || !/^[0-9a-f]{64}$/.test(String(r.allowedPathsHash)) || !/^[0-9a-f]{64}$/.test(String(r.testCommandHash))) throw new ModerationRejectError(422,'Invalid repo hashes.');
  }
  const scan = scanPayload(resolved.payload);
  if(reviewed) Object.assign(scan,{verdict:reviewed.body.verdict,riskScore:reviewed.body.riskScore,categories:reviewed.body.categories,reasons:reviewed.body.reasons});
  const effectiveScannerHash = reviewed ? String(reviewed.body.scannerHash) : scannerHashHex();
  const result: ModerationResult = {verdict:scan.verdict,riskScore:scan.riskScore,specHash:target,moderator:moderator?.address ?? null,attestation:null,policyHash:moderationPolicyHashHex()};
  if(params.preflightOnly) return {...result,preflightOnly:true,wouldAttest:scan.verdict === 'clean' && moderator !== null};
  const {key,keyId} = authorizedVerdictKey(result.moderator);
  const genesisHash = await rpc.getGenesisHash().send();
  if(reviewed && (reviewed.body.genesisHash !== genesisHash || reviewed.body.creator !== task.data.creator || reviewed.body.cluster !== (deps.cluster ?? 'mainnet'))) throw new ModerationRejectError(409,'Review context changed.');
  const [pda] = moderator ? await findTaskModerationPda({task:taskAddr,jobSpecHash:resolved.specHashBytes,moderator:moderator.address}) : [null];
  const readRecord = async () => pda ? await fetchMaybeTaskModeration(rpc,pda) : null;
  const usable = (record: Awaited<ReturnType<typeof readRecord>>) => record?.exists && record.data.status === 0 && record.data.creator === task.data.creator && record.data.task === taskAddr && record.data.moderator === moderator?.address && toHex(record.data.jobSpecHash as Uint8Array) === target && toHex(record.data.policyHash as Uint8Array) === result.policyHash && toHex(record.data.scannerHash as Uint8Array) === effectiveScannerHash && record.data.expiresAt > BigInt(Math.floor(Date.now()/1000));
  let record = await readRecord();
  if(existing?.result && existing.hash === target && existing.expires > Date.now()) {
    const cached = JSON.parse(existing.result) as ModerationResult;
    const cachedBody = cached.signedVerdict?.body;
    if(cachedBody?.policyHash !== result.policyHash || cachedBody.scannerHash !== effectiveScannerHash || cachedBody.genesisHash !== genesisHash || cachedBody.programId !== AGENC_COORDINATION_PROGRAM_ADDRESS) throw new ModerationRejectError(409,'Policy changed; operator review required.');
    if(existing.state === 'held' || usable(record)) return cached;
  }
  if(existing && ['reserved','pending'].includes(existing.state) && !usable(record)) return {...result,pending:true,...(queuedJob ? {jobId:queuedJob.id,retryAfterSeconds:5}:{}),recordPda:pda ?? undefined,attestation:existing.signature ? {signature:existing.signature,recordedAt:new Date().toISOString(),expiresAt:null} : null};
  store.admit(params.task,target,task.data.creator,deps.spendLimits ?? DEFAULT_SPEND_LIMITS);
  let retrievability: SpecRetrievability | undefined;
  let expires = Math.min(Math.floor(Date.now()/1000)*1000+72*3600000,reviewed ? Date.parse(String(reviewed.body.expiresAt)):Infinity);
  if(scan.verdict === 'clean' && moderator && pda) {
    result.recordPda = pda;
    if(usable(record) && record?.exists) {
      expires = Math.min(Number(record.data.expiresAt)*1000,expires);
      result.attestation = {signature:existing?.signature ?? '',recordedAt:new Date(Number(record.data.recordedAt)*1000).toISOString(),expiresAt:new Date(expires).toISOString()};
    } else {
      if(record?.exists) throw new ModerationRejectError(409,'Existing on-chain record requires operator review.');
      const mode = await resolveSignerMode(rpc,moderator);
      retrievability = await ensureSpecRetrievable({registryUrl:deps.jobSpecRegistryUrl ?? DEFAULT_JOB_SPEC_REGISTRY_URL,registryToken:deps.jobSpecRegistryToken ?? null,pinEnabled:deps.pinEnabled,authenticatedCreator,targetHashHex:target,payload:resolved.payload,candidateUris:[params.specUri],resolvedFromUri:resolved.retrievedFromUri,moderator:null,what:'task spec'});
      const instruction = await facade.recordTaskModeration({task:taskAddr,moderator,...(mode.moderationAttestor ? {moderationAttestor:mode.moderationAttestor}:{}),jobSpecHash:resolved.specHashBytes,status:0,riskScore:scan.riskScore,categoryMask:scan.categoryMask,policyHash:moderationPolicyHashBytes(),scannerHash:Buffer.from(effectiveScannerHash,'hex'),expiresAt:BigInt(Math.floor(expires/1000))}) as Instruction;
      // Close the read/build race as far as possible without changing revision 5.
      const current = await fetchMaybeTask(rpc,taskAddr);
      if(!current.exists || current.data.creator !== task.data.creator || current.data.status !== 0 || current.data.currentWorkers !== 0 || current.data.completions !== 0) throw new ModerationRejectError(409,'Task changed.');
      if(!priorAuthorization) bindRequester(current.data,params.task,target,params.creatorAuthorization,store,true);
      const latestPinned = await fetchMaybeTaskJobSpec(rpc,jobSpecPda);
      if(latestPinned.exists && toHex(latestPinned.data.jobSpecHash as Uint8Array) !== target) throw new ModerationRejectError(409,'Pin changed.');
      record = await readRecord();
      if(record?.exists) throw new ModerationRejectError(409,'Record appeared; retry read.');
      const sent = await signAndSend(deps.rpcUrl,instruction,moderator,{store,task:params.task,reserve:(cost,balance)=>store.reserve(params.task,target,task.data.creator,cost,balance,deps.spendLimits ?? DEFAULT_SPEND_LIMITS)});
      result.attestation = {signature:sent.signature,recordedAt:new Date().toISOString(),expiresAt:new Date(expires).toISOString()};
      if(sent.pending) return {...result,pending:true,...(queuedJob ? {jobId:queuedJob.id,retryAfterSeconds:5}:{})};
    }
  }
  if(retrievability) Object.assign(result,attestedRetrievabilityFields(retrievability));
  const issuedAt = new Date().toISOString();
  const body: Record<string,unknown> = {...(reviewed?.body ?? {}),v:1,kind:'task-intake',cluster:deps.cluster ?? 'mainnet',genesisHash,programId:AGENC_COORDINATION_PROGRAM_ADDRESS,taskPda:params.task,creator:task.data.creator,jobSpecHash:target,jobSpecUri:retrievability?.specRegistryUri ?? params.specUri ?? (pinned.exists ? pinned.data.jobSpecUri : null),policyHash:result.policyHash,scannerHash:effectiveScannerHash,verdict:scan.verdict,riskScore:scan.riskScore,categories:scan.categories ?? [],reasons:scan.reasons ?? (scan.truncated ? ['INPUT_LIMIT'] : []),record:{moderator:result.moderator,pda:result.attestation ? pda : null,txSignature:result.attestation?.signature || null},issuedAt,expiresAt:new Date(expires).toISOString(),nonce:randomBytes(16).toString('hex'),keyId};
  if(repo && typeof repo === 'object' && !Array.isArray(repo)) {
    const r = repo as Record<string,unknown>;
    body.repo = Object.fromEntries(repoFields.map(f=>[f,r[f]]));
  }
  result.signedVerdict = signDocument(body,key);
  if(reviewed) store.releaseQueuedSpend(params.task);
  if(store.get(params.task)?.state === 'pending') store.finish(params.task,result,expires);
  else store.saveVerdict(params.task,target,task.data.creator,result,expires);
  if(queuedJob && reviewed) store.finishJob(queuedJob.id,result,expires);
  return result;
}
