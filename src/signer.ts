import { scannerHash as repositoryScannerHash } from '../worker/rules.js';
import { validateJob, type GithubSpec } from '../worker/types.js';
import type { GithubClient } from '../worker/github.js';
import { buildPaymentOffer, readPaymentPrice, type PaymentOffer } from './payment.js';
import { assertJsonDepth } from './json-depth.js';
/** Creator-bound revision 5 task intake. All network boundaries are mockable in tests. */

import { readFileSync } from "node:fs";
import { bindRequester, type CreatorAuthorization } from "./binding.js";
import { getStore, DEFAULT_SPEND_LIMITS, type AttestationStore, type SpendLimits } from "./store.js";
import { authorizedVerdictKey, signDocument, type SignedDocument } from "./verdict.js";
import { createHash, randomBytes } from "node:crypto";
import {
  address,
  createKeyPairSignerFromBytes,
  createSolanaRpc,
  signature as solanaSignature,
  type Address,
  type Instruction,
  type TransactionSigner,
} from "@solana/kit";
import {
  getRecordTaskModerationInstructionDataDecoder,
  getRecordTaskModerationDiscriminatorBytes,
  type TaskModeration,
  facade,
  AGENC_COORDINATION_PROGRAM_ADDRESS,
  fetchMaybeTaskModeration,
  findTaskModerationPda,
  fetchMaybeTask,
  fetchMaybeTaskJobSpec,
  fetchMaybeModerationConfig,
  fetchMaybeModerationAttestor,
  findTaskJobSpecPda,
  findModerationConfigPda,
  findModerationAttestorPda,
  values,
} from "@tetsuo-ai/marketplace-sdk";
import { base58Decode } from "./base58.js";
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
export interface ModerationResult extends Partial<Omit<PaymentOffer,'moderator'>> {
  verdict: Verdict;
  riskScore: number;
  /** Canonical spec hash (hex) — equals the on-chain spec_hash. */
  specHash: string;
  /**
   * The signer whose on-chain record a consumption gate must name as its
   * P1.2 `moderator` argument. Null in verdict-only mode (no signer).
   */
  moderator: string | null;
  /** Present only on a CLEAN verdict with a confirmed on-chain record; null when held. */
  attestation: { signature: string; recordedAt: string; expiresAt: string | null } | null;
  /** sha256 of the moderation policy document (hex) the attestation commits to. */
  policyHash: string;
  /**
   * Present on payment offers and attested results: a retrievable copy of the exact spec
   * content was verified (or pinned) before the offer was signed.
   */
  retrievable?: true;
  /** Present on payment offers and attested results: this service published the spec itself. */
  pinned?: boolean;
  /** Present on payment offers and attested results: https URL where the spec is retrievable. */
  specRegistryUri?: string;
  pending?: boolean;
  jobId?: string;
  retryAfterSeconds?: number;
  preflightOnly?: boolean;
  wouldAttest?: boolean;
  signedVerdict?: SignedDocument;
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
  attestationServiceFeeLamports?: number;
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

/** Validate binding, scan, journal, then offer a creator-paid transaction and sign a separate verdict. */
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
  const existing = store.get(params.task);
  const queuedJob = store.intakeJob(params.task,target);
  const queuedContext = queuedJob ? JSON.parse(queuedJob.context) as import('./store.js').QueueContext : existing && existing.expires>Date.now() ? store.binding(params.task,target) : undefined;
  const priorAuthorization = queuedContext?.authenticatedCreator && queuedContext.creator === task.data.creator;
  const admittedAuthorization = queuedContext?.creatorAuthorization && JSON.stringify(queuedContext.creatorAuthorization) === JSON.stringify(params.creatorAuthorization);
  const authenticatedCreator = priorAuthorization && (!params.creatorAuthorization || admittedAuthorization)
    ? (task.data.status === 0 && task.data.currentWorkers === 0 && task.data.completions === 0 ? true : (()=>{throw new ModerationRejectError(409,'Task changed.');})())
    : bindRequester(task.data,params.task,target,params.creatorAuthorization,store,params.preflightOnly);
  if(existing && (existing.expires > Date.now() || ['queued','reserved','pending'].includes(existing.state)) && existing.hash !== target) throw new ModerationRejectError(409,'One live hash per task.');
  if(!params.preflightOnly) store.rememberBinding(params.task,target,{payload:params.spec ?? {},creator:task.data.creator,authenticatedCreator,creatorAuthorization:params.creatorAuthorization ?? queuedContext?.creatorAuthorization,specUri:params.specUri});
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
        if(task.data.creator === moderator.address) throw new ModerationRejectError(409,'Moderator must not be the fee payer.');
        store.enqueueIntake(params.task,target,task.data.creator,deps.spendLimits ?? DEFAULT_SPEND_LIMITS,job,{payload:resolved.payload,creator:task.data.creator,authenticatedCreator,creatorAuthorization:params.creatorAuthorization,specUri:params.specUri ?? (pinned.exists ? pinned.data.jobSpecUri : undefined)});
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
  const usable = (record: Awaited<ReturnType<typeof readRecord>>) => record?.exists && record.data.status === 0 && record.data.riskScore === scan.riskScore && record.data.categoryMask === BigInt(scan.categoryMask) && record.data.creator === task.data.creator && record.data.task === taskAddr && record.data.moderator === moderator?.address && toHex(record.data.jobSpecHash as Uint8Array) === target && toHex(record.data.policyHash as Uint8Array) === result.policyHash && toHex(record.data.scannerHash as Uint8Array) === effectiveScannerHash && record.data.expiresAt > BigInt(Math.floor(Date.now()/1000));
  let record = await readRecord();
  let cachedPayment: ModerationResult|undefined;
  if(existing?.result && existing.hash === target && existing.expires > Date.now()) {
    const cached = JSON.parse(existing.result) as ModerationResult;
    const cachedBody = cached.signedVerdict?.body;
    if(cachedBody?.policyHash !== result.policyHash || cachedBody.scannerHash !== effectiveScannerHash || cachedBody.genesisHash !== genesisHash || cachedBody.programId !== AGENC_COORDINATION_PROGRAM_ADDRESS || cachedBody.creator !== task.data.creator || cached.moderator !== (moderator?.address ?? null)) throw new ModerationRejectError(409,'Policy or creator changed; operator review required.');
    if(existing.state === 'held') return cached;
    if(usable(record)) return confirmPayment(deps,params.task,target,cached);
    if(record?.exists || existing.state === 'confirmed') throw new ModerationRejectError(409,'Confirmed record changed or disappeared.');
    if(cached.transaction && cached.lastValidBlockHeight !== undefined) {
      if(await rpc.getBlockHeight({commitment:'confirmed'}).send() <= BigInt(cached.lastValidBlockHeight)) return cached;
      cachedPayment=cached;
    }
  }
  // Never automatically replace legacy R-paid reservations after upgrade.
  if(existing && ['reserved','pending'].includes(existing.state) && !usable(record)) throw new ModerationRejectError(409,'Legacy payment needs reconciliation.');
  store.admit(params.task,target,task.data.creator,deps.spendLimits ?? DEFAULT_SPEND_LIMITS);
  let retrievability: SpecRetrievability | undefined;
  let expires = cachedPayment ? existing!.expires : Math.min(Math.floor(Date.now()/1000)*1000+72*3600000,reviewed ? Date.parse(String(reviewed.body.expiresAt)):Infinity);
  if(scan.verdict === 'clean' && moderator && pda) {
    result.recordPda = pda;
    if(usable(record) && record?.exists) {
      expires = Math.min(Number(record.data.expiresAt)*1000,expires);
      result.attestation = {signature:await recordSignature(deps.rpcUrl,pda,record.data),recordedAt:new Date(Number(record.data.recordedAt)*1000).toISOString(),expiresAt:new Date(expires).toISOString()};
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
      store.assertPaymentCapacity(params.task,task.data.creator,deps.spendLimits ?? DEFAULT_SPEND_LIMITS);
      const price=cachedPayment ? {priceLamports:cachedPayment.priceLamports!,rentLamports:cachedPayment.rentLamports!,serviceFeeLamports:cachedPayment.serviceFeeLamports!} : await readPaymentPrice(deps.rpcUrl,deps.attestationServiceFeeLamports ?? 0);
      Object.assign(result,await buildPaymentOffer(deps.rpcUrl,task.data.creator,moderator,pda,instruction,price));
    }
  }
  if(retrievability) Object.assign(result,attestedRetrievabilityFields(retrievability));
  const issuedAt = new Date().toISOString();
  const body: Record<string,unknown> = {...(reviewed?.body ?? {}),v:1,kind:'task-intake',cluster:deps.cluster ?? 'mainnet',genesisHash,programId:AGENC_COORDINATION_PROGRAM_ADDRESS,taskPda:params.task,creator:task.data.creator,jobSpecHash:target,jobSpecUri:retrievability?.specRegistryUri ?? params.specUri ?? (pinned.exists ? pinned.data.jobSpecUri : null),policyHash:result.policyHash,scannerHash:effectiveScannerHash,verdict:scan.verdict,riskScore:scan.riskScore,categories:scan.categories ?? [],reasons:scan.reasons ?? (scan.truncated ? ['INPUT_LIMIT'] : []),payment:result.priceLamports !== undefined ? {recordPda:pda,priceLamports:result.priceLamports,payer:task.data.creator} : null,record:{moderator:result.moderator,pda:scan.verdict === 'clean' ? pda : null,txSignature:result.attestation?.signature || null},issuedAt,expiresAt:new Date(expires).toISOString(),nonce:randomBytes(16).toString('hex'),keyId};
  if(repo && typeof repo === 'object' && !Array.isArray(repo)) {
    const r = repo as Record<string,unknown>;
    body.repo = Object.fromEntries(repoFields.map(f=>[f,r[f]]));
  }
  result.signedVerdict = cachedPayment?.signedVerdict ?? signDocument(body,key);
  if(result.transaction) {
    const offer=store.saveOffer(params.task,target,task.data.creator,result,expires,deps.spendLimits ?? DEFAULT_SPEND_LIMITS,existing?.result);
    if(queuedJob && reviewed) store.finishJob(queuedJob.id,offer,expires);
    return offer;
  }
  if(store.get(params.task)?.state === 'pending') store.finish(params.task,result,expires);
  else store.saveVerdict(params.task,target,task.data.creator,result,expires);
  if(queuedJob && reviewed) store.finishJob(queuedJob.id,result,expires);
  return result;
}

/** Obtain an actual confirmed signature from PDA history; never invent a receipt. */
async function recordSignature(rpcUrl: string, pda: string, record: TaskModeration): Promise<string> {
  const rpc=createSolanaRpc(rpcUrl);
  const history=await rpc.getSignaturesForAddress(address(pda),{commitment:'confirmed',limit:20}).send();
  for(const receipt of history) {
    if(receipt.err !== null) continue;
    const tx=await rpc.getTransaction(solanaSignature(receipt.signature),{commitment:'confirmed',encoding:'json',maxSupportedTransactionVersion:0}).send();
    if(!tx || !tx.meta || tx.meta.err !== null) continue;
    const message=tx.transaction.message;
    const keys=[...message.accountKeys,...(tx.meta.loadedAddresses?.writable ?? []),...(tx.meta.loadedAddresses?.readonly ?? [])];
    for(const ix of message.instructions) {
      if(keys[ix.programIdIndex] !== AGENC_COORDINATION_PROGRAM_ADDRESS || keys[ix.accounts[1]] !== record.task ||
         keys[ix.accounts[2]] !== record.moderator || keys[ix.accounts[3]] !== pda) continue;
      try {
        const bytes=base58Decode(ix.data);
        if(!Buffer.from(bytes.subarray(0,8)).equals(Buffer.from(getRecordTaskModerationDiscriminatorBytes()))) continue;
        const data=getRecordTaskModerationInstructionDataDecoder().decode(bytes);
        if(Buffer.from(data.jobSpecHash).equals(Buffer.from(record.jobSpecHash)) && data.status===record.status &&
           data.riskScore===record.riskScore && data.categoryMask===record.categoryMask && data.expiresAt===record.expiresAt &&
           Buffer.from(data.policyHash).equals(Buffer.from(record.policyHash)) && Buffer.from(data.scannerHash).equals(Buffer.from(record.scannerHash))) return receipt.signature;
      } catch { /* Unrelated instruction: continue looking for the record receipt. */ }
    }
  }
  throw new ModerationRejectError(502,'Confirmed record signature unavailable.');
}
async function confirmPayment(deps:AttestDeps,task:string,hash:string,result:ModerationResult):Promise<ModerationResult> {
  if(result.attestation) return result;
  const {key,keyId}=authorizedVerdictKey(result.moderator);
  const body=result.signedVerdict!.body;
  const record=await fetchMaybeTaskModeration(createSolanaRpc(deps.rpcUrl),address(result.recordPda!));
  if(!record.exists || !recordMatches(record.data,result,task,hash)) throw new ModerationRejectError(409,'Record binding changed.');
  const signature=await recordSignature(deps.rpcUrl,result.recordPda!,record.data);
  const paid={...result};
  delete paid.transaction;delete paid.lastValidBlockHeight;
  paid.attestation={signature,recordedAt:new Date(Number(record.data.recordedAt)*1000).toISOString(),expiresAt:String(body.expiresAt)};
  paid.signedVerdict=signDocument({...body,keyId,record:{...(body.record as Record<string,unknown>),txSignature:signature}},key);
  const store=deps.store ?? getStore();
  store.saveVerdict(task,hash,String(body.creator),paid,Date.parse(String(body.expiresAt)));
  const job=store.intakeJob(task,hash);if(job) store.finishJob(job.id,paid,Date.parse(String(body.expiresAt)));
  return paid;
}
/** GET only reconciles a paid record; it never creates or reissues transactions. */
export async function getStoredAttestation(deps:AttestDeps,task:string,hash:string):Promise<ModerationResult|undefined> {
  const saved=(deps.store ?? getStore()).get(task);
  if(!saved?.result || saved.hash!==hash || saved.expires<=Date.now()) return undefined;
  const result=JSON.parse(saved.result) as ModerationResult;
  if(result.verdict !== 'clean' || !result.recordPda) return result;
  const record=await fetchMaybeTaskModeration(createSolanaRpc(deps.rpcUrl),address(result.recordPda));
  if(!record.exists) {
    if(result.attestation) throw new ModerationRejectError(409,'Confirmed record disappeared.');
    return result;
  }
  if(!recordMatches(record.data,result,task,hash))
    throw new ModerationRejectError(409,'Confirmed record binding mismatch.');
  return confirmPayment(deps,task,hash,result);
}

function recordMatches(record:TaskModeration,result:ModerationResult,task:string,hash:string):boolean {
  const b=result.signedVerdict!.body;
  return record.status===0 && record.task===task && record.creator===b.creator && record.moderator===result.moderator &&
    Buffer.from(record.jobSpecHash).toString('hex')===hash && Buffer.from(record.policyHash).toString('hex')===b.policyHash &&
    Buffer.from(record.scannerHash).toString('hex')===b.scannerHash && record.riskScore===result.riskScore &&
    record.expiresAt>=BigInt(Math.floor(Date.parse(String(b.expiresAt))/1000)) && record.expiresAt>BigInt(Math.floor(Date.now()/1000));
}
