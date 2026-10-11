import { scannerHash as repositoryScannerHash } from '../worker/rules.js';
import { enqueueDeliverable, acceptQueuedReport } from './repo-queue.js';
import { verifyQueueRequest, type QueueRequest } from '../worker/queue-http.js';
import type { SignedDocument } from './verdict.js';
import { randomUUID } from 'node:crypto';
import { assertJsonDepth } from './json-depth.js';
import { getStore } from './store.js';
import { loadKeyManifest } from './verdict.js';
import type { CreatorAuthorization } from './binding.js';
/** Desktop attestor HTTP surface; POST never advertises CORS. */

import { normalizeTaskModerationInput } from "@tetsuo-ai/marketplace-moderation";
import { loadConfig, type ServiceConfig } from "./config.js";
import { clientIp, limiterMode, rateLimit } from "./rate-limit.js";
import { MAX_BODY_BYTES } from "./limits.js";
import {
  attestTask,
  loadModeratorSigner,
  ModerationRejectError,
  ModerationSignerUnavailableError,
  SpecNotRetrievableError,
  type AttestDeps,
  type ModerationResult,
} from "./signer.js";
import { moderationPolicyBytes, moderationPolicyHashHex } from "./policy.js";
import { SCANNER_DESCRIPTOR, scannerHashHex } from "./scan.js";
import { openApiDocument } from "./openapi.js";
import { SERVICE_NAME, SERVICE_VERSION } from "./version.js";

const PDA_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const HASH_RE = /^[0-9a-f]{64}$/;

function json(body: unknown, status = 200, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(body && typeof body === "object" && !Array.isArray(body) ? {moderator:null,...body} : body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extra,
    },
  });
}

function errorJson(status: number, _message: string, extra?: Record<string, unknown>): Response {
  const logId = typeof extra?.logId === 'string' ? extra.logId : randomUUID();
  console.error(JSON.stringify({logId,event:'request-refused',status}));
  return json({ ok: false, error: 'Request could not be completed.', logId, ...extra }, status);
}

async function readJsonBody(request: Request): Promise<Record<string, unknown>> {
  // Reject before buffering when the declared size is over the cap. The Node
  // self-host adapter additionally hard-caps the stream (byteCap), so a lying
  // or absent Content-Length cannot OOM the process; here we also re-check the
  // materialized BYTE length (not UTF-16 code units) as the transport-agnostic
  // backstop.
  const declared = Number(request.headers.get("content-length") ?? "");
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    throw new ModerationRejectError(413, "Request body too large.");
  }
  let raw: string;
  try {
    raw = await request.text();
  } catch {
    // The stream cap (or a client abort) fired mid-read.
    throw new ModerationRejectError(413, "Request body too large or truncated.");
  }
  if (Buffer.byteLength(raw, "utf8") > MAX_BODY_BYTES) {
    throw new ModerationRejectError(413, "Request body too large.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ModerationRejectError(400, "Invalid JSON body.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ModerationRejectError(400, "Body must be a JSON object.");
  }
  assertJsonDepth(parsed);
  const preflight = (parsed as Record<string,unknown>).preflightOnly;
  if(preflight !== undefined && typeof preflight !== 'boolean') throw new ModerationRejectError(400,'preflightOnly must be boolean.');
  return parsed as Record<string, unknown>;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function optionalObject(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/** Map attest-core errors to HTTP responses; unexpected errors → retryable 502. */
function attestErrorResponse(error: unknown, config: ServiceConfig): Response {
  const logId = randomUUID();
  const status = error instanceof ModerationRejectError ? error.httpStatus : error instanceof SpecNotRetrievableError ? error.httpStatus : error instanceof ModerationSignerUnavailableError ? 503 : 502;
  console.error(JSON.stringify({logId,event:'request-failed',type:error instanceof Error ? error.name : 'Error',status}));
  try { getStore(config.storePath).audit('request-failed',{logId,status,type:error instanceof Error ? error.name : 'Error'}); } catch { /* Error response must work when the DB is unavailable. */ }
  return errorJson(status,'Request could not be completed.',{logId,...(error instanceof SpecNotRetrievableError ? {code:error.code,retryable:true} : {})});
}

/** POST gate: API key (when configured) then rate limit. Returns a Response to short-circuit, or null to proceed. */
async function gatePost(config: ServiceConfig, request: Request): Promise<Response | null> {
  if (config.apiKeys.length > 0) {
    const header = request.headers.get("authorization") ?? "";
    const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
    if (!token || !config.apiKeys.includes(token)) {
      return errorJson(401, "This deployment requires an API key (Authorization: Bearer <key>).");
    }
  }
  const decision = await rateLimit(config, clientIp(request));
  if (!decision.allowed) {
    const response = errorJson(429,'Request rate exceeded.',{retryAfterSeconds:decision.retryAfterSeconds});
    response.headers.set('retry-after',String(decision.retryAfterSeconds));
    return response;
  }
  return null;
}

/* ------------------------------- handlers -------------------------------- */

function attestDeps(config: ServiceConfig): AttestDeps {
  return {
    repository: config.repositoryImageDigest ? {imageDigest:config.repositoryImageDigest,workers:config.repositoryWorkers}:undefined,
    rpcUrl: config.rpcUrl,
    attestationTtlSeconds: config.attestationTtlSeconds,
    jobSpecRegistryUrl: config.jobSpecRegistryUrl,
    jobSpecRegistryToken: config.jobSpecRegistryToken,
    pinEnabled: config.pinEnabled,
    cluster: config.cluster,
    store: getStore(config.storePath),
    spendLimits: config.spendLimits,
  };
}

async function handleTasks(config: ServiceConfig, request: Request, overrides: Partial<AttestDeps> = {}): Promise<Response> {
  const body = await readJsonBody(request);
  const task = optionalString(body.task) ?? optionalString(body.taskPda);
  if (!task || !PDA_RE.test(task)) {
    return errorJson(400, "Provide a valid task PDA (task).");
  }
  const jobSpecHash = optionalString(body.jobSpecHash)?.toLowerCase();
  if (jobSpecHash && !HASH_RE.test(jobSpecHash)) {
    return errorJson(400, "jobSpecHash must be 64 hex chars.");
  }
  const result = await attestTask({...attestDeps(config),...overrides}, {
    task,
    jobSpecHash,
    creatorAuthorization: optionalObject(body.creatorAuthorization) as unknown as CreatorAuthorization | undefined,
    preflightOnly: body.preflightOnly === true,
    spec: optionalObject(body.spec),
    specUri: optionalString(body.specUri),
  });
  return json({ ok: true, attested: result.attestation !== null && !result.pending, ...result },result.pending ? 202 : 200);
}

/**
 * Compatibility endpoint for existing callers of the kit backend's
 * `POST /api/task-moderation/attest`:
 *
 *  - store-core `createRemoteTaskModerationAttestor` sends
 *    `{ taskPda, jobSpecHash, jobSpecUri, jobSpec, jobSpecCanonicalJson }`;
 *  - agenc.ag's proxy sends `{ taskPda, jobSpecHash, text,
 *    moderationPayloadHash, ... }` (the c14n moderation-input shape).
 *
 * Both reduce to pre-pin task attestation. The hash check is fail-closed:
 * the canonical payload hash OR the raw text-bytes sha256 must equal
 * `jobSpecHash` (the hash the task will pin). Responds with the kit-backend
 * shape `{ attested, moderation, txSignature }`.
 */
async function handleCompatAttest(config: ServiceConfig, request: Request, overrides: Partial<AttestDeps> = {}): Promise<Response> {
  const body = await readJsonBody(request);
  const task = optionalString(body.taskPda) ?? optionalString(body.task);
  const jobSpecHash = optionalString(body.jobSpecHash)?.toLowerCase();
  if (!task || !PDA_RE.test(task)) return errorJson(400, "Invalid taskPda.");
  if (!jobSpecHash || !HASH_RE.test(jobSpecHash)) return errorJson(400, "Invalid jobSpecHash.");

  const rawString = (value: unknown) => typeof value === 'string' && value.trim() ? value : undefined;
  const text = rawString(body.text) ?? rawString(body.jobSpecCanonicalJson);
  const jobSpecObject = optionalObject(body.jobSpec) ?? optionalObject(body.spec);
  let payloadHashFromText: string | null = null;

  // Single source of truth: when `text` is present it is the authoritative
  // content (the on-chain job_spec_hash is a hash OF a document, so the bytes
  // define the content). We derive the scanned spec FROM `text` and never let a
  // separately-supplied `jobSpec` object override it — otherwise a caller could
  // bind an attestation to sha256(text) while the scanner saw an unrelated
  // object. `jobSpec` is honored ONLY when no `text` was provided.
  let spec: Record<string, unknown> | undefined;
  let rawText: string | undefined;
  if (text) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return errorJson(422, "Spec text is not valid JSON.");
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return errorJson(422, "Spec text must be a JSON object.");
    }
    assertJsonDepth(parsed);
    spec = parsed as Record<string, unknown>;
    rawText = text;
    // Kit-backend parity detail for the response's moderation object: the
    // c14n moderation-input hash (`agenc-task-moderation-c14n-v1`). Best
    // effort — the fail-closed binding check lives in the signer.
    try {
      payloadHashFromText = normalizeTaskModerationInput(text).payloadHash;
    } catch {
      payloadHashFromText = null;
    }
  } else {
    spec = jobSpecObject;
  }
  if (!spec) {
    return errorJson(400, "Provide the spec inline (jobSpec) or as text.");
  }

  // store-core's remote attestor also sends `jobSpecUri` (the hosted copy of
  // the spec). The inline spec/text still wins RESOLUTION (single source of
  // truth for what gets scanned), but the URI feeds the retrievability gate's
  // candidate list — a spec hosted there passes without being force-routed
  // through the registry pin path.
  const result = await attestTask({...attestDeps(config),...overrides}, {
    task,
    jobSpecHash,
    creatorAuthorization: optionalObject(body.creatorAuthorization) as unknown as CreatorAuthorization | undefined,
    preflightOnly: body.preflightOnly === true,
    spec,
    specUri: optionalString(body.jobSpecUri),
    rawText,
  });
  return json({
    ok: true,
    attested: result.attestation !== null && !result.pending,
    moderator: result.moderator,
    verdict: result.verdict,
    ...(result.signedVerdict ? {signedVerdict:result.signedVerdict} : {}),
    ...(result.preflightOnly ? {preflightOnly:true,wouldAttest:result.wouldAttest} : {}),
    ...(result.pending ? {pending:true,jobId:result.jobId,retryAfterSeconds:result.retryAfterSeconds} : {}),
    moderation: {
      status: result.verdict,
      moderator: result.moderator,
      verdict: result.verdict,
      riskScore: result.riskScore,
      specHash: result.specHash,
      policyHash: result.policyHash,
      scannerHash: scannerHashHex(),
      expiresAt: result.attestation?.expiresAt ?? null,
      ...(payloadHashFromText ? { payloadHash: payloadHashFromText } : {}),
    },
    txSignature: result.attestation?.signature ?? null,
    ...(result.attestation
      ? {
          retrievable: result.retrievable,
          pinned: result.pinned,
          specRegistryUri: result.specRegistryUri,
        }
      : {}),
  },result.pending ? 202 : 200);
}

async function handleInfo(config: ServiceConfig): Promise<Response> {
  let signerAddress: string | null = null;
  let signerConfigured = false;
  try {
    const signer = await loadModeratorSigner();
    signerAddress = signer.address;
    signerConfigured = true;
  } catch {
    /* verdict-only deployment */
  }
  return json({
    ok: true,
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    cluster: config.cluster,
    signerConfigured,
    moderator: signerAddress,
    policyHash: moderationPolicyHashHex(),
    scannerHash: scannerHashHex(),
    scannerDescriptor: SCANNER_DESCRIPTOR,
    repository: {enabled:!!config.repositoryImageDigest && Object.keys(config.repositoryWorkers).length>0,imageDigest:config.repositoryImageDigest,scannerHash:config.repositoryImageDigest ? repositoryScannerHash(config.repositoryImageDigest):null},
    attestationTtlSeconds: config.attestationTtlSeconds,
    // The retrievability gate: every attestation implies retrievable content.
    jobSpecRegistry: {
      url: config.jobSpecRegistryUrl,
      pinEnabled:config.pinEnabled,
      pinCredential: config.pinEnabled && config.jobSpecRegistryToken ? "registry-token" : "disabled",
    },
    spendLimits: config.spendLimits,
    apiKeyRequired: config.apiKeys.length > 0,
    rateLimit: {
      mode: limiterMode(config),
      perIp: config.rateLimitPerIp,
      global: config.rateLimitGlobal,
      windowMs: config.rateLimitWindowMs,
    },
    endpoints: [
      "GET /v1/keys",
      "GET /v1/attestations/:task/:hash",
      "POST /v1/moderation/tasks",
      "POST /v1/moderation/deliverables",
      "GET /v1/deliverable-reviews/:task/:submission/:artifact",
      "POST /api/task-moderation/attest",
      "GET /v1/policy",
      "GET /v1/info",
      "GET /v1/health",
      "GET /openapi.json",
    ],
  });
}

/* --------------------------------- router -------------------------------- */

export type FetchHandler = (request: Request) => Promise<Response>;

/** Build the service's fetch handler. `configOverride` is a test seam. */
export function createModerationApi(configOverride?: Partial<ServiceConfig>, overrides: Partial<AttestDeps> = {}): FetchHandler {
  const handle = async function(request: Request): Promise<Response> {
    const config: ServiceConfig = { ...loadConfig(), ...configOverride };
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: {"access-control-allow-origin":"*","access-control-allow-methods":"GET, OPTIONS"} });
    }

    try {
      if (request.method === "GET") {
        if (path === "/v1/health") return json({ ok: true });
        if (path === '/v1/keys') return json({ok:true,manifest:loadKeyManifest()});
        const match = /^\/v1\/attestations\/([^/]+)\/([0-9a-f]{64})$/.exec(path);
        if(match) {
          const stored = (overrides.store ?? getStore(config.storePath)).get(match[1]);
          if(!stored || stored.hash !== match[2] || !stored.result || stored.expires <= Date.now()) return errorJson(404,'Attestation unavailable.');
          return json({ok:true,attested:stored.state === 'confirmed',...JSON.parse(stored.result)});
        }
        const deliverable=/^\/v1\/deliverable-reviews\/([^/]+)\/([^/]+)\/([0-9a-f]{64})$/.exec(path);
        if(deliverable) {
          const stored=(overrides.store ?? getStore(config.storePath)).deliverableJob(deliverable[1],deliverable[2],deliverable[3]);
          if(!stored?.result || stored.expires<=Date.now()) return errorJson(404,'Review unavailable.');
          return json({ok:true,attested:false,...JSON.parse(stored.result)});
        }
        if (path === "/v1/info") return handleInfo(config);
        if (path === "/v1/policy") {
          return new Response(new Uint8Array(moderationPolicyBytes()), {
            status: 200,
            headers: {
              "content-type": "text/markdown; charset=utf-8",
              "cache-control": "public, max-age=300",
            },
          });
        }
        if (path === "/openapi.json") return json(openApiDocument());
        if (path === "/" ) return handleInfo(config);
        return errorJson(404, `Unknown path ${path}. See GET /v1/info for the endpoint list.`);
      }

      if (request.method === "POST") {
        if(path === '/internal/worker/pull' || path === '/internal/worker/reports') {
          const deps={...attestDeps(config),...overrides};
          if(!deps.repository || !Object.keys(deps.repository.workers).length) return errorJson(503,'Worker unavailable.');
          const envelope=await readJsonBody(request) as unknown as SignedDocument<QueueRequest>;
          let auth:QueueRequest;
          try { auth=verifyQueueRequest(envelope,path,deps.repository.workers); }
          catch { return errorJson(403,'Worker authentication refused.'); }
          const store=deps.store ?? getStore(config.storePath);
          store.consumeNonce('transport:'+auth.workerId,auth.nonce);
          if(path === '/internal/worker/pull') {
            const lease=store.leaseJob(auth.workerId);
            return lease ? json({jobId:lease.id,leaseToken:lease.lease,leaseExpiresAt:new Date(lease.leaseUntil).toISOString(),job:JSON.parse(lease.job)}) : new Response(null,{status:204});
          }
          return json(await acceptQueuedReport(deps,auth.workerId,auth.payload as unknown as Parameters<typeof acceptQueuedReport>[2]));
        }
        const gate = await gatePost(config, request);
        if (gate) return gate;
        if (path === "/v1/moderation/listings") return errorJson(410,"Task intake only.");
        if (path === "/v1/moderation/tasks") return await handleTasks(config, request, overrides);
        if (path === '/v1/moderation/deliverables') {
          const body=await readJsonBody(request);
          if(typeof body.task !== 'string' || !PDA_RE.test(body.task) || typeof body.submissionPda !== 'string' || !PDA_RE.test(body.submissionPda) || typeof body.artifactSha256 !== 'string' || !HASH_RE.test(body.artifactSha256)) return errorJson(400,'Invalid deliverable binding.');
          const result=await enqueueDeliverable({...attestDeps(config),...overrides},body as {task:string;submissionPda:string;artifactSha256:string});
          return json({ok:true,attested:false,...result},result.pending ? 202:200);
        }
        if (path === "/api/task-moderation/attest") return await handleCompatAttest(config, request, overrides);
        return errorJson(404, `Unknown path ${path}. See GET /v1/info for the endpoint list.`);
      }

      return errorJson(405, "Method not allowed.");
    } catch (error) {
      return attestErrorResponse(error,config);
    }
  };
  return async request => {
    const response = await handle(request);
    if(request.method === 'GET') response.headers.set('access-control-allow-origin','*');
    return response;
  };
}

export type { ModerationResult };
