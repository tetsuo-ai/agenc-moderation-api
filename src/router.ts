/**
 * HTTP surface (WinterCG fetch handler — runs unchanged on Vercel functions
 * and the self-host Node adapter).
 *
 * PUBLIC endpoints (CORS-open; POST endpoints are rate-limited and optionally
 * API-keyed — plain bearer keys, NOT kit-entitlement gating):
 *
 *   POST /v1/moderation/listings   { listing, spec? | specUri? }
 *   POST /v1/moderation/tasks      { task, jobSpecHash?, spec? | specUri? }
 *   POST /api/task-moderation/attest   (compatibility: store-core remote
 *        attestor + agenc.ag proxy shapes) → { attested, moderation, txSignature }
 *   GET  /v1/policy      the exact policy bytes (sha256 == policy_hash)
 *   GET  /v1/info        service identity: signer pubkey, cluster, hashes, TTL
 *   GET  /v1/health      liveness
 *   GET  /openapi.json   the OpenAPI document
 */

import { normalizeTaskModerationInput } from "@tetsuo-ai/marketplace-moderation";
import { loadConfig, type ServiceConfig } from "./config.js";
import { clientIp, limiterMode, rateLimit } from "./rate-limit.js";
import { MAX_BODY_BYTES } from "./limits.js";
import {
  attestListing,
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

const CORS_HEADERS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type, authorization",
  "access-control-max-age": "86400",
};

function json(body: unknown, status = 200, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...CORS_HEADERS,
      ...extra,
    },
  });
}

function errorJson(status: number, message: string, extra?: Record<string, unknown>): Response {
  return json({ ok: false, error: message, ...extra }, status);
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
function attestErrorResponse(error: unknown): Response {
  if (error instanceof ModerationSignerUnavailableError) {
    return errorJson(503, error.message);
  }
  if (error instanceof SpecNotRetrievableError) {
    // Fail-closed retrievability refusal — retryable once the spec is hosted.
    return errorJson(error.httpStatus, error.message, { code: error.code, retryable: true });
  }
  if (error instanceof ModerationRejectError) {
    return errorJson(error.httpStatus, error.message);
  }
  return errorJson(502, error instanceof Error ? error.message : "Moderation failed.", {
    retryable: true,
  });
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
    const message =
      decision.deniedBy === "global"
        ? "The service-wide attestation ceiling for this window is exhausted. Retry shortly."
        : decision.deniedBy === "shared-store-error"
          ? "Rate-limit store temporarily unavailable; requests are paused to protect the signer. Retry shortly."
          : "Too many requests from this address. Retry shortly.";
    return new Response(JSON.stringify({ ok: false, error: message, retryAfterSeconds: decision.retryAfterSeconds }), {
      status: 429,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        "retry-after": String(decision.retryAfterSeconds),
        ...CORS_HEADERS,
      },
    });
  }
  return null;
}

/* ------------------------------- handlers -------------------------------- */

function attestDeps(config: ServiceConfig): AttestDeps {
  return {
    rpcUrl: config.rpcUrl,
    attestationTtlSeconds: config.attestationTtlSeconds,
    jobSpecRegistryUrl: config.jobSpecRegistryUrl,
    jobSpecRegistryToken: config.jobSpecRegistryToken,
  };
}

async function handleListings(config: ServiceConfig, request: Request): Promise<Response> {
  const body = await readJsonBody(request);
  const listing = optionalString(body.listing) ?? optionalString(body.listingPda);
  if (!listing || !PDA_RE.test(listing)) {
    return errorJson(400, "Provide a valid listing PDA (listing).");
  }
  const result = await attestListing(attestDeps(config), {
    listing,
    spec: optionalObject(body.spec),
    specUri: optionalString(body.specUri),
  });
  return json({ ok: true, attested: result.attestation !== null, ...result });
}

async function handleTasks(config: ServiceConfig, request: Request): Promise<Response> {
  const body = await readJsonBody(request);
  const task = optionalString(body.task) ?? optionalString(body.taskPda);
  if (!task || !PDA_RE.test(task)) {
    return errorJson(400, "Provide a valid task PDA (task).");
  }
  const jobSpecHash = optionalString(body.jobSpecHash)?.toLowerCase();
  if (jobSpecHash && !HASH_RE.test(jobSpecHash)) {
    return errorJson(400, "jobSpecHash must be 64 hex chars.");
  }
  const result = await attestTask(attestDeps(config), {
    task,
    jobSpecHash,
    spec: optionalObject(body.spec),
    specUri: optionalString(body.specUri),
  });
  return json({ ok: true, attested: result.attestation !== null, ...result });
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
async function handleCompatAttest(config: ServiceConfig, request: Request): Promise<Response> {
  const body = await readJsonBody(request);
  const task = optionalString(body.taskPda) ?? optionalString(body.task);
  const jobSpecHash = optionalString(body.jobSpecHash)?.toLowerCase();
  if (!task || !PDA_RE.test(task)) return errorJson(400, "Invalid taskPda.");
  if (!jobSpecHash || !HASH_RE.test(jobSpecHash)) return errorJson(400, "Invalid jobSpecHash.");

  const text = optionalString(body.text) ?? optionalString(body.jobSpecCanonicalJson);
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

  const result = await attestTask(attestDeps(config), { task, jobSpecHash, spec, rawText });
  return json({
    ok: true,
    attested: result.attestation !== null,
    moderation: {
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
  });
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
    attestationTtlSeconds: config.attestationTtlSeconds,
    // The retrievability gate: every attestation implies retrievable content.
    jobSpecRegistry: {
      url: config.jobSpecRegistryUrl,
      pinCredential: config.jobSpecRegistryToken ? "registry-token" : "wallet-upload-ticket",
    },
    apiKeyRequired: config.apiKeys.length > 0,
    rateLimit: {
      mode: limiterMode(config),
      perIp: config.rateLimitPerIp,
      global: config.rateLimitGlobal,
      windowMs: config.rateLimitWindowMs,
    },
    endpoints: [
      "POST /v1/moderation/listings",
      "POST /v1/moderation/tasks",
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
export function createModerationApi(configOverride?: Partial<ServiceConfig>): FetchHandler {
  return async function handle(request: Request): Promise<Response> {
    const config: ServiceConfig = { ...loadConfig(), ...configOverride };
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    try {
      if (request.method === "GET") {
        if (path === "/v1/health") return json({ ok: true });
        if (path === "/v1/info") return handleInfo(config);
        if (path === "/v1/policy") {
          return new Response(new Uint8Array(moderationPolicyBytes()), {
            status: 200,
            headers: {
              "content-type": "text/markdown; charset=utf-8",
              "cache-control": "public, max-age=300",
              ...CORS_HEADERS,
            },
          });
        }
        if (path === "/openapi.json") return json(openApiDocument());
        if (path === "/" ) return handleInfo(config);
        return errorJson(404, `Unknown path ${path}. See GET /v1/info for the endpoint list.`);
      }

      if (request.method === "POST") {
        const gate = await gatePost(config, request);
        if (gate) return gate;
        if (path === "/v1/moderation/listings") return await handleListings(config, request);
        if (path === "/v1/moderation/tasks") return await handleTasks(config, request);
        if (path === "/api/task-moderation/attest") return await handleCompatAttest(config, request);
        return errorJson(404, `Unknown path ${path}. See GET /v1/info for the endpoint list.`);
      }

      return errorJson(405, "Method not allowed.");
    } catch (error) {
      return attestErrorResponse(error);
    }
  };
}

export type { ModerationResult };
