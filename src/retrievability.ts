/** Hash-bound retrievability. Optional registry pins require creator auth and operator token. */

import { createHash } from "node:crypto";
import { type TransactionSigner } from "@solana/kit";
import { values } from "@tetsuo-ai/marketplace-sdk";
import { fetchJobSpecBody } from "./ssrf-fetch.js";
import { SpecNotRetrievableError } from "./errors.js";
import { SERVICE_VERSION } from "./version.js";

/** The official marketplace job-spec registry (operator-overridable). */
export const DEFAULT_JOB_SPEC_REGISTRY_URL = "https://marketplace.agenc.tech";

const REGISTRY_PATH = "/api/job-specs";
const UPLOAD_TICKET_PATH = "/api/job-spec-upload-tickets";
const REGISTRY_TIMEOUT_MS = 10_000;
const MAX_REGISTRY_RESPONSE_BYTES = 1024 * 1024;
const HASH_RE = /^[0-9a-f]{64}$/;
const SAFE_HEADER_NAME_RE = /^[a-z0-9-]{1,128}$/i;

/** How retrievability was established for an attested spec. */
export interface SpecRetrievability {
  retrievable: true;
  /** True when THIS service published the spec to the registry itself. */
  pinned: boolean;
  /** https URL where the exact spec content is retrievable. */
  specRegistryUri: string;
}

/** Test seams — production callers omit this and get real network. */
export interface RetrievabilityDeps {
  /** Used for the operator-configured registry base (trusted). */
  fetchImpl?: typeof fetch;
  /** Used for caller/on-chain URIs (untrusted → SSRF-guarded by default). */
  fetchSpecBody?: (uri: string) => Promise<{ text: string; sha256: string }>;
}

/** Unwrap a job-spec envelope to its payload; a bare payload passes through. */
export function unwrapPayload(document: Record<string, unknown>): Record<string, unknown> {
  const inner = document.payload;
  return inner && typeof inner === "object" && !Array.isArray(inner)
    ? (inner as Record<string, unknown>)
    : document;
}

/**
 * Parse + vet the operator-configured registry base. https in production;
 * http is tolerated so self-hosters can point localnet/dev deployments at a
 * local registry (the base is trusted operator config, never request input).
 */
function parseRegistryBase(registryUrl: string): URL {
  const url = new URL(registryUrl);
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Job-spec registry URL must use https:// (or http:// for local dev)");
  }
  if (url.username || url.password) {
    throw new Error("Job-spec registry URL must not contain credentials");
  }
  return url;
}

/** Content-addressed registry object URL for a spec hash (kit URL semantics). */
export function jobSpecRegistryObjectUrl(registryUrl: string, hashHex: string): string {
  const hash = hashHex.toLowerCase();
  if (!HASH_RE.test(hash)) throw new Error("jobSpecHash must be 64 hex chars.");
  const url = parseRegistryBase(registryUrl);
  const trimmedPath = url.pathname.replace(/\/+$/, "");
  url.pathname = `${trimmedPath && trimmedPath !== "/" ? trimmedPath : REGISTRY_PATH}/${hash}`;
  url.search = "";
  url.hash = "";
  return url.toString();
}

/** Upload-ticket minting URL for a registry base (kit URL semantics). */
export function jobSpecUploadTicketUrl(registryUrl: string): string {
  const url = parseRegistryBase(registryUrl);
  const trimmedPath = url.pathname.replace(/\/+$/, "");
  if (trimmedPath.endsWith(REGISTRY_PATH)) {
    url.pathname = `${trimmedPath.slice(0, -REGISTRY_PATH.length)}${UPLOAD_TICKET_PATH}`;
  } else if (!trimmedPath || trimmedPath === "/") {
    url.pathname = UPLOAD_TICKET_PATH;
  } else {
    url.pathname = `${trimmedPath}/job-spec-upload-tickets`;
  }
  url.search = "";
  url.hash = "";
  return url.toString();
}

/**
 * Kit-metadata headers for hosted-entitlement observation on registry writes
 * (schema-valid so an `enforce`-mode registry still accepts the service).
 */
function hostedEntitlementHeaders(): Record<string, string> {
  const platform =
    process.platform === "darwin" ? "macos" : process.platform === "win32" ? "windows" : "linux";
  return {
    "x-agenc-install-id": "agenc-moderation-api-pin",
    "x-agenc-distribution": "package-or-source",
    "x-agenc-version": SERVICE_VERSION,
    "x-agenc-channel": "stable",
    "x-agenc-platform": platform,
    "x-agenc-arch": process.arch === "arm64" ? "arm64" : "x64",
  };
}

/**
 * Read a (trusted-base) registry response body with a hard byte cap. The body
 * is STREAMED and aborted the moment the cap is crossed — a missing or lying
 * Content-Length cannot buffer an unbounded body into memory first.
 */
async function readRegistryBody(response: Response): Promise<string> {
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (declared > MAX_REGISTRY_RESPONSE_BYTES) {
    throw new Error("Registry response exceeds the size cap");
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > MAX_REGISTRY_RESPONSE_BYTES) {
      await reader.cancel().catch(() => {});
      throw new Error("Registry response exceeds the size cap");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Does served content bind to the target hash? Accepts the SAME two bindings
 * the attest core accepts: sha256(raw served bytes) == target (legacy
 * content-addressed), or canonical json-stable-v1 payload hash == target
 * (the registry envelope / kit binding).
 */
async function contentMatchesHash(text: string, target: string): Promise<boolean> {
  if (createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex") === target) {
    return true;
  }
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch {
    return false;
  }
  if (!document || typeof document !== "object" || Array.isArray(document)) return false;
  const payload = unwrapPayload(document as Record<string, unknown>);
  try {
    return (await values.canonicalJobSpecHash(payload)).hex.toLowerCase() === target;
  } catch {
    return false;
  }
}

/**
 * Path 3: publish the payload to the registry ourselves. Only possible when
 * the declared hash IS the canonical json-stable-v1 payload hash (the registry
 * is canonical-content-addressed), and the payload passes the registry's
 * public job-spec envelope schema server-side.
 */
async function tryPinToRegistry(params: {
  registryUrl: string;
  registryToken: string | null;
  targetHashHex: string;
  payload: Record<string, unknown>;
  moderator: TransactionSigner | null;
  fetchImpl: typeof fetch;
}): Promise<SpecRetrievability | { failed: string }> {
  let canonicalHex: string;
  try {
    canonicalHex = (await values.canonicalJobSpecHash(params.payload)).hex.toLowerCase();
  } catch {
    return { failed: "pin skipped: the payload is not JSON-canonicalizable (json-stable-v1)" };
  }
  if (canonicalHex !== params.targetHashHex) {
    return {
      failed:
        "pin skipped: the declared hash is a raw-bytes hash, not the canonical payload hash — " +
        "the registry hosts canonical content only, so host the exact bytes at an https URL instead",
    };
  }

  const objectUrl = jobSpecRegistryObjectUrl(params.registryUrl, params.targetHashHex);
  // The exact envelope shape the registry's publicJobSpecEnvelopeSchema
  // requires and the kit publishes: payload + integrity.payloadHash +
  // integrity.uri (the https registry URL ending in /<hash>).
  const envelope = {
    schemaVersion: 1,
    kind: "agenc.marketplace.jobSpecEnvelope",
    integrity: {
      algorithm: "sha256",
      canonicalization: "json-stable-v1",
      payloadHash: params.targetHashHex,
      uri: objectUrl,
    },
    payload: params.payload,
  };

  const headers: Record<string, string> = {
    "content-type": "application/json; charset=utf-8",
    ...hostedEntitlementHeaders(),
  };
  if (!params.registryToken) return { failed: 'Operator token required' };
  headers.authorization = `Bearer ${params.registryToken}`;

  let response: Response;
  try {
    response = await params.fetchImpl(objectUrl, {
      method: "PUT",
      redirect: "manual",
      headers,
      body: JSON.stringify(envelope),
      signal: AbortSignal.timeout(REGISTRY_TIMEOUT_MS),
    });
  } catch {
    return { failed: "the registry PUT was unreachable" };
  }
  let body: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(await readRegistryBody(response));
    body = parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    body = {};
  }
  if (!response.ok) {
    return { failed: `the registry refused the pin (HTTP ${response.status})` };
  }
  const echoedHash =
    typeof body.jobSpecHash === "string"
      ? body.jobSpecHash.toLowerCase()
      : typeof body.hash === "string"
        ? body.hash.toLowerCase()
        : "";
  if (echoedHash !== params.targetHashHex) {
    return { failed: "the registry pin response echoed a mismatched hash" };
  }
  return { retrievable: true, pinned: true, specRegistryUri: objectUrl };
}

export interface EnsureSpecRetrievableParams {
  pinEnabled?: boolean;
  authenticatedCreator?: boolean;
  /** Registry base URL (operator-configured, trusted). */
  registryUrl: string;
  /** Operator registry write token, when provisioned (else wallet tickets). */
  registryToken: string | null;
  /** The hash the attestation binds to, lowercase hex. */
  targetHashHex: string;
  /** The exact hash-verified payload that was scanned. */
  payload: Record<string, unknown>;
  /** Caller/on-chain URIs worth checking (non-https entries are skipped). */
  candidateUris?: readonly (string | undefined)[];
  /**
   * Set when the payload was ALREADY resolved by fetching this https URI and
   * hash-verifying it (specUri / post-pin flows) — retrievability is proven
   * by construction, no extra network is spent.
   */
  resolvedFromUri?: string | undefined;
  /** The loaded moderation signer (for wallet-scoped upload tickets). */
  moderator: TransactionSigner | null;
  /** What to call the spec in errors ("task spec" / "listing spec"). */
  what: string;
}

/**
 * Establish that the exact content behind `targetHashHex` is retrievable,
 * pinning it to the registry when the caller gave us the bytes and nothing
 * hosts them yet. @throws SpecNotRetrievableError (fail-closed) otherwise.
 */
export async function ensureSpecRetrievable(
  params: EnsureSpecRetrievableParams,
  deps: RetrievabilityDeps = {},
): Promise<SpecRetrievability> {
  const target = params.targetHashHex.toLowerCase();
  const fetchImpl = deps.fetchImpl ?? fetch;
  const fetchSpec = deps.fetchSpecBody ?? fetchJobSpecBody;

  // Proven by construction: the payload was just fetched from this URI and
  // fail-closed hash-matched by the attest core.
  if (params.resolvedFromUri) {
    return { retrievable: true, pinned: false, specRegistryUri: params.resolvedFromUri };
  }

  const failures: string[] = [];

  // 1. Already retrievable at the registry.
  const objectUrl = jobSpecRegistryObjectUrl(params.registryUrl, target);
  try {
    const response = await fetchImpl(objectUrl, {
      method: "GET",
      redirect: "manual",
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(REGISTRY_TIMEOUT_MS),
    });
    if (response.status === 200) {
      if (await contentMatchesHash(await readRegistryBody(response), target)) {
        return { retrievable: true, pinned: false, specRegistryUri: objectUrl };
      }
      failures.push("the registry object exists but does not hash-match the spec");
    } else {
      failures.push(`registry GET returned ${response.status}`);
    }
  } catch {
    failures.push("registry GET failed");
  }

  // 2. Retrievable at the caller's (or on-chain) https URI — untrusted input,
  //    fetched through the SSRF guard.
  const candidates = [...new Set(params.candidateUris ?? [])].filter(
    (uri): uri is string => typeof uri === "string" && /^https:\/\//i.test(uri.trim()),
  );
  for (const uri of candidates) {
    try {
      const body = await fetchSpec(uri.trim());
      if (body.sha256.toLowerCase() === target || (await contentMatchesHash(body.text, target))) {
        return { retrievable: true, pinned: false, specRegistryUri: uri.trim() };
      }
      failures.push(`${uri} serves content that does not hash-match`);
    } catch (error) {
      failures.push(`${uri} was not fetchable (${error instanceof Error ? error.message : "error"})`);
    }
  }

  if (!params.pinEnabled || !params.authenticatedCreator || !params.registryToken) {
    throw new SpecNotRetrievableError('SPEC_NOT_RETRIEVABLE: pinning disabled or unauthorized.');
  }
  // 3. Pin it ourselves — the caller handed us the payload; host it for them.
  const pin = await tryPinToRegistry({
    registryUrl: params.registryUrl,
    registryToken: params.registryToken,
    targetHashHex: target,
    payload: params.payload,
    moderator: params.moderator,
    fetchImpl,
  });
  if (!("failed" in pin)) return pin;
  failures.push(pin.failed);

  throw new SpecNotRetrievableError(
    `SPEC_NOT_RETRIEVABLE: no retrievable copy of the ${params.what} (hash ${target}) exists, ` +
      "so attesting would bless content workers can never read. Host the exact spec at the " +
      `public registry (${objectUrl}; kit: \`job-spec publish\`) or at any public https URL ` +
      "passed as specUri, or include the full spec payload so this service can pin it for you, " +
      `then retry. Details: ${failures.join("; ")}.`,
  );
}
