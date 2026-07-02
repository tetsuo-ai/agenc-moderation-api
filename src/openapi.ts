/**
 * The OpenAPI 3.1 document served at GET /openapi.json. Static by design —
 * regenerating at request time from types would drag a schema library into the
 * runtime; this service's surface is small enough to state exactly.
 */

import { SERVICE_NAME, SERVICE_VERSION } from "./version.js";

const moderationResult = {
  type: "object",
  required: ["ok", "attested", "verdict", "riskScore", "specHash", "attestation", "policyHash"],
  properties: {
    ok: { type: "boolean" },
    attested: {
      type: "boolean",
      description: "True when a CLEAN verdict was recorded on-chain.",
    },
    verdict: { type: "string", enum: ["clean", "suspicious", "blocked"] },
    riskScore: { type: "integer", minimum: 0, maximum: 100 },
    specHash: {
      type: "string",
      pattern: "^[0-9a-f]{64}$",
      description: "Canonical json-stable-v1 spec hash — equals the on-chain job_spec_hash.",
    },
    attestation: {
      oneOf: [
        {
          type: "object",
          required: ["signature", "recordedAt"],
          properties: {
            signature: { type: "string", description: "record_*_moderation tx signature." },
            recordedAt: { type: "string", format: "date-time" },
            expiresAt: {
              type: ["string", "null"],
              format: "date-time",
              description: "On-chain expires_at; null when this deployment disables expiry.",
            },
          },
        },
        { type: "null" },
      ],
      description: "Present only for a CLEAN verdict that was signed + confirmed; null when held.",
    },
    policyHash: {
      type: "string",
      pattern: "^[0-9a-f]{64}$",
      description: "sha256 of GET /v1/policy bytes — the on-chain policy_hash committed to.",
    },
  },
} as const;

const errorShape = {
  type: "object",
  required: ["ok", "error"],
  properties: {
    ok: { type: "boolean", enum: [false] },
    error: { type: "string" },
    retryable: { type: "boolean" },
    retryAfterSeconds: { type: "integer" },
  },
} as const;

export function openApiDocument(): Record<string, unknown> {
  return {
    openapi: "3.1.0",
    info: {
      title: "AgenC Public Moderation API",
      version: SERVICE_VERSION,
      description:
        "Publicly callable moderation attestation for the AgenC marketplace protocol. " +
        "Scans job-spec payloads by the published deterministic policy and, on a clean " +
        "verdict, records the on-chain ListingModeration/TaskModeration attestation the " +
        "publish/hire gates consume. Not kit-entitlement gated. Source: " +
        `github.com/tetsuo-ai/${SERVICE_NAME}.`,
      license: { name: "MIT" },
    },
    paths: {
      "/v1/moderation/listings": {
        post: {
          summary: "Moderate + attest a service listing",
          description:
            "Reads the on-chain ServiceListing spec_hash, resolves the payload (inline spec " +
            "> specUri > on-chain spec_uri), fail-closed hash-matches it, scans, and on a " +
            "clean verdict records record_listing_moderation.",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["listing"],
                  properties: {
                    listing: { type: "string", description: "ServiceListing PDA (base58)." },
                    spec: { type: "object", description: "Inline job-spec envelope or payload." },
                    specUri: { type: "string", description: "https URL of the hosted spec." },
                  },
                },
              },
            },
          },
          responses: {
            "200": { description: "Verdict (and attestation when clean).", content: { "application/json": { schema: moderationResult } } },
            "400": { description: "Malformed request.", content: { "application/json": { schema: errorShape } } },
            "404": { description: "Listing not found on-chain.", content: { "application/json": { schema: errorShape } } },
            "422": { description: "Spec does not hash to the on-chain spec_hash.", content: { "application/json": { schema: errorShape } } },
            "429": { description: "Rate limited.", content: { "application/json": { schema: errorShape } } },
            "503": { description: "No signer configured / signer not authorized on this cluster.", content: { "application/json": { schema: errorShape } } },
          },
        },
      },
      "/v1/moderation/tasks": {
        post: {
          summary: "Moderate + attest a task job spec (pre-pin or post-pin)",
          description:
            "PRE-PIN (external marketplaces): provide jobSpecHash plus the spec inline or by " +
            "URI; the TaskModeration record is created for the hash you will pin via " +
            "set_task_job_spec. POST-PIN: omit them and the pinned TaskJobSpec is read " +
            "from chain.",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["task"],
                  properties: {
                    task: { type: "string", description: "Task PDA (base58)." },
                    jobSpecHash: { type: "string", pattern: "^[0-9a-f]{64}$" },
                    spec: { type: "object" },
                    specUri: { type: "string" },
                  },
                },
              },
            },
          },
          responses: {
            "200": { description: "Verdict (and attestation when clean).", content: { "application/json": { schema: moderationResult } } },
            "400": { description: "Malformed request.", content: { "application/json": { schema: errorShape } } },
            "404": { description: "Task not found on-chain.", content: { "application/json": { schema: errorShape } } },
            "409": { description: "No job spec pinned and none provided.", content: { "application/json": { schema: errorShape } } },
            "422": { description: "Spec does not hash to the expected job_spec_hash.", content: { "application/json": { schema: errorShape } } },
            "429": { description: "Rate limited.", content: { "application/json": { schema: errorShape } } },
            "503": { description: "No signer configured / signer not authorized on this cluster.", content: { "application/json": { schema: errorShape } } },
          },
        },
      },
      "/api/task-moderation/attest": {
        post: {
          summary: "Compatibility task attest (store-core / kit-backend request shape)",
          description:
            "Drop-in endpoint for callers of the hosted kit backend's attest route: accepts " +
            "{ taskPda, jobSpecHash, jobSpec | text, ... } and responds with " +
            "{ attested, moderation, txSignature }. No kit entitlement headers required.",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["taskPda", "jobSpecHash"],
                  properties: {
                    taskPda: { type: "string" },
                    jobSpecHash: { type: "string", pattern: "^[0-9a-f]{64}$" },
                    jobSpec: { type: "object" },
                    jobSpecUri: { type: "string" },
                    jobSpecCanonicalJson: { type: "string" },
                    text: { type: "string" },
                  },
                },
              },
            },
          },
          responses: {
            "200": {
              description: "Kit-backend-shaped result.",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["ok", "attested", "moderation", "txSignature"],
                    properties: {
                      ok: { type: "boolean" },
                      attested: { type: "boolean" },
                      moderation: { type: "object" },
                      txSignature: { type: ["string", "null"] },
                    },
                  },
                },
              },
            },
            "4XX": { description: "Rejections (same statuses as /v1/moderation/tasks).", content: { "application/json": { schema: errorShape } } },
          },
        },
      },
      "/v1/policy": {
        get: {
          summary: "The exact policy document bytes (sha256 == on-chain policy_hash)",
          responses: { "200": { description: "Markdown.", content: { "text/markdown": {} } } },
        },
      },
      "/v1/info": {
        get: {
          summary: "Service identity: signer pubkey, cluster, policy/scanner hashes, TTL",
          responses: { "200": { description: "Info.", content: { "application/json": {} } } },
        },
      },
      "/v1/health": {
        get: { summary: "Liveness", responses: { "200": { description: "OK." } } },
      },
    },
    components: {
      securitySchemes: {
        bearerKey: {
          type: "http",
          scheme: "bearer",
          description:
            "Only enforced when the deployment configures ATTEST_API_KEYS; the public " +
            "hosted deployment is open + rate-limited.",
        },
      },
    },
  };
}
