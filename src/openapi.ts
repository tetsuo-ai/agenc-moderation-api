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
      description:
        "True when a CLEAN verdict was recorded on-chain by this service. False when the " +
        "caller pays: the approval is then recorded by the transaction in `payment`.",
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
      description:
        "Present only for a CLEAN verdict this service signed + sent itself; null when held, " +
        "and null when the caller pays (see `payment`).",
    },
    moderator: {
      type: ["string", "null"],
      description:
        "The signer whose record a consumption gate must name as its `moderator`. Null in " +
        "verdict-only mode.",
    },
    payment: {
      type: "object",
      required: ["transaction", "payer", "depositLamports", "lastValidBlockHeight", "expiresAt"],
      description:
        "Present on a CLEAN verdict when the request named a `payer`. The approval is not " +
        "recorded yet: the payer signs and sends `transaction`.",
      properties: {
        transaction: {
          type: "string",
          description:
            "Base64 wire transaction signed by this service. The payer is its fee payer. For a " +
            "task (program revision 9) it holds one record_task_moderation instruction whose " +
            "last account, rent_payer, is the payer: the program takes the deposit from the " +
            "payer and returns it to the task's creator when the task is closed. For a listing " +
            "it holds a System transfer of `depositLamports` from the payer to `moderator` (left " +
            "out when that is 0) followed by one record_listing_moderation instruction.",
        },
        payer: { type: "string", description: "The wallet that pays (base58)." },
        depositLamports: {
          type: "string",
          description:
            "The deposit the new approval record takes from the payer: as its rent payer for " +
            "a task, by the transfer to this service's signer for a listing. \"0\" when the " +
            "record already exists.",
        },
        lastValidBlockHeight: {
          type: "string",
          description: "The transaction can land until the chain passes this block height.",
        },
        expiresAt: {
          type: ["string", "null"],
          format: "date-time",
          description: "When the approval itself runs out; null when expiry is disabled.",
        },
      },
    },
    policyHash: {
      type: "string",
      pattern: "^[0-9a-f]{64}$",
      description: "sha256 of GET /v1/policy bytes — the on-chain policy_hash committed to.",
    },
    retrievable: {
      type: "boolean",
      enum: [true],
      description:
        "Present only on attested results: a retrievable copy of the exact spec content " +
        "was verified (or pinned) before the attestation was recorded.",
    },
    pinned: {
      type: "boolean",
      description:
        "Present only on attested results: true when this service published the spec to " +
        "the public job-spec registry itself.",
    },
    specRegistryUri: {
      type: "string",
      description: "Present only on attested results: https URL where the spec is retrievable.",
    },
  },
} as const;

const payerProperty = {
  type: "string",
  description:
    "The wallet that pays for the approval (base58). For a task it must be the task's " +
    "creator. A CLEAN answer then carries `payment`: the approval as a transaction for this " +
    "wallet to sign and send. Required unless the deployment pays for approvals itself " +
    "(GET /v1/info → requesterPays: false).",
} as const;

const revisionRefusalDescription =
  "UNSUPPORTED_PROGRAM_REVISION (code, retryable): the program is not stamped revision 9, " +
  "the only revision this build signs for. Nothing was signed. Also: no signer configured, " +
  "or the signer is not authorized on this cluster.";

const payerRequiredResponse = {
  description:
    "This deployment does not pay for approvals and the request named no `payer`.",
  content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
} as const;

const specNotRetrievableDescription =
  "SPEC_NOT_RETRIEVABLE (code, retryable): no retrievable copy of the spec exists at the " +
  "public registry or an https specUri, and the service could not pin it. Host the spec, " +
  "then retry — attestations are never recorded for content workers cannot fetch.";

const errorShape = {
  type: "object",
  required: ["ok", "error"],
  properties: {
    ok: { type: "boolean", enum: [false] },
    error: { type: "string" },
    code: {
      type: "string",
      description:
        "Machine-readable code: SPEC_NOT_RETRIEVABLE, MODERATOR_IS_TASK_CREATOR, " +
        "MODERATOR_IS_LISTING_PROVIDER, PAYER_NOT_TASK_CREATOR, UNSUPPORTED_PROGRAM_REVISION " +
        "or CRON_SECRET_MISSING.",
    },
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
            "clean verdict records record_listing_moderation. An attestation is only " +
            "recorded after spec retrievability is established (registry, https URI, or a " +
            "service-side pin).",
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
                    payer: payerProperty,
                  },
                },
              },
            },
          },
          responses: {
            "200": { description: "Verdict (and attestation when clean).", content: { "application/json": { schema: moderationResult } } },
            "400": { description: "Malformed request.", content: { "application/json": { schema: errorShape } } },
            "402": payerRequiredResponse,
            "404": { description: "Listing not found on-chain.", content: { "application/json": { schema: errorShape } } },
            "409": { description: specNotRetrievableDescription, content: { "application/json": { schema: errorShape } } },
            "422": {
              description:
                "Spec does not hash to the on-chain spec_hash; or MODERATOR_IS_LISTING_PROVIDER: " +
                "this service's signer provides the listing (program error 6434).",
              content: { "application/json": { schema: errorShape } },
            },
            "429": { description: "Rate limited.", content: { "application/json": { schema: errorShape } } },
            "503": { description: revisionRefusalDescription, content: { "application/json": { schema: errorShape } } },
          },
        },
      },
      "/v1/moderation/tasks": {
        post: {
          summary: "Moderate + attest a task job spec (pre-pin or post-pin)",
          description:
            "PRE-PIN (external marketplaces): provide jobSpecHash plus the spec inline or by " +
            "URI; the TaskModeration record is created for the hash you will pin via " +
            "set_task_job_spec. For revision-5 listing hires, this must equal the immutable " +
            "task-specific commitment funded by hire_from_listing; legacy uncommitted hires " +
            "must be cancelled and re-hired. POST-PIN: omit them and the pinned TaskJobSpec is read " +
            "from chain. Every attestation implies retrievable content: before recording, " +
            "the service verifies the spec is fetchable at the public job-spec registry or " +
            "an https specUri, or pins the inline payload to the registry itself; otherwise " +
            "it refuses with SPEC_NOT_RETRIEVABLE (409, retryable).",
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
                    payer: payerProperty,
                  },
                },
              },
            },
          },
          responses: {
            "200": { description: "Verdict (and attestation when clean).", content: { "application/json": { schema: moderationResult } } },
            "400": { description: "Malformed request.", content: { "application/json": { schema: errorShape } } },
            "402": payerRequiredResponse,
            "404": { description: "Task not found on-chain.", content: { "application/json": { schema: errorShape } } },
            "409": {
              description: `No job spec pinned and none provided; or ${specNotRetrievableDescription}`,
              content: { "application/json": { schema: errorShape } },
            },
            "422": {
              description:
                "Spec does not hash to the expected job_spec_hash; or MODERATOR_IS_TASK_CREATOR: " +
                "this service's signer created the task (program error 6432); or " +
                "PAYER_NOT_TASK_CREATOR: `payer` is not the task's creator (6433).",
              content: { "application/json": { schema: errorShape } },
            },
            "429": { description: "Rate limited.", content: { "application/json": { schema: errorShape } } },
            "503": { description: revisionRefusalDescription, content: { "application/json": { schema: errorShape } } },
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
                    jobSpecUri: {
                      type: "string",
                      description:
                        "https URL hosting the spec — feeds the retrievability gate " +
                        "(the inline jobSpec/text still defines what gets scanned).",
                    },
                    jobSpecCanonicalJson: { type: "string" },
                    text: { type: "string" },
                    payer: payerProperty,
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
                      retrievable: {
                        type: "boolean",
                        enum: [true],
                        description: "Present only when attested — see /v1/moderation/tasks.",
                      },
                      pinned: { type: "boolean", description: "Present only when attested." },
                      specRegistryUri: { type: "string", description: "Present only when attested." },
                      moderator: {
                        type: "string",
                        description: "Present with `payment`: this service's signer.",
                      },
                      payment: moderationResult.properties.payment,
                    },
                  },
                },
              },
            },
            "4XX": { description: "Rejections (same statuses as /v1/moderation/tasks).", content: { "application/json": { schema: errorShape } } },
          },
        },
      },
      "/v1/cron/heartbeat": {
        get: {
          summary: "Operator: run the weekly moderation liveness heartbeat check",
          description:
            "Called by Vercel Cron. Off unless HEARTBEAT_ENABLED is on; then it needs " +
            "`Authorization: Bearer <CRON_SECRET>`. It sends a plain moderation_heartbeat (no " +
            "window change) only on a revision 9 program, only when this service's signer may " +
            "heartbeat, and only when the last heartbeat on chain is about a week old.",
          security: [{ cronSecret: [] }],
          responses: {
            "200": { description: "What the check did: sent, or why not.", content: { "application/json": {} } },
            "401": { description: "Missing or wrong cron secret.", content: { "application/json": { schema: errorShape } } },
            "502": { description: "The check failed (retryable).", content: { "application/json": { schema: errorShape } } },
            "503": { description: "CRON_SECRET_MISSING: the job is on but no secret is set.", content: { "application/json": { schema: errorShape } } },
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
      schemas: { Error: errorShape },
      securitySchemes: {
        bearerKey: {
          type: "http",
          scheme: "bearer",
          description:
            "Only enforced when the deployment configures ATTEST_API_KEYS; the public " +
            "hosted deployment is open + rate-limited.",
        },
        cronSecret: {
          type: "http",
          scheme: "bearer",
          description: "The deployment's CRON_SECRET (operator heartbeat trigger only).",
        },
      },
    },
  };
}
