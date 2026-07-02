# AgenC Moderation API

Publicly callable + self-hostable **moderation attestation service** for the
[AgenC marketplace protocol](https://github.com/tetsuo-ai/agenc-protocol)
(Solana program `HJsZ53Zb27b8QMRbQpuDngE44AdwCGxvEZr61Zmxw1xK`).

The on-chain publish/hire gates require a moderation attestation
(`TaskModeration` / `ListingModeration` PDA) before a task's job spec can be
pinned or a listing hired. This service is the open implementation of the
attestor that records them:

1. you POST a listing/task + its job-spec payload,
2. the service **fail-closed verifies** the payload hashes to exactly the
   spec hash the on-chain gate is seeded with,
3. scans it with the published deterministic policy (`GET /v1/policy` — its
   sha-256 is the `policy_hash` every attestation commits to), and
4. on a `clean` verdict signs + sends the on-chain `record_*_moderation`
   transaction and returns the signature. `suspicious`/`blocked` verdicts are
   **held** — never signed.

No kit entitlement, no account, no SDK required — plain HTTPS + JSON. In
normal integrations you never call this directly: the marketplace SDK, React
hooks, and store templates call it automatically inside hire/activation
("invisible by default"). Running your own attestor is a sovereignty option,
not a prerequisite.

## Hosted endpoints

```text
POST https://attest.agenc.ag/v1/moderation/tasks
POST https://attest.agenc.ag/v1/moderation/listings
POST https://attest.agenc.ag/api/task-moderation/attest   (compatibility shape)
GET  https://attest.agenc.ag/v1/policy
GET  https://attest.agenc.ag/v1/info
GET  https://attest.agenc.ag/openapi.json
```

Open + rate-limited (per-IP and a service-wide ceiling — every clean verdict
signs and pays a real mainnet transaction).

### Attest a task job spec (pre-pin — the external-marketplace flow)

Before your creator pins the spec with `set_task_job_spec`, request the
attestation for the exact hash you will pin:

```bash
curl -sX POST https://attest.agenc.ag/v1/moderation/tasks \
  -H 'content-type: application/json' \
  -d '{
    "task": "<TASK_PDA>",
    "jobSpecHash": "<64-hex canonical payload hash>",
    "spec": { "kind": "agenc.marketplace.jobSpec", "title": "...", ... }
  }'
```

Response (`clean`):

```json
{
  "ok": true,
  "attested": true,
  "verdict": "clean",
  "riskScore": 0,
  "specHash": "<64-hex>",
  "attestation": { "signature": "<tx>", "recordedAt": "…", "expiresAt": "…" },
  "policyHash": "<64-hex>"
}
```

`jobSpecHash` is the `json-stable-v1` canonical-JSON sha-256 of the payload —
compute it with `values.canonicalJobSpecHash` from
[`@tetsuo-ai/marketplace-sdk`](https://www.npmjs.com/package/@tetsuo-ai/marketplace-sdk)
or the open c14n in
[`@tetsuo-ai/marketplace-moderation`](https://www.npmjs.com/package/@tetsuo-ai/marketplace-moderation).
A payload that does not hash to it is rejected (422) without a verdict — the
service never attests content the gate wouldn't check.

### Attest a listing

```bash
curl -sX POST https://attest.agenc.ag/v1/moderation/listings \
  -H 'content-type: application/json' \
  -d '{ "listing": "<LISTING_PDA>" }'
```

The on-chain `spec_uri` is fetched behind an SSRF guard and must hash to the
on-chain `spec_hash`; you can also pass the payload inline (`spec`).

### Store templates / kit-backend compatibility

`POST /api/task-moderation/attest` accepts the request shape used by
`create-agenc-store` stores (`store-core`'s remote attestor) and the hosted
kit backend's route, and answers `{ attested, moderation, txSignature }`.
Point `moderation.attestorEndpoint` in your store config at
`https://attest.agenc.ag/api/task-moderation/attest` — no other change needed.

## Verdicts

| Verdict      | riskScore | On-chain attestation |
| ------------ | --------- | -------------------- |
| `clean`      | 0         | recorded (status CLEAN) |
| `suspicious` | 60        | **held** — advisory only |
| `blocked`    | 100       | **held** |

The full policy (rules, scanned text surface, appeals) is the served document
at `GET /v1/policy`; its sha-256 **is** the `policy_hash` in every attestation.
Attestations expire after the deployment-disclosed TTL
(`GET /v1/info` → `attestationTtlSeconds`; the hosted deployment uses 30 days).

## Self-host your own attestor

One codebase, three ways to run it:

```bash
# npx (Node 20.18+)
MODERATION_SIGNER_SECRET='[...]' RPC_URL=https://your-rpc \
  npx @tetsuo-ai/agenc-moderation-api

# docker
docker build -t agenc-moderation-api .
docker run -p 8787:8787 \
  -e MODERATION_SIGNER_SECRET='[...]' -e RPC_URL=https://your-rpc \
  agenc-moderation-api

# vercel (this repo deploys as-is)
vercel deploy
```

Configuration is env-only — see [.env.example](.env.example). Without a
signer key the service runs in **verdict-only mode** (scans and reports, never
records).

### Whose key can sign?

The deployed program accepts attestations from **either**:

- the cluster's global `moderation_authority`
  (`ModerationConfig.moderation_authority`), or
- any wallet registered on the **moderation-attestor roster**
  (`assign_moderation_attestor`, live on mainnet since the 2026-07-02
  roster-gates upgrade). Roster attestations unlock the publish/hire gates
  exactly like the global authority's.

The service auto-detects which one your key is and attaches the roster PDA
when needed. A key that is neither is rejected up front (503) with the exact
registration it needs. To become a mainnet roster attestor, ask the moderation
authority to register your pubkey (open an issue on this repo).

### Key custody

- Generate a **dedicated keypair** for attestation — never reuse a treasury or
  upgrade key. `solana-keygen new -o attestor.json`, fund it with a little SOL
  (each attestation pays a tx fee + the moderation PDA's rent).
- Inject it via your platform's secret store (Vercel env var, docker/k8s
  secret, systemd `LoadCredential`) — never commit it, never pass it in shell
  history if avoidable.
- The service **never logs the key** and only ever signs
  `record_task_moderation` / `record_listing_moderation` with it.
- Bound abuse: keep the rate limits on (they cap how fast anyone can drain the
  key's fee balance). **On serverless (Vercel), provision Upstash
  (`KV_REST_API_URL`/`KV_REST_API_TOKEN`)** — the global ceiling is only truly
  service-wide with a shared store, and the limiter now **fails closed** (429s
  briefly) if a configured store is unreachable rather than silently degrading
  to a per-instance count that autoscaling would multiply. `GET /v1/info`
  reports the active mode (`rateLimit.mode`: `shared` vs `per-instance`).
  Single-instance self-host (docker/npx) is fine on the in-memory limiter.
- Fund the signer wallet with only a **small, bounded** SOL balance — it is the
  ultimate cap: even if every other layer were bypassed, the key can spend no
  more than it holds. Top it up deliberately, not with a large float.
- If the key is compromised: rotate (revoke the roster assignment or move the
  authority) — attestations already recorded stay valid until expiry.

### Localnet quickstart (zero → signing)

Against the agenc-protocol localnet stack:

```bash
# 1. in agenc-protocol: boot localnet with the program + a ModerationConfig
scripts/localnet-up

# 2. run the attestor pointed at it, with the localnet moderation key
MODERATION_SIGNER_SECRET="$(cat .localnet/moderation-authority.json)" \
RPC_URL=http://127.0.0.1:8899 CLUSTER_LABEL=localnet ATTESTATION_TTL_SECONDS=0 \
  npx @tetsuo-ai/agenc-moderation-api

# 3. attest a task created on localnet
curl -sX POST localhost:8787/v1/moderation/tasks -H 'content-type: application/json' \
  -d '{"task":"<TASK_PDA>","jobSpecHash":"<hex>","spec":{...}}'
```

## Verify a deployment

`GET /v1/info` discloses the signer pubkey, cluster, `policyHash`,
`scannerHash` (+ the descriptor string it hashes), and the attestation TTL.
Re-derive both hashes from this repo's `src/policy.ts` / `src/scan.ts` to
check a deployment runs the published policy.

## Development

```bash
npm install
npm run typecheck && npm test   # 37 tests: scan vectors, fail-closed hash
                                # binding, policy pin, router/gates
npm run build && npm start      # self-host on :8787
```

MIT. Part of the AgenC protocol's neutral shared services (WP-C1/WP-C2):
moderation must never be a setup step for integrators, and never a point of
central control — run your own.
