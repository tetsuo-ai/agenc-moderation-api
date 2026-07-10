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
  "policyHash": "<64-hex>",
  "retrievable": true,
  "pinned": false,
  "specRegistryUri": "https://marketplace.agenc.tech/api/job-specs/<64-hex>"
}
```

`jobSpecHash` is the `json-stable-v1` canonical-JSON sha-256 of the payload —
compute it with `values.canonicalJobSpecHash` from
[`@tetsuo-ai/marketplace-sdk`](https://www.npmjs.com/package/@tetsuo-ai/marketplace-sdk)
or the open c14n in
[`@tetsuo-ai/marketplace-moderation`](https://www.npmjs.com/package/@tetsuo-ai/marketplace-moderation).
A payload that does not hash to it is rejected (422) without a verdict — the
service never attests content the gate wouldn't check.

### Every attestation implies retrievable content

An attestation for a spec nobody can fetch produces a task workers can claim
but never read. Before recording ANY attestation the service therefore
establishes retrievability, by the first of:

1. **Already retrievable** — `GET <registry>/api/job-specs/<hash>` returns
   hash-matching content (`JOB_SPEC_REGISTRY_URL`, default the official
   `https://marketplace.agenc.tech` registry). The agenc.ag / kit
   `tasks create-reviewed-public` flow always publishes first, so it passes here.
2. **Retrievable at your URI** — an https `specUri` whose bytes (or canonical
   payload) hash to `jobSpecHash`, fetched behind the SSRF guard.
3. **Pinned by the service** — when you sent the full payload inline, the
   service publishes it to the registry FOR you (`PUT /api/job-specs/<hash>`,
   authorized by `JOB_SPEC_REGISTRY_TOKEN` when configured, else by a
   wallet-scoped upload ticket signed with the moderation signer key — an
   off-chain signature, no extra transaction). The response then carries
   `"pinned": true`.

If none succeed the request is refused with **HTTP 409
`{ code: "SPEC_NOT_RETRIEVABLE", retryable: true }`** and no transaction is
signed. Host the spec (registry or any public https URL) and retry. Note the
registry is canonical-content-addressed: a legacy raw-bytes hash binding
(`sha256(bytes)` ≠ canonical payload hash) cannot be pinned — host those exact
bytes at an https URL and pass it as `specUri` instead.

### Attest a listing

```bash
curl -sX POST https://attest.agenc.ag/v1/moderation/listings \
  -H 'content-type: application/json' \
  -d '{ "listing": "<LISTING_PDA>" }'
```

The on-chain `spec_uri` is fetched behind an SSRF guard and must hash to the
on-chain `spec_hash`; you can also pass the payload inline (`spec`). The same
retrievability gate applies: an inline listing spec is only attested once a
retrievable copy is verified or pinned.

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

**Any wallet — roster registration is permissionless.** The deployed program
accepts attestations from **either**:

- the cluster's global `moderation_authority`
  (`ModerationConfig.moderation_authority`), or
- any wallet registered on the **moderation-attestor roster**. Roster
  attestations satisfy the publish/hire gates exactly like the global
  authority's (live on mainnet since the 2026-07-02 roster-gates upgrade),
  and since the 2026-07-03 P1.2 open-roster upgrade **anyone can
  self-register** — no approval, no issue to open, no tetsuo involvement.

The service auto-detects which one your key is and attaches the roster PDA
when needed. A key that is neither is rejected up front (503) with the exact
registration it needs.

#### Register your signer on the roster (mainnet, self-service)

`register_moderation_attestor` self-registers the signing wallet by
depositing a **0.25 SOL refundable bond** (plus the roster PDA's rent, ~0.002
SOL) on its own `["moderation_attestor", <pubkey>]` PDA. The bond is an
attributable-identity deposit — it is **never confiscatable** and is refunded
in full when you exit. Build the instruction with the marketplace SDK
(`@tetsuo-ai/marketplace-sdk` ^0.8.0):

```ts
import { facade } from "@tetsuo-ai/marketplace-sdk";

// attestor: a TransactionSigner for the dedicated attestation wallet
// (the same key you set as MODERATION_SIGNER_SECRET)
const ix = await facade.registerModerationAttestor({ attestor });
// sign + send `ix` with any @solana/kit transaction pipeline; the wallet
// pays the PDA rent and the 0.25 SOL bond in the same instruction
```

Fund the wallet with the bond + rent + a small fee float first. Registering
an already-rostered wallet fails (that is the "already registered" signal).

To leave the roster: `facade.requestAttestorExit({ attestor })` — the program
rejects the key's attestations from the **moment the exit is requested** —
then, after the **7-day cooldown**, `facade.finalizeAttestorExit({ attestor })`
closes the PDA and refunds **everything** (bond + rent) to the wallet.
Re-registering later re-inits a fresh entry.

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
- If the key is compromised: rotate. For a self-registered roster key, request
  the attestor exit (`request_attestor_exit` — its attestations are rejected
  from that moment), finalize after the 7-day cooldown to recover the bond,
  and register a fresh key (registration is permissionless, so the new key is
  live immediately). For an authority-deputized key, revoke it
  (`revoke_moderation_attestor`); for the global authority, move the
  authority. Attestations already recorded stay valid until expiry.

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
npm run typecheck && npm test   # 55 tests: scan vectors, fail-closed hash
                                # binding, policy pin, router/gates
npm run build && npm start      # self-host on :8787
```

MIT. Part of the AgenC protocol's neutral shared services (WP-C1/WP-C2):
moderation must never be a setup step for integrators, and never a point of
central control — run your own.
