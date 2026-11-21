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
4. on a `clean` verdict signs the on-chain `record_*_moderation` transaction
   and hands it back for the caller to pay for and send (see
   [Who pays](#who-pays-for-an-approval)). `suspicious`/`blocked` verdicts are
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

Open + rate-limited (per-IP and a service-wide ceiling).

### Who pays for an approval

The caller does. Every new approval record holds a deposit: its rent, about
0.0018 SOL at today's rent. A service that paid it for everyone would be
drained by whoever asked most. Instead:

1. Send the wallet that will pay as `payer` with your request. For a task,
   that must be the task's creator.
2. A `clean` answer carries `payment.transaction`: one transaction, already
   signed by this service, in which `payer` is the fee payer.
3. Check it, add `payer`'s signature and send it before
   `payment.lastValidBlockHeight`. The approval exists once it lands; until
   then `attested` is `false` and `attestation` is `null`.

What the transaction holds, and where the deposit goes:

- Task approval (program revision 9): one `record_task_moderation`
  instruction and nothing else. Your wallet is its last account,
  `rent_payer`, so the program takes the deposit (`payment.depositLamports`)
  from your wallet itself, and the record notes that you paid it. When the
  finished task is closed (`close_task`), the deposit comes back to your
  wallet. Nothing goes to this service.
- Listing approval: a System transfer of the deposit from your wallet to
  `moderator`, then one `record_listing_moderation`, in which your wallet does
  not appear. The program takes the deposit from `moderator`. This deposit is
  not returned.

Either way the transaction lands whole or not at all, so you never pay for
an approval you do not get.

Check before you sign:

- the fee payer is your wallet, the message is version 0, and there are no
  address lookup tables;
- for a task: exactly one instruction, a `record_task_moderation` of program
  `HJsZ53Zb27b8QMRbQpuDngE44AdwCGxvEZr61Zmxw1xK` for your task and your hash,
  in which your wallet appears once, as its seventh and last account
  (`rent_payer`);
- for a listing: at most a System transfer from your wallet to `moderator` of
  at most the record's rent, then one `record_listing_moderation` of the same
  program for your listing and your hash, in which your wallet does not
  appear.

A record that already exists costs nothing to renew: `depositLamports` is
`"0"`, and its deposit still goes back to whoever paid it first. For a
listing the transaction then holds only the approval.

A request with no `payer` is refused with **HTTP 402**. A self-hoster who
wants their own signer to pay for every approval sets `REQUESTER_PAYS=false`;
`GET /v1/info` reports which (`requesterPays`). That signer is then the
record's rent payer, and a task record's deposit comes back to it when the
task is closed.

### What the service refuses

These are rules of program revision 9. The service checks them before it
signs anything, so you get a clear answer instead of a failed transaction.
Each answer carries a `code`.

| Status | `code` | When |
| ------ | ------ | ---- |
| 422 | `MODERATOR_IS_TASK_CREATOR` | This service's signer created the task. A creator cannot moderate its own task (program error 6432). |
| 422 | `MODERATOR_IS_LISTING_PROVIDER` | This service's signer is the listing's provider. A provider cannot moderate its own listing (6434). |
| 422 | `PAYER_NOT_TASK_CREATOR` | The `payer` for a task is not its creator. For a task, only its creator can be `payer` (6433). |
| 503 | `UNSUPPORTED_PROGRAM_REVISION` | The program is not stamped revision 9. Nothing was signed. `retryable` is `true`. |

### Program revision

This build signs for revision 9 of the program only (`GET /v1/info` →
`signingRevision`). Before it signs, it reads the program's revision stamp
(`ProtocolConfig.surface_revision`). On any other stamp it answers 503
`UNSUPPORTED_PROGRAM_REVISION` and signs nothing. The two revisions do not
mix: the revision 9 task approval sent to a revision 8 program would make
this service's signer pay the deposit, and the revision 8 approval fails on a
revision 9 program. Switch a deployment to this build after the revision 9
stamp and before the protocol is unpaused.

### Attest a task job spec (pre-pin — the external-marketplace flow)

Before your creator pins the spec with `set_task_job_spec`, request the
attestation for the exact hash you will pin:

```bash
curl -sX POST https://attest.agenc.ag/v1/moderation/tasks \
  -H 'content-type: application/json' \
  -d '{
    "task": "<TASK_PDA>",
    "jobSpecHash": "<64-hex canonical payload hash>",
    "spec": { "kind": "agenc.marketplace.jobSpec", "title": "...", ... },
    "payer": "<THE TASK CREATOR'S WALLET>"
  }'
```

Response (`clean`):

```json
{
  "ok": true,
  "attested": false,
  "verdict": "clean",
  "riskScore": 0,
  "specHash": "<64-hex>",
  "moderator": "<this service's signer>",
  "attestation": null,
  "policyHash": "<64-hex>",
  "retrievable": true,
  "pinned": false,
  "specRegistryUri": "https://marketplace.agenc.tech/api/job-specs/<64-hex>",
  "payment": {
    "transaction": "<base64, signed by the service; sign as payer and send>",
    "payer": "<THE TASK CREATOR'S WALLET>",
    "depositLamports": "1838960",
    "lastValidBlockHeight": "…",
    "expiresAt": "…"
  }
}
```

Present `moderator` at `set_task_job_spec` once the transaction has landed.
On a deployment that pays for approvals itself (`REQUESTER_PAYS=false`) a
request without `payer` is recorded by the service: `attested` is `true` and
`attestation` is `{ "signature": "<tx>", "recordedAt": "…", "expiresAt": "…" }`.

`jobSpecHash` is the `json-stable-v1` canonical-JSON sha-256 of the payload —
compute it with `values.canonicalJobSpecHash` from
[`@tetsuo-ai/marketplace-sdk`](https://www.npmjs.com/package/@tetsuo-ai/marketplace-sdk)
or the open c14n in
[`@tetsuo-ai/marketplace-moderation`](https://www.npmjs.com/package/@tetsuo-ai/marketplace-moderation).
A payload that does not hash to it is rejected (422) without a verdict — the
service never attests content the gate wouldn't check.

For a revision-5 listing hire, use the same task-specific hash that was passed
to `hire_from_listing`. The service reads the canonical `HireRecord` and
verifies that `jobSpecHash` equals the immutable commitment stored in the
hired Task before it fetches, publishes, or signs anything. A legacy hired
task with no such commitment must be cancelled and re-hired with a current
client; direct tasks (which have no `HireRecord`) are unaffected.

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
  -d '{ "listing": "<LISTING_PDA>", "payer": "<WALLET THAT PAYS>" }'
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
`https://attest.agenc.ag/api/task-moderation/attest`. It takes `payer` like
the other endpoints (the task's creator) and then also answers `moderator`
and `payment`; a caller that sends no `payer` is refused (402) unless the
deployment pays for approvals itself.

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
# npx (Node 22.23.1+)
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
(`@tetsuo-ai/marketplace-sdk` ^0.14.0):

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

- Generate a **dedicated keypair** for attestation. Never reuse a treasury or
  upgrade key. `solana-keygen new -o attestor.json`. With callers paying (the
  default) it needs no SOL for approvals; with `REQUESTER_PAYS=false` fund it
  with a little SOL (each attestation then pays a tx fee + the moderation
  PDA's rent out of it). With the heartbeat on, keep enough for one fee a
  week (about 5,000 lamports each).
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
  -d '{"task":"<TASK_PDA>","jobSpecHash":"<hex>","spec":{...},"payer":"<WALLET>"}'
```

## Liveness heartbeat

The publish and hire gates relax to moderation-optional when nobody sends
`moderation_heartbeat` within the liveness window (90 days). A deployment
whose signer holds the moderation authority key can send it every week.

- It is off by default. Set `HEARTBEAT_ENABLED=true` to turn it on.
- It sends a plain heartbeat. It never changes the liveness window.
- It uses the revision 9 wire, which carries the `protocol_config` account.
- It sends only when the program is stamped revision 9, its signer may send
  a heartbeat (the moderation authority, the config authority or a protocol
  owner; a roster attestor may not), and the last heartbeat on chain is about
  a week old. A heartbeat from anyone else resets that clock.
- Each heartbeat costs the signer one fee, about 5,000 lamports.

How it runs:

- Self-host (npx, docker): the server checks every hour.
- Vercel: `vercel.json` calls `GET /v1/cron/heartbeat` once a day. Set
  `CRON_SECRET` in the project: Vercel Cron sends it as a bearer token, and
  the endpoint refuses any other caller. With the job on and no
  `CRON_SECRET`, the endpoint stays closed (503).

`GET /v1/info` reports `heartbeat.enabled`.

## Verify a deployment

`GET /v1/info` discloses the signer pubkey, cluster, `policyHash`,
`scannerHash` (+ the descriptor string it hashes), the attestation TTL, the
program revision it signs for (`signingRevision`) and whether the heartbeat
is on.
Re-derive both hashes from this repo's `src/policy.ts` / `src/scan.ts` to
check a deployment runs the published policy.

## Development

```bash
npm install
npm run typecheck && npm test   # scan vectors, fail-closed hash binding,
                                # policy pin, router/gates, payment shapes,
                                # heartbeat, and the program test
npm run build && npm start      # self-host on :8787
```

`test/program-litesvm.test.ts` runs this service's transactions on the real
program in LiteSVM: the SDK's bundled build, or the file named by
`AGENC_TEST_PROGRAM_SO`. With `AGENC_TEST_REVISION8_SO` set to a revision 8
build it also shows why the service signs on a revision 9 stamp only.

MIT. Part of the AgenC protocol's neutral shared services (WP-C1/WP-C2):
moderation must never be a setup step for integrators, and never a point of
central control — run your own.
