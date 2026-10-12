# AgenC Desktop attestor — queued repository intake and deliverable review

Revision 5 task intake with creator binding, a durable SQLite journal, creator
quotas, and V-signed off-chain verdicts. AgenC is the only attestor. Its roster key
R partially signs payment transactions; the task creator co-signs and submits
them. The service never submits Solana transactions. Repository screening uses
signed worker reports and independent signer checks. Deliverable reviews stay
off-chain and require no payment. No program upgrade is required.

## HTTP contract

- `POST /v1/moderation/tasks`: `{task, jobSpecHash, spec?, specUri?, creatorAuthorization?, preflightOnly?}`.
- `POST /api/task-moderation/attest`: accepts `{taskPda, jobSpecHash, jobSpec?, jobSpecCanonicalJson?, text?, jobSpecUri?, creatorAuthorization?, preflightOnly?}`.
- `GET /v1/attestations/:task/:hash`: persisted, unexpired signed result.
- `POST /v1/moderation/deliverables`: `{task, submissionPda, artifactSha256}`.
- `GET /v1/deliverable-reviews/:task/:submission/:artifact`: stored deliverable verdict.
- `GET /v1/keys`: offline-root signed key manifest.
- `GET /v1/policy`, `/v1/info`, `/v1/health`, `/openapi.json`.

Desktop posts `{task, jobSpecHash, specUri, spec}`. A canonical payload with
`custom.github` checks creator binding, Open/unclaimed task, pinned hash, one live
hash, quotas, outstanding capacity and roster/key availability, then atomically
queues a `repo-intake` job. The first POST returns **202**:

```json
{"ok":true,"moderator":"<R>","attested":false,"pending":true,"jobId":"<uuid>","retryAfterSeconds":5,"attestation":null}
```

Repeat POST after five seconds. GET returns **404** until the worker result has
been independently checked and a final verdict is stored. GET does not start or
resume work. A CLEAN verdict returns **200** with a payment offer, for example:

```json
{
  "ok": true,
  "moderator": "<R>",
  "attested": false,
  "verdict": "clean",
  "attestation": null,
  "transaction": "<base64 partially signed Solana wire transaction>",
  "lastValidBlockHeight": 123456,
  "priceLamports": 2519520,
  "rentLamports": 2519520,
  "serviceFeeLamports": 0,
  "recordPda": "<TaskModeration PDA>",
  "signedVerdict": {
    "body": {
      "kind": "task-intake",
      "verdict": "clean",
      "creator": "<creator>",
      "payment": {"recordPda": "<TaskModeration PDA>", "priceLamports": 2519520, "payer": "<creator>"},
      "record": {"moderator": "<R>", "pda": "<TaskModeration PDA>", "txSignature": null}
    },
    "signature": "<V Ed25519 signature in hex>"
  }
}
```

The example abbreviates the signed context, repo, checks and time fields. Repo
ID is numeric; `allowedPathsHash` and `testCommandHash` are SHA-256 of canonical
JSON values. Non-repository intake can return its offer immediately with **200**.

Desktop verifies the V signature and key manifest, independently reads the Task
creator, and validates the transaction against the signed `payment` and `record`
bindings. The transaction uses that creator as fee payer and has exactly two
instructions, in this order (no compute-budget instructions or address tables):

1. SystemProgram transfer from creator to R of `rentLamports + serviceFeeLamports`.
2. `record_task_moderation` for the signed task/hash, CLEAN status, risk score,
   policy/scanner hashes and expiry, with R as signer and program rent payer.

Desktop checks the record PDA, instruction accounts/data, total price, creator
fee payer, valid R signature and absence of other instructions. It adds the
creator signature **without modifying the message**, sends the transaction from
its own wallet/RPC, and confirms before `lastValidBlockHeight`. The creator pays
both the transfer and network fees. Rent comes from
`getMinimumBalanceForRentExemption(getTaskModerationSize())`; revision 5 currently
needs 2,519,520 lamports. `ATTESTATION_SERVICE_FEE_LAMPORTS` defaults to **0**.
R receives rent before the program debits it, and never pays network fees: its
balance is unchanged with a zero service fee, or increases by the service fee.
Instruction failure rolls back the transfer and record creation atomically;
the creator still pays the network fee. Later `close_task` returns record rent
to **R**, as required by the unchanged program; it does not refund the creator.

After confirmation, GET `/v1/attestations/:task/:hash` returns **200** with
`attested:true`, `attestation.signature`, and a V-signed `record.txSignature`.
The signature is resolved from confirmed PDA history and verified against the
actual record instruction. There is no `transaction` or `lastValidBlockHeight`
once paid. A valid record that already exists also returns no payment offer.
The RPC must provide confirmed transaction history for receipt lookup.
GET reuses one chain read per stored attestation for five seconds, so a new
payment can take up to five seconds to show.

While a blockhash is live, repeat POST returns the identical stored offer.
After blockheight expiry, repeat POST produces a fresh R-partially-signed
transaction for the **same V-signed verdict, price and record expiry**, without
another quota admission. Reissues are subject to POST rate limits. A rent
increase beyond the originally quoted rent refuses reissue rather than exposing
R to a debit. A new verdict after verdict expiry requires fresh intake; a live
task cannot acquire a second hash. Hold/reject verdicts return **200** with signed
reasons, `attestation:null`, `payment:null`, and no transaction.

Repository preflight returns **200**, `preflightOnly:true`, `wouldAttest:false`;
it cannot predict a worker review. Repository jobs require the canonical SDK
payload hash; legacy raw-text hashes remain supported for other intake.

For a deliverable, Desktop posts exactly:

```json
{"task":"<task PDA>","submissionPda":"<submission PDA>","artifactSha256":"<64 lowercase hex>"}
```

The task must be Open, InProgress or PendingValidation with the same pinned spec
and a clean, unexpired stored repository intake. The signer independently reads
the submission and claim, derives the submission PDA from its claim, checks
claim task/worker ownership, requires submission status Submitted, and binds
`artifactSha256` to the submission's 32-byte **proofHash**. The content-addressed
artifact uses the phase 2 format below. New review: **202**
`{ok:true,moderator:null,attested:false,pending:true,jobId,retryAfterSeconds:5}`.
Ready review: **200**
`{ok:true,moderator:"<R>",attested:false,verdict,attestation:null,signedVerdict:{body,signature}}`.
The body is `kind:"deliverable-review",scope:"repository"`, bound to submission,
artifact, accepted intake hash, manifest, resulting tree and tests. Failing
reviews also store signed reasons. Deliverable GET is **404** while pending,
**200** once stored. Reviews cannot outlive their accepted intake. Each distinct
submission/artifact consumes creator scanner quota; retries consume none.

Errors use `{ok:false,moderator:null,error:"Request could not be completed.",logId}`:
**400** malformed input or JSON depth limit, **401** missing configured Desktop API key, **403**
creator/worker authentication failure, **404** missing task/submission/result,
**409** task/hash/submission/lease conflicts, changed policy, unavailable spec, or a
`specUri` that differs from the one the intake was opened with,
**413** body size limit, **422** hash mismatch or invalid GitHub spec, **429**
IP/creator quota or outstanding-transaction cap, **502** upstream/recheck/chain failure, **503**
unavailable R/V/worker/roster or invalid payment configuration. Spec retrievability errors also carry
`code:"SPEC_NOT_RETRIEVABLE",retryable:true`. IP 429 includes `retryAfterSeconds`
and a `Retry-After` header. GET routes other than health, policy and
`/openapi.json` have their own limits: `RATE_LIMIT_GET_PER_IP` (default 60) and
`RATE_LIMIT_GET_GLOBAL` (default 600) per window. See `/openapi.json` for request/response schemas.

Listing writes return 410. POST responses have no CORS headers. Compat returns
`moderation.status` and `verdict` as `clean`, `suspicious`, or `blocked`, and always
includes `moderator`. `preflightOnly:true` never signs any message or transaction,
pays rent, consumes a nonce, or pins; it returns `attested:false`, `preflightOnly:true`
and `wouldAttest`. A true `wouldAttest` means the scanner and task binding pass
with R configured; quota, outstanding-capacity, custody and retrievability checks still apply at intake.

Tasks must exist and be Open with `currentWorkers=0` and `completions=0`. Binding
requires `description[0..32] == jobSpecHash`, or creator authorization. A different
pinned TaskJobSpec hash is refused. Revision 5 listing hires use the second half
of description for their task-specific commitment; those creators must explicitly
authorize intake. Hash resolution preserves the SDK canonical payload binding and
legacy SHA-256 of exact raw bytes. When text is supplied, those bytes determine
the scanned content rather than any separately supplied object.

`creatorAuthorization` is `{issuedAt, nonce, signature}`. Nonce is 16–64 bytes as
lowercase hex; signature is 64-byte Ed25519 lowercase hex. `issuedAt` is canonical
ISO UTC, at most five minutes old and at most 30 seconds ahead. Sign these UTF-8
bytes with the task's creator wallet, with no trailing newline:

```text
AgenC attestation request v1
creator=<pubkey>
task=<pda>
jobSpecHash=<lowercase hex>
issuedAt=<iso>
nonce=<lowercase hex>
```

A verified authorization nonce is single use even if later checks refuse intake.
For an unexpired admitted intake, the exact originally accepted
authorization can be reused, including after its initial five-minute window;
that durable authorization stays bound to the same task, hash and creator. Other
requests require a fresh authorization, or the commitment-bound path.

## Verdicts and offline keys

R is the AgenC on-chain roster key and program rent payer; V is a separate Ed25519 verdict key. Provision
R as a Solana 64-byte JSON keypair file via `MODERATION_SIGNER_SECRET_FILE` and V
as PKCS8 PEM via `VERDICT_KEY_FILE`. Both work with systemd credentials. Production
refuses `MODERATION_SIGNER_SECRET`, `MODERATION_AUTHORITY_SECRET`, and
`VERDICT_KEY_SECRET` environment secrets. Startup fails if required keys or the
manifest are invalid. The service never loads an offline root private key.

`KEY_MANIFEST_FILE` contains `{body,signature}`. `ROOT_PUBLIC_KEY` is the trusted
base58 root public key. The body has this shape:

```json
{
  "v": 1,
  "issuedAt": "2026-10-11T00:00:00.000Z",
  "expiresAt": "2027-01-01T00:00:00.000Z",
  "keys": [{
    "keyId": "desktop-V1",
    "purpose": "verdict",
    "publicKey": "<V base58 public key>",
    "notBefore": "2026-10-11T00:00:00.000Z",
    "notAfter": "2027-01-01T00:00:00.000Z"
  }]
}
```

On an offline machine, sign `0xff || "agenc-desktop-keys/v1" || 0x00 ||
canonicalJson(body)` with the root key; put its lowercase hex Ed25519 signature
in the envelope. Canonical JSON sorts object keys recursively, preserves array
order, emits compact JSON and UTF-8. Deploy only that envelope and root public
key. V must be a currently valid `purpose:verdict` manifest entry and differ from R.
Rotate V by provisioning a new offline-signed manifest and credential; retain
historical public keys for verification for at least the 72-hour verdict TTL.

`signedVerdict` is `{body,signature}`, over `0xff ||
"agenc-desktop-attestation/v1" || 0x00 || canonicalJson(body)`. Body fields are
`v`, `kind:task-intake`, `cluster`, `genesisHash`, `programId`, `taskPda`, `creator`,
`jobSpecHash`, `jobSpecUri`, optional `repo`, `policyHash`, `scannerHash`, `verdict`,
`riskScore`, `categories`, `reasons`, `payment:{recordPda,priceLamports,payer}`
(or null without an offer), `record:{moderator,pda,txSignature}`,
`issuedAt`, `expiresAt`, `nonce`, `keyId`. Expiry is 72 hours, capped by an existing
record's expiry when reused. Repo metadata, when present, must include `id`,
`owner`, `name`, `licenseSpdx`, 40-hex `baseCommit` and `treeSha`, 64-hex
`allowedPathsHash` and `testCommandHash`, and positive integer `maxDiffBytes`.
For `scope:repository`, these fields come from the independently rechecked worker
report and committed `custom.github` limits. General phase 1 `payload.repo`
metadata alone is a spec commitment and does not constitute repository screening.

## Persistent controls

`ATTESTATION_DB_PATH` defaults to `./data/attestations.sqlite`. Use durable local
storage, one signer service per R key, and preserve the database and WAL through
restart/upgrade. SQLite FULL synchronization and immediate transactions serialize
admissions and offer publication; concurrent builders return the stored winner.
Defaults are 20 intakes per creator per rolling day, five distinct tasks per hour,
and five outstanding creator payment slots (`CREATOR_OUTSTANDING_TRANSACTIONS`).
Queued repository jobs reserve a slot; a hold/reject verdict releases it, while
a CLEAN offer keeps it until payment is reconciled or its verdict expires.
Blockhash expiry alone keeps the slot so the same offer can be reissued. Reissues
consume no additional slot. Set a quota/cap to zero to stop new intake. IP and
global POST limits also bound reissues. See [service.env.example](deploy/service.env.example).

Task records have no spend-ledger or wallet-floor dependency. No service path
pays Solana transaction fees; R only needs a small balance for operator-managed
roster maintenance. For a nonzero service fee, retain the ordinary rent-exempt
minimum for its system wallet; a zero-to-dust wallet transition can fail Solana
runtime rent checks. This introduces no service-funded transaction fees. Legacy `SPEND_HOURLY_LAMPORTS`, `SPEND_DAILY_LAMPORTS` and
`WALLET_FLOOR_LAMPORTS` settings have no effect on task intake. Historical spend
rows remain for operator reconciliation; old
`reserved`/`pending` entries cannot be automatically replaced. Inspect their
chain state before modifying the journal. Existing signed verdicts whose policy
binding changed need operator review.

The `audit`, `admissions`, `intake_bindings`, `nonces`, `jobs`, and `intakes` tables
retain quotas, authorizations, payment offers and receipts. Restrict DB access
to the signer OS user and back it up consistently. Request failures return a
generic message and `logId`; logs store the ID and error type without request
contents or upstream error details.

Pinning defaults off. Enable only with `ENABLE_SPEC_PINNING=1`, an operator
`JOB_SPEC_REGISTRY_TOKEN`, and a valid creator-wallet authorization. A description
commitment alone never grants registry write authorization. R and V never sign
registry tickets. Existing registry objects or public HTTPS specs can satisfy
retrievability without writes.

## DigitalOcean droplet

Use Node 24 (the container pins Node 24.14.0 by digest) and a current systemd with
`LoadCredentialEncrypted` support. Build the source with `npm ci`,
`npm run typecheck`, `npm test`, and `npm run build`; copy the built release to
`/opt/agenc-attestor` owned by root. This repository provides deployment templates;
applying them is an operator action.

Use separate OS users: `agenc-api` for the nginx HTTP/API edge worker, and
`agenc-signer` for the attestor Node process. Configure nginx's main `user`
directive to `agenc-api`; the signer user owns only its credential runtime directory
and `/var/lib/agenc-attestor`. The nginx user must have no access to R, V, the DB,
or encrypted credential source files. This isolates the edge from key custody;
phase 1's trusted router and signing core share the signer process. A separate
signing daemon with an independent authorization protocol remains future work.

Provision the R JSON file and V PEM using `systemd-creds encrypt` on the droplet
into `/etc/credstore.encrypted/agenc-moderation.key` and `agenc-verdict.pem`,
then remove plaintext provisioning copies. Keep encrypted files root-only.
Install the offline-signed `keys.json` in `/etc/agenc-attestor`, copy
`deploy/service.env.example` to `/etc/agenc-attestor/service.env`, and configure
RPC, cluster and root public key. Install [agenc-attestor.service](deploy/agenc-attestor.service).
The service binds `127.0.0.1:8787`; the droplet firewall must expose only nginx
TLS and operator SSH, never port 8787.

Install [nginx.conf](deploy/nginx.conf) inside nginx's `http` context, replace the
hostname and TLS paths, and validate nginx configuration before reload. It replaces
inbound X-Forwarded-For with the socket client address, strips other IP headers,
sets request limits and a 512 KiB body cap. `TRUST_PROXY=1` is safe only with this
loopback-only listener behind the configured edge. Without it, Node uses the
socket peer address and ignores all IP headers. Allow only trusted OS users on the
host because they can access loopback.

The unit uses systemd encrypted credentials, a private state directory, no
capabilities, restricted address families, read-only system paths, protected
kernel settings and process limits. Use journalctl for `logId` correlation.
`GET /v1/health` is liveness; monitor wallet balance, pending reservations,
manifest expiry, disk space and RPC health separately.

Alternatively build `docker build -f deploy/Dockerfile .`; mount a durable `/data`,
read-only credential files and manifest, configure their file paths, and bind the
published port to loopback for nginx. The image is digest-pinned and has a
HEALTHCHECK. Never put key bytes in Docker environment variables.

## Phase 2

`worker/` is a sequential queue consumer. Jobs are `{kind:"repo-intake" |
"deliverable", taskPda, jobSpecHash, github, artifact?}`. `github` is the exact
`payload.custom.github` object from the canonical committed job spec:

```json
{
  "owner": "example", "repo": "public-repo", "license": "MIT",
  "baseCommit": "<40 lowercase hex>", "workType": "bugfix",
  "allowedPaths": ["src"], "maxDiffBytes": 100000,
  "testCommand": "npm test", "needsNetworkForInstall": true
}
```

Optional `issueUrl` must name an issue in the same GitHub repository. Allowed
paths are literal relative file/directory prefixes, never globs, `.` or `.git`.
All touched old/new paths must remain inside them. SHA values are lowercase hex.
Deliverable jobs also have `artifact:{sha256,submissionPda}`. The report signature
uses a separate `0xff || "agenc-worker-report/v1" || 0x00 || canonicalJson(body)`
domain. A report key authenticates a worker, has no verdict authority, and differs
from every V/R key. The controller holds only its report key; every scanner
container receives zero credentials. Reports expire after ten minutes; signer
replay prevention uses an atomic durable nonce guard.

The worker resolves named repos to numeric IDs, re-reads public/non-archived/
enabled metadata by ID, checks size/default branch, compares API SPDX and actual
LICENSE grant text, checks base ancestry and records the immutable tree SHA.
The allowlist is MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause and ISC. Missing,
ambiguous or inconsistent licensing rejects. The container's LICENSE bytes and
tree must match the API facts. Scans cover install hooks/config, executables,
archives/large blobs, workflow risks, unsafe paths/symlinks/case collisions,
confusable filenames in allowed paths, secrets, allowed-path existence, test
runner and agent instructions. Instruction filenames are recorded; detected
injection rejects. Non-ASCII filenames in allowed paths conservatively reject.
Each check returns `pass`, `hold` or `reject`; any rejection wins, otherwise any
hold wins. Unknown formats, quota failures and API outages never become passes.

The initial executable runner is `npm test` or `npm run <script>`, with root
package-lock/npm-shrinkwrap v2/v3, registry.npmjs.org sources and SHA-512 integrity.
Missing/other/nested/ambiguous lockfiles or other runners hold. Install hooks,
symlinks, native blobs and risky workflows hold or reject before execution.
Dependency versions (including transitive and dev dependencies) are queried
against OSV in bounded batches; advisories, partial/paginated responses and
outages hold. This support limit intentionally requires review for other
ecosystems. Tests execute only after all preceding checks pass.

Artifact registry GET `/artifacts/<sha256>` must return `{bytesBase64}` containing
the exact UTF-8 object bytes `{manifest,patchBase64}`; the outer SHA commits to
those bytes. The manifest contains `repo:{id,owner,name}`, `baseCommit`,
`headCommit`, `patchSha256`, and may contain extra provenance. The patch digest
is checked independently. The exact attested base/repo is mandatory. The worker
checks byte size, textual paths, binary/symlink hunks, sensitive changes and
secrets, then verifies `git apply --check --index`, applies it and checks the
actual staged delta and resulting tree. The head commit must be retrievable from
GitHub, descend from the base and have exactly that tree. Unpublished heads hold.
Resulting dependency additions/versions receive OSV queries. Changes to install
hooks, registry URLs, CI, git config or instruction files hold. npm installation
uses `--ignore-scripts` from the reviewed lockfile; tests have no network, with
time, memory, pids, CPU and tmpfs caps. Reports expose output hashes, not logs
containing possible secrets.

`reviewWorkerReport` in [src/repo-review.ts](src/repo-review.ts) is an internal
signer function, exported from the package. Supply a trusted context resolver
that uses phase 1 creator binding and independent task/spec/submission reads,
the worker public-key allowlist, pinned scanner digest, root-authorized intake V
keys and a durable nonce guard. It canonicalizes the declared spec itself,
verifies the report and required checks, rechecks GitHub identity/license/base/
tree and deliverable head facts, then calls the existing `signDocument` with V.
`scannerHash` commits to the actual rule source files, parser/transport/sandbox/
signer code, dependency lock, compiled JavaScript bundle, limits and worker image digest. Ship identical
read-only source and compiled releases on signer and worker. Reports from other
rules/images are refused. Worker signatures cannot serve as verdict signatures.

Repo intake yields a signed `kind:"task-intake",scope:"repository"` with repo
binding; deliverables yield `kind:"deliverable-review",scope:"repository"`
bound to `taskPda`, `submissionPda`, `artifactSha256`, manifest, resulting tree,
test result and `intakeHash`. Verdicts map to `clean`/`suspicious`/`blocked`.
Clean intake documents include the R moderation PDA/transaction after the
queue adapter records it. Held/rejected intakes and all deliverable reviews have
`record.pda:null,txSignature:null`. The HTTP adapter requires worker review for
every `custom.github` intake and cannot use general phase 1 scanning to bypass it.
`GET /v1/info` exposes the repository image and scanner commitments separately
from the general payload scanner.

Desktop must verify a deliverable-review **before** acceptance/settlement:

1. Verify the root-signed key manifest, V purpose, validity/revocation and the
   exact verdict-domain Ed25519 signature, never the worker report signature.
2. Require `v:1`, `kind:deliverable-review`, `scope:repository`, `verdict:clean`,
   valid issued/expiry times, expected cluster/genesis/program, current policy
   and scanner/image commitments, and every mandatory check passing.
3. Match task/creator/canonical jobSpecHash to independently read task/spec data;
   match submissionPda and artifactSha256 to the actual submission and downloaded
   artifact bytes. Check manifest patch digest, repo ID/owner/name and exact base.
4. Verify the accepted repository intake, its repo/tree/allowedPaths/testCommand/
   maxDiffBytes bindings and `intakeHash`; the review must not outlive the intake.
   Check head/resultTreeSha and successful, non-timeout test evidence. Never
   interpret a repository verdict as an on-chain paid record or general payload
   moderation; retain revision 5 gates and general task policy checks.

See [deploy/WORKER.md](deploy/WORKER.md) for the separate DigitalOcean worker
unit, offline compose qualification profile, nftables egress allowlist, queue
contract, required image qualification and hostname-gateway limitations. No
templates have been applied. Real-container/egress qualification, droplet deployment, R roster registration,
offline root/V ceremony and Desktop verdict consumption remain operator/client
integration work. The durable queue and trusted context adapter are implemented. Heuristic license, secret, YAML and instruction
scans cannot prove arbitrary repository code safe; compromised report keys or
container/engine vulnerabilities remain risks even for a passing report.

## Worker transport and local development

Set `WORKER_KEYS_FILE` to a signer-readable JSON map
`{"scanner-do-1":"<worker report Ed25519 base58 public key>"}` and
`WORKER_IMAGE_DIGEST=sha256:<64 hex>` on the signer. Configure the identical
image digest and `queueUrl:"https://attestor.example.com"` on the worker.
The worker binary processes one lease at a time; no Desktop API key is needed.
The signer owns the SQLite queue; the scanner never opens the signing database.

`POST /internal/worker/pull` and `POST /internal/worker/reports` take
`{body,signature}`. Body is
`{workerId,path,issuedAt,nonce,payload}`. Sign with the worker report credential
using `0xff || "agenc-worker-queue/v1" || 0x00 || canonicalJson(body)`; the path
must equal the actual endpoint, time must be within 60 seconds (30 seconds future
skew allowed), and nonce is fresh 16-byte lowercase hex. Nonces are durable.
Pull payload is `{}`. Pull returns **200**
`{moderator:null,jobId,leaseToken,leaseExpiresAt,job}` or **204** with no body.
The lease lasts 15 minutes, covering the worker's ten-minute job bound.

Report payload is `{jobId,leaseToken,report:{body,signature}}`; the inner report
uses the existing separate report domain. A report must name the leased job and
worker, match the current bundle/image, and pass signer binding/rechecks.
Acknowledgement is **200** `{moderator:null,accepted:true,jobId}` after atomic
report+replay-nonce storage. A duplicate exact report is acknowledged under a
fresh transport nonce; a different report is **409**. Forgery is **403**; missing,
expired or superseded lease is **409**. Crash recovery redelivers unfinished
leases; reviewed jobs resume through Desktop POST. Chain failures after durable
report acceptance do not discard the report or trigger another payment.

Restrict these endpoints at nginx and the droplet ingress firewall to the fixed
worker droplet IP. The public Desktop location must not provide an alternative
route to them; direct port 8787 remains loopback-only. Add the signer TLS host to
the controller's approved egress configuration. See [deploy/WORKER.md](deploy/WORKER.md)
and [deploy/nginx.conf](deploy/nginx.conf); these templates have not been applied.

Development can use `runDevelopmentWorkerOnce(attestDeps, workerDeps)` from the
package. It pulls from the same persistent queue and runs `processJob` in process;
inject a mocked `Sandbox` (clone/apply/test/close), GitHub, registry/OSV and RPC.
It is disabled under `NODE_ENV=production`. This is dependency injection, not an
automatic success report or a container daemon. The complete local examples are
[test/repo-queue.test.ts](test/repo-queue.test.ts), including payment offers and
signature verification. [test/payment-litesvm.test.ts](test/payment-litesvm.test.ts)
loads the SDK's bundled compiled `agenc_coordination.so` in LiteSVM using
throwaway keys. It executes the actual API offer after creator co-signing, checks
R's balance and exact rent, exercises failure rollback, and verifies that
`close_task` returns the rent to R. No live RPC or container daemon is used:

```sh
npm test -- --maxWorkers=2
npm run typecheck
```
