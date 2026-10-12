# Separate DigitalOcean scanner droplet

These are operator templates; nothing in phase 2 deploys them. Use a fresh Linux
droplet with a dedicated unprivileged `agenc-worker` UID, current rootless Podman
(preferred) or rootless Docker and delegated cgroup v2 limits. Do not place R, V,
Solana secrets, GitHub tokens or a root-manifest private key on this droplet.
The controller has one Ed25519 report credential; scanner containers receive no
credentials. Authorize its public key in the signer's separate worker allowlist.
It is never a `purpose:verdict` entry. Revoke it independently after compromise.

Build the same release on worker and signer, run `npm run typecheck`,
`npm test -- --maxWorkers=2`, `npm run build`, and ship `dist/`, `src/`, `worker/`,
`package.json`, `package-lock.json`, `tsconfig.json` and `tsup.config.ts` read-only under `/opt/agenc-attestor`.
Rules are hashed from their actual source bytes, compiled JavaScript bundle,
limits and the scanner image digest. Keep the source and built release together; rebuild after every source
change. The trusted scanner image needs Node, git and npm at fixed versions and
no entrypoint side effects. Build/qualify it separately, scan its SBOM, pin its
digest and pre-pull it as the worker UID; this repository intentionally supplies
no invented scanner image digest. Pulling images is outside job execution.

Provision subordinate UID/GID ranges for rootless Podman, a writable private
`/var/lib/agenc-worker` storage/config directory, `/run/user/<uid>` and a
rootless network called `agenc-fetch`. Set the unit's `ReadWritePaths` UID to
match the nftables worker UID and provision its private `/run/user/<uid>` before
startup. Ensure CPU, pids, memory, tmpfs and
network disconnect/inspect work on the chosen engine version. The unit delegates
cgroups and permits mapping helpers. Do not disable SELinux/seccomp/AppArmor.
Pin the engine and image versions in the deployment inventory.

Networking is a deployment boundary: a network named `agenc-fetch` alone does
not restrict egress. Install `worker-egress.nft` after setting the actual UID and
populate its timeout sets from **only** `worker-egress-hosts.txt` and the fixed
artifact registry host. Run the DNS refresh as a separate privileged timer, vet
every returned address, replace sets atomically and expire them with DNS TTLs.
Empty/expired sets fail closed. Retain your droplet SSH/ingress firewall.
Do not apply this template without checking rootless helper socket UIDs and
packet counters; forwarded/rootful traffic needs a separate forward-chain policy.

IP allowlists alone cannot distinguish domains on shared CDN addresses. For a
strict hostname guarantee, put the fetch network behind a dedicated TLS/SNI
egress gateway enforcing these same exact names and prohibit direct 443 egress
around it. Test private IP, DO metadata, rebinding, redirect and cross-domain
cases before accepting live jobs. OSV uses `api.osv.dev/v1/querybatch` (a read-only
POST query); no registry write or Solana transaction endpoint is used.

Copy `worker.config.example.json` to `/etc/agenc-worker/worker.json`, fill the
digest and registry, and encrypt a **report-only** PKCS8 PEM credential with
`systemd-creds` into the path in `agenc-worker.service`. Root owns configuration,
release and encrypted credential files. Never mount an engine socket, host home
or host env into any container. The rootless CLI is used on the controller host.
The compose file is an offline scanner qualification profile, not a privileged
Docker-in-Docker controller.

Production transport is authenticated HTTPS to `queueUrl` in worker.json.
The signer owns the durable SQLite `jobs` table alongside admissions/spend.
Provision `WORKER_KEYS_FILE` as a public-key JSON map on the signer, and set its
`WORKER_IMAGE_DIGEST` to the identical qualified image digest. Do not put R or V
on the scanner. The worker unit no longer needs a FIFO or a queue bridge.

`POST /internal/worker/pull` receives a report-key-signed envelope
`{body:{workerId,path,issuedAt,nonce,payload:{}},signature}`. Domain bytes are
`0xff || "agenc-worker-queue/v1" || 0x00 || canonicalJson(body)`. The exact path,
a fresh 60-second timestamp and durable nonce are checked. HTTP 200 returns
`{moderator:null,jobId,leaseToken,leaseExpiresAt,job}`; 204 has no body. A lease
lasts fifteen minutes; only expired unfinished leases are redelivered.

`POST /internal/worker/reports` uses the same outer envelope with
`payload:{jobId,leaseToken,report:{body,signature}}`. The inner report retains
its separate worker-report domain. The signer checks the allowed worker key,
lease ownership, exact queued job, current bundle/image, task/spec/submission
and GitHub facts. Its worker replay nonce and rechecked report are stored in one
transaction before chain work. HTTP 200 `{moderator:null,accepted:true,jobId}`
acknowledges durable acceptance. Retry the exact report with a fresh outer nonce.
Different reports for an accepted job, expired leases and nonce replay are 409;
forgery is 403. Chain/retrievability failures after acceptance retain the report
and Desktop POST resumes finalization without another payment.

In [nginx.conf](nginx.conf), replace `203.0.113.20` with the worker's fixed public
IP (add its fixed IPv6 if used), keep `deny all`, and mirror this restriction in
the droplet ingress firewall. Public clients must never reach `/internal/worker/`
through another location/proxy. Keep Node on 127.0.0.1:8787, with no public ingress
to that port. Signed requests authenticate the worker even after IP filtering.
Add only the fixed signer TLS hostname and artifact host to the dedicated
signer/artifact egress sets and hostname gateway. Empty sets fail closed.

The binary remains a bounded UTF-8 JSONL consumer when `queueUrl` is omitted;
that development adapter requires an explicit stdin source and report sink.
For local tests use `runDevelopmentWorkerOnce` with mocked Sandbox, RPC, GitHub,
registry and OSV dependencies; it uses the same durable queue and signer rechecks,
runs sequentially and is forbidden in production. No daemon is needed. Never
requeue test failures as automatic approval. Monitor worker-error/cleanup holds
and orphan containers; reconcile orphans outside the signer.

The container starts with only the restricted fetch network; fetch uses
`git init`, exact-SHA `fetch --depth 1`, disabled hooks/submodules/LFS/redirects.
It disconnects all networks and verifies the disconnect before inspecting or
applying changes. Dependency install alone can reattach `agenc-fetch`; it uses
`npm ci --ignore-scripts`. Test execution has no attached network, the equivalent
of `--network none`, and never gets an unrestricted network. Each CLI phase has
a 120-second bound, the job has a 10-minute bound, cleanup has a separate bound.
Killing a hung CLI does not itself prove container code stopped; failed cleanup
produces a hold and requires the controller's orphan reconciler.

The signer uses `reviewWorkerReport` internally, with a trusted task/submission
context resolver, independently canonicalized job spec and durable nonce guard
(e.g. `store.consumeNonce('worker:'+workerId, nonce)`). Historical intake V keys
must come from the offline-root verified key manifest with validity/revocation
checked by the caller. A submitted report must not define its own authoritative
task context. The internal reviewer does not submit transactions. Its durable HTTP adapter
uses the existing guarded signer path for clean repository intake only; held/
rejected intakes and deliverable reviews never create chain records. Enable live
intake only after droplet/image/egress qualification, R roster registration, the
offline root/V ceremony and Desktop verification of the signed repository gate.
