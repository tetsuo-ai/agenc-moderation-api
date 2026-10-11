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

The queue protocol is bounded UTF-8 JSONL over stdin/stdout; `consumeQueue` also
accepts an async iterable for a production durable lease adapter. Create the
private `jobs.fifo` as the worker UID before unit startup. A local queue bridge
leases one item at a time, writes a job line and durably saves the resulting
signed report; acknowledge only after signer verification. Do not feed arbitrary
queue clients directly to the signer. Invalid input exits nonzero so its lease
remains unacknowledged. Stdout reports are redacted but contain repo filenames;
rotate/restrict the report journal. Monitor worker-error/cleanup holds and orphan
containers; reconcile orphans outside the signer. Never requeue test failures as
automatic approval.

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
task context. This API neither writes registry objects nor creates chain records.
Connect the queue bridge and Desktop repository verdict gate before enabling
live repository tasks; the existing HTTP route refuses `custom.github` tasks.
