/**
 * Self-host entrypoint: a plain Node HTTP server around the same fetch handler
 * the hosted deployment runs. `npx @tetsuo-ai/agenc-moderation-api` or
 * `docker run` (see README) boots this.
 */
import { createServer } from "node:http";
import { nodeRequestToWeb, writeWebResponse } from "./node-adapter.js";
import { createModerationApi } from "./router.js";
import { loadConfig } from "./config.js";
import { loadModeratorSigner } from "./signer.js";
import { moderationPolicyHashHex } from "./policy.js";
import { scannerHashHex } from "./scan.js";
import { SERVICE_NAME, SERVICE_VERSION } from "./version.js";
import { startHeartbeatTimer } from "./heartbeat.js";
import { SIGNING_SURFACE_REVISION } from "./revision.js";

export async function startServer(port = Number(process.env.PORT ?? 8787)): Promise<void> {
  const handler = createModerationApi();
  const config = loadConfig();

  let signerLine = "signer: NOT CONFIGURED (verdict-only mode — no attestations will be recorded)";
  try {
    const signer = await loadModeratorSigner();
    signerLine = `signer: ${signer.address}`;
  } catch {
    /* verdict-only */
  }

  const server = createServer((req, res) => {
    handler(nodeRequestToWeb(req))
      .then((response) => writeWebResponse(res, response))
      .catch(() => {
        res.statusCode = 500;
        res.end('{"ok":false,"error":"internal error"}');
      });
  });

  await new Promise<void>((resolve) => server.listen(port, resolve));
  console.log(`[${SERVICE_NAME}] v${SERVICE_VERSION} listening on :${port}`);
  console.log(`[${SERVICE_NAME}] rpc: ${config.rpcUrl} (${config.cluster})`);
  console.log(`[${SERVICE_NAME}] ${signerLine}`);
  console.log(`[${SERVICE_NAME}] policyHash: ${moderationPolicyHashHex()}`);
  console.log(`[${SERVICE_NAME}] scannerHash: ${scannerHashHex()}`);
  console.log(
    `[${SERVICE_NAME}] ttl: ${config.attestationTtlSeconds}s; rate: ${config.rateLimitPerIp}/ip + ${config.rateLimitGlobal} global per ${config.rateLimitWindowMs}ms${config.upstashUrl ? " (shared)" : " (per-instance)"}`,
  );
  console.log(`[${SERVICE_NAME}] signs for program revision ${SIGNING_SURFACE_REVISION} only`);
  // The weekly liveness heartbeat: off unless HEARTBEAT_ENABLED turns it on.
  if (config.heartbeatEnabled) {
    startHeartbeatTimer(config);
    console.log(`[${SERVICE_NAME}] heartbeat: on (checked hourly, sent weekly)`);
  } else {
    console.log(`[${SERVICE_NAME}] heartbeat: off`);
  }
}
