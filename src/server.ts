/**
 * Self-host entrypoint: a plain Node HTTP server around the same fetch handler
 * the hosted deployment runs. `npx @tetsuo-ai/agenc-moderation-api` or
 * `docker run` (see README) boots this.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { createModerationApi } from "./router.js";
import { loadConfig } from "./config.js";
import { loadModeratorSigner } from "./signer.js";
import { moderationPolicyHashHex } from "./policy.js";
import { scannerHashHex } from "./scan.js";
import { SERVICE_NAME, SERVICE_VERSION } from "./version.js";

function toRequest(req: IncomingMessage): Request {
  const host = req.headers.host ?? "localhost";
  const url = `http://${host}${req.url ?? "/"}`;
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (typeof value === "string") headers.set(key, value);
    else if (Array.isArray(value)) headers.set(key, value.join(", "));
  }
  const method = req.method ?? "GET";
  const body =
    method === "GET" || method === "HEAD"
      ? undefined
      : (Readable.toWeb(req) as unknown as BodyInit);
  return new Request(url, {
    method,
    headers,
    body,
    // Node requires this for streamed request bodies.
    ...(body ? { duplex: "half" } : {}),
  } as RequestInit);
}

async function writeResponse(res: ServerResponse, response: Response): Promise<void> {
  res.statusCode = response.status;
  response.headers.forEach((value, key) => res.setHeader(key, value));
  const buffer = Buffer.from(await response.arrayBuffer());
  res.end(buffer);
}

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
    handler(toRequest(req))
      .then((response) => writeResponse(res, response))
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
}
