/**
 * Bridge Node's `IncomingMessage`/`ServerResponse` to the WinterCG
 * `Request`/`Response` the router speaks. Shared by the self-host server
 * (`server.ts`) and the Vercel function entry (`api/index.ts`) so both run the
 * exact same handler.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable, Transform } from "node:stream";
import { MAX_BODY_BYTES } from "./limits.js";

/**
 * A pass-through that destroys the stream once more than `maxBytes` have
 * flowed — the self-host server has no reverse proxy in front of it, so this is
 * the hard cap that stops an unbounded socket body from being buffered into
 * memory (the request read then rejects and the handler returns an error,
 * instead of OOMing the single Node process).
 */
function byteCap(maxBytes: number): Transform {
  let total = 0;
  return new Transform({
    transform(chunk: Buffer, _enc, cb) {
      total += chunk.length;
      if (total > maxBytes) {
        cb(new Error("request body exceeds the size limit"));
        return;
      }
      cb(null, chunk);
    },
  });
}

export function nodeRequestToWeb(req: IncomingMessage, maxBytes = MAX_BODY_BYTES): Request {
  const host = req.headers.host ?? "localhost";
  const proto =
    (req.headers["x-forwarded-proto"] as string | undefined)?.split(",")[0]?.trim() ?? "http";
  const url = `${proto}://${host}${req.url ?? "/"}`;
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (typeof value === "string") headers.set(key, value);
    else if (Array.isArray(value)) headers.set(key, value.join(", "));
  }
  const method = req.method ?? "GET";
  const init: RequestInit & { duplex?: "half" } = { method, headers };
  if (method !== "GET" && method !== "HEAD") {
    const capped = req.pipe(byteCap(maxBytes));
    init.body = Readable.toWeb(capped) as unknown as BodyInit;
    init.duplex = "half";
  }
  return new Request(url, init);
}

export async function writeWebResponse(
  res: ServerResponse,
  response: Response,
): Promise<void> {
  res.statusCode = response.status;
  response.headers.forEach((value, key) => res.setHeader(key, value));
  const buffer = Buffer.from(await response.arrayBuffer());
  res.end(buffer);
}
