/**
 * Bridge Node's `IncomingMessage`/`ServerResponse` to the WinterCG
 * `Request`/`Response` the router speaks. Shared by the self-host server
 * (`server.ts`) and the Vercel function entry (`api/index.ts`) so both run the
 * exact same handler.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";

export function nodeRequestToWeb(req: IncomingMessage): Request {
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
    init.body = Readable.toWeb(req) as unknown as BodyInit;
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
