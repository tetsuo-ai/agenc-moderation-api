import { clientIp } from '../src/rate-limit.js';
import { Readable } from "node:stream";
import type { IncomingMessage } from "node:http";
import { describe, expect, it } from "vitest";
import { nodeRequestToWeb } from "../src/node-adapter.js";

/** Build a fake IncomingMessage streaming `chunks` with the given method/headers. */
function fakeReq(method: string, chunks: Buffer[], headers: Record<string, string> = {}): IncomingMessage {
  const readable = Readable.from(chunks) as unknown as IncomingMessage;
  Object.defineProperty(readable,"socket",{value:{remoteAddress:"198.51.100.4"}});
  readable.method = method;
  readable.url = "/v1/moderation/tasks";
  readable.headers = { host: "svc.test", ...headers };
  return readable;
}

describe("nodeRequestToWeb stream cap (self-host OOM guard)", () => {
  it("REJECTS reading a body that exceeds the byte cap — the stream never fully buffers", async () => {
    // 4 KiB of body against a 1 KiB cap. Pre-fix (no byteCap) this fully
    // materialized into memory; post-fix the stream is destroyed past the cap
    // and the read rejects.
    const oversized = [Buffer.alloc(4096, 0x78)];
    const request = nodeRequestToWeb(fakeReq("POST", oversized), 1024);
    await expect(request.text()).rejects.toBeDefined();
  });

  it("reads a within-cap body normally", async () => {
    const body = Buffer.from(JSON.stringify({ ok: true }), "utf8");
    const request = nodeRequestToWeb(fakeReq("POST", [body], { "content-type": "application/json" }), 1024);
    await expect(request.text()).resolves.toBe('{"ok":true}');
  });

  it("passes through GET with no body and preserves the path", async () => {
    const request = nodeRequestToWeb(fakeReq("GET", []));
    expect(new URL(request.url).pathname).toBe("/v1/moderation/tasks");
    expect(request.method).toBe("GET");
  });
});

it('uses the socket address despite every forged IP header',()=>{
  delete process.env.TRUST_PROXY;
  const req=nodeRequestToWeb(fakeReq('GET',[],{'x-forwarded-for':'1.2.3.4','x-real-ip':'8.8.8.8','x-vercel-forwarded-for':'9.9.9.9'}));
  expect(clientIp(req)).toBe('198.51.100.4');
});
