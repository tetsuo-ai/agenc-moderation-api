import { Readable } from "node:stream";
import type { IncomingMessage } from "node:http";
import { describe, expect, it } from "vitest";
import { nodeRequestToWeb } from "../src/node-adapter.js";

/** Build a fake IncomingMessage streaming `chunks` with the given method/headers. */
function fakeReq(method: string, chunks: Buffer[], headers: Record<string, string> = {}): IncomingMessage {
  const readable = Readable.from(chunks) as unknown as IncomingMessage;
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
