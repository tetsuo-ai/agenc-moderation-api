/**
 * Retrievability gate unit tests — "every attestation implies retrievable
 * content". These drive ensureSpecRetrievable directly with injected fetch
 * seams (no live network, no signer env).
 */
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { generateKeyPairSigner } from "@solana/kit";
import { values } from "@tetsuo-ai/marketplace-sdk";
import {
  ensureSpecRetrievable,
  jobSpecRegistryObjectUrl,
  jobSpecUploadTicketUrl,
} from "../src/retrievability.js";
import { SpecNotRetrievableError } from "../src/errors.js";

const REGISTRY = "https://registry.test";

const PAYLOAD = {
  kind: "agenc.marketplace.jobSpec",
  title: "Summarize three research papers",
  shortDescription: "Read the linked papers and produce a two-page summary.",
};

async function canonicalHex(payload: Record<string, unknown>): Promise<string> {
  return (await values.canonicalJobSpecHash(payload)).hex.toLowerCase();
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** A fetch stub that records calls and dispatches on method+URL. */
function fetchStub(
  handler: (method: string, url: string, init?: RequestInit) => Response | Promise<Response>,
): { impl: typeof fetch; calls: Array<{ method: string; url: string; init?: RequestInit }> } {
  const calls: Array<{ method: string; url: string; init?: RequestInit }> = [];
  const impl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const method = (init?.method ?? "GET").toUpperCase();
    calls.push({ method, url, init });
    return handler(method, url, init);
  }) as typeof fetch;
  return { impl, calls };
}

describe("registry URL construction", () => {
  it("appends /api/job-specs/<hash> to a bare origin", () => {
    expect(jobSpecRegistryObjectUrl("https://marketplace.agenc.tech", "ab".repeat(32))).toBe(
      `https://marketplace.agenc.tech/api/job-specs/${"ab".repeat(32)}`,
    );
  });

  it("respects a custom registry path and derives the ticket URL beside it", () => {
    expect(jobSpecRegistryObjectUrl("https://host.test/api/job-specs", "ab".repeat(32))).toBe(
      `https://host.test/api/job-specs/${"ab".repeat(32)}`,
    );
    expect(jobSpecUploadTicketUrl("https://host.test/api/job-specs")).toBe(
      "https://host.test/api/job-spec-upload-tickets",
    );
    expect(jobSpecUploadTicketUrl("https://marketplace.agenc.tech")).toBe(
      "https://marketplace.agenc.tech/api/job-spec-upload-tickets",
    );
  });

  it("allows http bases for local dev but refuses other protocols and credentials", () => {
    // http is tolerated: the base is trusted operator config (localnet registries).
    expect(jobSpecRegistryObjectUrl("http://127.0.0.1:8799", "ab".repeat(32))).toBe(
      `http://127.0.0.1:8799/api/job-specs/${"ab".repeat(32)}`,
    );
    expect(() => jobSpecRegistryObjectUrl("ftp://registry.test", "ab".repeat(32))).toThrow(
      /https/,
    );
    expect(() => jobSpecRegistryObjectUrl("https://user:pw@registry.test", "ab".repeat(32))).toThrow(
      /credentials/,
    );
  });
});

describe("ensureSpecRetrievable", () => {
  it("short-circuits with ZERO network when the payload was resolved from a URI", async () => {
    const { impl, calls } = fetchStub(() => {
      throw new Error("network must not be touched");
    });
    const result = await ensureSpecRetrievable(
      {
        registryUrl: REGISTRY,
        registryToken: null,
        targetHashHex: await canonicalHex(PAYLOAD),
        payload: PAYLOAD,
        resolvedFromUri: "https://specs.example/spec.json",
        moderator: null,
        what: "task spec",
      },
      {
        fetchImpl: impl,
        fetchSpecBody: () => Promise.reject(new Error("must not fetch")),
      },
    );
    expect(result).toEqual({
      retrievable: true,
      pinned: false,
      specRegistryUri: "https://specs.example/spec.json",
    });
    expect(calls).toHaveLength(0);
  });

  it("accepts a registry object whose canonical payload hash matches", async () => {
    const target = await canonicalHex(PAYLOAD);
    const envelope = {
      schemaVersion: 1,
      kind: "agenc.marketplace.jobSpecEnvelope",
      integrity: {
        algorithm: "sha256",
        canonicalization: "json-stable-v1",
        payloadHash: target,
        uri: `${REGISTRY}/api/job-specs/${target}`,
      },
      payload: PAYLOAD,
    };
    const { impl, calls } = fetchStub((method, url) =>
      method === "GET" && url === `${REGISTRY}/api/job-specs/${target}`
        ? jsonResponse(envelope)
        : jsonResponse({ ok: false }, 500),
    );
    const result = await ensureSpecRetrievable(
      {
        registryUrl: REGISTRY,
        registryToken: null,
        targetHashHex: target,
        payload: PAYLOAD,
        moderator: null,
        what: "task spec",
      },
      { fetchImpl: impl },
    );
    expect(result).toEqual({
      retrievable: true,
      pinned: false,
      specRegistryUri: `${REGISTRY}/api/job-specs/${target}`,
    });
    expect(calls.map((c) => c.method)).toEqual(["GET"]);
  });

  it("aborts an over-cap registry body mid-stream (no Content-Length) and fails closed", async () => {
    const target = await canonicalHex(PAYLOAD);
    let enqueued = 0;
    const chunk = new Uint8Array(256 * 1024);
    const oversized = new ReadableStream<Uint8Array>({
      pull(controller) {
        // 64 × 256 KiB = 16 MiB — 16× the cap; the reader must cancel long
        // before draining it all.
        if (enqueued >= 64) {
          controller.close();
          return;
        }
        enqueued += 1;
        controller.enqueue(chunk);
      },
    });
    const { impl } = fetchStub((method) =>
      method === "GET" ? new Response(oversized, { status: 200 }) : jsonResponse({ ok: false }, 404),
    );
    await expect(
      ensureSpecRetrievable(
        {
          registryUrl: REGISTRY,
          registryToken: null,
          targetHashHex: target,
          payload: PAYLOAD,
          moderator: null,
          what: "task spec",
        },
        { fetchImpl: impl },
      ),
    ).rejects.toBeInstanceOf(SpecNotRetrievableError);
    // The stream was cancelled at the cap, not drained: ~5 chunks reach the
    // 1 MiB cap; allow a little reader lookahead but nowhere near the 64 total.
    expect(enqueued).toBeLessThanOrEqual(8);
  });

  it("REJECTS a registry 200 whose content does not hash-match (fail-closed)", async () => {
    const target = await canonicalHex(PAYLOAD);
    const { impl } = fetchStub((method) =>
      method === "GET"
        ? jsonResponse({ payload: { title: "some other spec entirely" } })
        : jsonResponse({ ok: false }, 404),
    );
    await expect(
      ensureSpecRetrievable(
        {
          registryUrl: REGISTRY,
          registryToken: null,
          targetHashHex: target,
          payload: PAYLOAD,
          moderator: null,
          what: "task spec",
        },
        { fetchImpl: impl },
      ),
    ).rejects.toBeInstanceOf(SpecNotRetrievableError);
  });

  it("accepts a caller https URI serving the exact raw bytes (legacy binding)", async () => {
    const text = JSON.stringify({ version: 1, payload: PAYLOAD });
    const rawHex = createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");
    const { impl, calls } = fetchStub(() => jsonResponse({ ok: false }, 404));
    const result = await ensureSpecRetrievable(
      {
        registryUrl: REGISTRY,
        registryToken: null,
        targetHashHex: rawHex,
        payload: PAYLOAD,
        candidateUris: ["not-https", undefined, "https://specs.example/spec.json"],
        moderator: null,
        what: "task spec",
      },
      {
        fetchImpl: impl,
        fetchSpecBody: async () => ({ text, sha256: rawHex }),
      },
    );
    expect(result).toEqual({
      retrievable: true,
      pinned: false,
      specRegistryUri: "https://specs.example/spec.json",
    });
    // Registry was consulted first (404), then the URI; no PUT was attempted.
    expect(calls.map((c) => c.method)).toEqual(["GET"]);
  });

  it("pins with an operator registry token (Bearer) — no upload ticket minted", async () => {
    const target = await canonicalHex(PAYLOAD);
    const objectUrl = `${REGISTRY}/api/job-specs/${target}`;
    const { impl, calls } = fetchStub((method, url) => {
      if (method === "GET") return jsonResponse({ ok: false }, 404);
      if (method === "PUT" && url === objectUrl) {
        return jsonResponse({ ok: true, jobSpecHash: target, jobSpecUri: objectUrl }, 201);
      }
      return jsonResponse({ ok: false }, 500);
    });
    const result = await ensureSpecRetrievable(
      {
        registryUrl: REGISTRY,
        registryToken: "operator-token",
        targetHashHex: target,
        payload: PAYLOAD,
        moderator: null,
        what: "task spec",
      },
      { fetchImpl: impl },
    );
    expect(result).toEqual({ retrievable: true, pinned: true, specRegistryUri: objectUrl });
    const put = calls.find((c) => c.method === "PUT");
    expect(put).toBeDefined();
    const headers = put?.init?.headers as Record<string, string>;
    expect(headers.authorization).toBe("Bearer operator-token");
    expect(headers["x-agenc-job-spec-upload-ticket"]).toBeUndefined();
    // No ticket POST happened.
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(0);
    // The published envelope is exactly the registry's schema shape.
    const envelope = JSON.parse(String(put?.init?.body)) as Record<string, unknown>;
    expect(envelope).toEqual({
      schemaVersion: 1,
      kind: "agenc.marketplace.jobSpecEnvelope",
      integrity: {
        algorithm: "sha256",
        canonicalization: "json-stable-v1",
        payloadHash: target,
        uri: objectUrl,
      },
      payload: PAYLOAD,
    });
  });

  it("pins via a wallet-scoped upload ticket when no token is configured", async () => {
    const target = await canonicalHex(PAYLOAD);
    const objectUrl = `${REGISTRY}/api/job-specs/${target}`;
    const moderator = await generateKeyPairSigner();
    const { impl, calls } = fetchStub((method, url, init) => {
      if (method === "GET") return jsonResponse({ ok: false }, 404);
      if (method === "POST" && url === `${REGISTRY}/api/job-spec-upload-tickets`) {
        const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
        expect(body.authority).toBe(moderator.address);
        expect(body.jobSpecHash).toBe(target);
        expect(String(body.message)).toContain("AgenC job-spec upload ticket v1");
        expect(String(body.signature)).toMatch(/^[0-9a-f]{128}$/);
        return jsonResponse(
          {
            ok: true,
            ticket: "TICKET.SIG",
            jobSpecHash: target,
            authority: moderator.address,
            expiresAt: new Date(Date.now() + 60_000).toISOString(),
            header: "x-agenc-job-spec-upload-ticket",
          },
          201,
        );
      }
      if (method === "PUT" && url === objectUrl) {
        return jsonResponse({ ok: true, jobSpecHash: target, jobSpecUri: objectUrl }, 201);
      }
      return jsonResponse({ ok: false }, 500);
    });
    const result = await ensureSpecRetrievable(
      {
        registryUrl: REGISTRY,
        registryToken: null,
        targetHashHex: target,
        payload: PAYLOAD,
        moderator,
        what: "task spec",
      },
      { fetchImpl: impl },
    );
    expect(result).toEqual({ retrievable: true, pinned: true, specRegistryUri: objectUrl });
    const put = calls.find((c) => c.method === "PUT");
    const headers = put?.init?.headers as Record<string, string>;
    expect(headers["x-agenc-job-spec-upload-ticket"]).toBe("TICKET.SIG");
  });

  it("cannot pin a raw-bytes (non-canonical) binding and refuses with guidance", async () => {
    const text = JSON.stringify({ version: 1, payload: PAYLOAD });
    const rawHex = createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");
    const { impl, calls } = fetchStub(() => jsonResponse({ ok: false }, 404));
    await expect(
      ensureSpecRetrievable(
        {
          registryUrl: REGISTRY,
          registryToken: "operator-token",
          targetHashHex: rawHex,
          payload: PAYLOAD,
          moderator: null,
          what: "task spec",
        },
        { fetchImpl: impl },
      ),
    ).rejects.toThrow(/SPEC_NOT_RETRIEVABLE.*raw-bytes hash/s);
    // The pin PUT was never even attempted for a raw-bytes binding.
    expect(calls.filter((c) => c.method === "PUT")).toHaveLength(0);
  });

  it("refuses (409, retryable, coded) when NOTHING is retrievable or pinnable", async () => {
    const target = await canonicalHex(PAYLOAD);
    const { impl } = fetchStub((method) =>
      // Registry 404s the GET, refuses the ticket mint (401).
      jsonResponse({ ok: false }, method === "GET" ? 404 : 401),
    );
    const moderator = await generateKeyPairSigner();
    const error = await ensureSpecRetrievable(
      {
        registryUrl: REGISTRY,
        registryToken: null,
        targetHashHex: target,
        payload: PAYLOAD,
        candidateUris: ["https://gone.example/spec.json"],
        moderator,
        what: "task spec",
      },
      {
        fetchImpl: impl,
        fetchSpecBody: () => Promise.reject(new Error("Upstream responded with status 404")),
      },
    ).then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(SpecNotRetrievableError);
    const rejected = error as SpecNotRetrievableError;
    expect(rejected.httpStatus).toBe(409);
    expect(rejected.code).toBe("SPEC_NOT_RETRIEVABLE");
    expect(rejected.retryable).toBe(true);
    expect(rejected.message).toContain("SPEC_NOT_RETRIEVABLE");
    expect(rejected.message).toContain(`${REGISTRY}/api/job-specs/${target}`);
    expect(rejected.message).toContain("https://gone.example/spec.json");
  });
});
