import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { __resetRateLimiterForTests, clientIp, limiterMode, rateLimit } from "../src/rate-limit.js";
import { loadConfig, type ServiceConfig } from "../src/config.js";

const BASE: ServiceConfig = {
  ...loadConfig(),
  rateLimitPerIp: 3,
  rateLimitGlobal: 100,
  rateLimitWindowMs: 60_000,
  upstashUrl: null,
  upstashToken: null,
};

beforeEach(() => __resetRateLimiterForTests());
afterEach(() => vi.restoreAllMocks());

describe("clientIp — trusts platform-set headers, not spoofable x-forwarded-for", () => {
  function req(headers: Record<string, string>): Request {
    return new Request("http://svc.test/v1/moderation/tasks", { method: "POST", headers });
  }

  it("prefers x-vercel-forwarded-for over any client x-forwarded-for", () => {
    expect(
      clientIp(req({ "x-vercel-forwarded-for": "8.8.8.8", "x-forwarded-for": "1.2.3.4, 5.6.7.8" })),
    ).toBe("8.8.8.8");
  });

  it("prefers x-real-ip over x-forwarded-for", () => {
    expect(clientIp(req({ "x-real-ip": "9.9.9.9", "x-forwarded-for": "1.2.3.4" }))).toBe("9.9.9.9");
  });

  it("uses the RIGHTMOST x-forwarded-for hop (proxy-added), not the spoofable leftmost", () => {
    // Attacker prepends a rotating fake; the trusted proxy appends the real IP last.
    expect(clientIp(req({ "x-forwarded-for": "203.0.113.99, 70.0.0.1" }))).toBe("70.0.0.1");
  });

  it("falls back to 'unknown' when no IP headers are present", () => {
    expect(clientIp(req({}))).toBe("unknown");
  });
});

describe("rate limiter (in-memory, no Upstash)", () => {
  it("bounds per IP and denies past the limit", async () => {
    const ip = "203.0.113.7";
    expect((await rateLimit(BASE, ip)).allowed).toBe(true);
    expect((await rateLimit(BASE, ip)).allowed).toBe(true);
    expect((await rateLimit(BASE, ip)).allowed).toBe(true);
    const denied = await rateLimit(BASE, ip);
    expect(denied.allowed).toBe(false);
    expect(denied.deniedBy).toBe("ip");
  });

  it("reports per-instance mode when no Upstash is configured", () => {
    expect(limiterMode(BASE)).toBe("per-instance");
  });
});

describe("rate limiter FAILS CLOSED when a configured shared store errors", () => {
  const withUpstash: ServiceConfig = {
    ...BASE,
    upstashUrl: "https://kv.example",
    upstashToken: "tok",
  };

  it("reports shared mode when Upstash is configured", () => {
    expect(limiterMode(withUpstash)).toBe("shared");
  });

  it("denies (does NOT silently fall back to per-instance) when Upstash is unreachable", async () => {
    // Simulate Upstash outage: the pipeline fetch always rejects.
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network down")));
    const decision = await rateLimit(withUpstash, "203.0.113.7");
    expect(decision.allowed).toBe(false);
    expect(decision.deniedBy).toBe("shared-store-error");
  });

  it("denies on a non-200 Upstash response too", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("nope", { status: 500 })),
    );
    const decision = await rateLimit(withUpstash, "203.0.113.7");
    expect(decision.allowed).toBe(false);
    expect(decision.deniedBy).toBe("shared-store-error");
  });

  it("allows within limit when Upstash returns a healthy count", async () => {
    // A fresh Response per call — rateLimit consumes twice (per-IP + global).
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify([{ result: 1 }, { result: 1 }]), { status: 200 })),
    );
    const decision = await rateLimit(withUpstash, "203.0.113.7");
    expect(decision.allowed).toBe(true);
  });
});
