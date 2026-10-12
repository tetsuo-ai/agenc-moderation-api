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
    ).toBe("unknown");
  });

  it("prefers x-real-ip over x-forwarded-for", () => {
    expect(clientIp(req({ "x-real-ip": "9.9.9.9", "x-forwarded-for": "1.2.3.4" }))).toBe("unknown");
  });

  it("uses the RIGHTMOST x-forwarded-for hop (proxy-added), not the spoofable leftmost", () => {
    // Attacker prepends a rotating fake; the trusted proxy appends the real IP last.
    expect(clientIp(req({ "x-forwarded-for": "203.0.113.99, 70.0.0.1" }))).toBe("unknown");
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

  it("keeps GET counters and limits apart from POST", async () => {
    const ip = "203.0.113.8";
    const config = { ...BASE, rateLimitGetPerIp: 5, rateLimitGetGlobal: 100 };
    for (let i = 0; i < 5; i++) expect((await rateLimit(config, ip, "get")).allowed).toBe(true);
    const denied = await rateLimit(config, ip, "get");
    expect(denied).toMatchObject({ allowed: false, deniedBy: "ip" });
    // The POST budget for the same IP is untouched.
    expect((await rateLimit(config, ip)).allowed).toBe(true);
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

it('trusts proxy header only when explicitly enabled',()=>{
  process.env.TRUST_PROXY='1';
  try { expect(clientIp(new Request('http://svc.test',{headers:{'x-forwarded-for':'fake, 70.0.0.1'}}))).toBe('70.0.0.1'); } finally {delete process.env.TRUST_PROXY;}
});

describe("rateKey", () => {
  it("keeps IPv4 per address and groups IPv6 by /64", async () => {
    const { rateKey } = await import("../src/rate-limit.js");
    expect(rateKey("203.0.113.7")).toBe("203.0.113.7");
    expect(rateKey("::ffff:203.0.113.7")).toBe("203.0.113.7");
    expect(rateKey("2001:db8:1:2::1")).toBe("2001:db8:1:2::/64");
    expect(rateKey("2001:0db8:0001:0002:aaaa:bbbb:cccc:dddd")).toBe("2001:db8:1:2::/64");
    expect(rateKey("2001:db8::1")).toBe("2001:db8:0:0::/64");
    expect(rateKey("fe80::1%en0")).toBe("fe80:0:0:0::/64");
    expect(rateKey("unknown")).toBe("unknown");
    expect(rateKey("2001:db8:zz::1")).toBe("2001:db8:zz::1");
  });
});
