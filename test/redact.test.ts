import { describe, expect, it } from "vitest";
import { redactSecrets, urlOrigin } from "../src/redact.js";

const KEY = "0123abcd-4567-89ef-fedc-ba9876543210";

describe("redactSecrets", () => {
  it("removes a provider key from an echoed RPC URL", () => {
    const message = `fetch failed for https://mainnet.helius-rpc.com/?api-key=${KEY}: timeout`;
    const out = redactSecrets(message);
    expect(out).not.toContain(KEY);
    expect(out).toContain("https://mainnet.helius-rpc.com/?api-key=<redacted>");
  });

  it("removes other key-like query values and URL credentials", () => {
    const out = redactSecrets(
      `a https://rpc.example/x?foo=1&apikey=${KEY}&token=${KEY} b https://user:${KEY}@rpc.example/ c`,
    );
    expect(out).not.toContain(KEY);
    expect(out).toContain("foo=1");
  });

  it("leaves ordinary messages alone", () => {
    const message = "The request did not pass the safety check.";
    expect(redactSecrets(message)).toBe(message);
  });
});

describe("urlOrigin", () => {
  it("keeps only the origin", () => {
    expect(urlOrigin(`https://mainnet.helius-rpc.com/?api-key=${KEY}`)).toBe("https://mainnet.helius-rpc.com");
  });

  it("does not echo an invalid URL", () => {
    expect(urlOrigin(`not a url ${KEY}`)).toBe("<invalid url>");
  });
});
