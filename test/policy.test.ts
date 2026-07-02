import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  MODERATION_POLICY_HASH_HEX,
  MODERATION_POLICY_TEXT,
  moderationPolicyBytes,
  moderationPolicyHashHex,
} from "../src/policy.js";
import { SCANNER_DESCRIPTOR } from "../src/scan.js";

describe("moderation policy", () => {
  it("pins the exact policy hash (edit deliberately, then update the pin)", () => {
    expect(moderationPolicyHashHex()).toBe(MODERATION_POLICY_HASH_HEX);
  });

  it("hash == sha256 of the served bytes, byte for byte", () => {
    const digest = createHash("sha256").update(moderationPolicyBytes()).digest("hex");
    expect(digest).toBe(MODERATION_POLICY_HASH_HEX);
  });

  it("commits to the scanner descriptor it actually uses", () => {
    expect(MODERATION_POLICY_TEXT).toContain(SCANNER_DESCRIPTOR);
  });

  it("documents the expiry disclosure endpoint", () => {
    expect(MODERATION_POLICY_TEXT).toContain("attestationTtlSeconds");
  });
});
