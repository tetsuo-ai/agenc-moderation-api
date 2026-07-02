/**
 * Fail-closed spec-hash binding — the money-path invariant: the service must
 * NEVER attest a payload whose hash differs from what the on-chain gate will
 * be seeded with (a mismatched attestation would bless content the gate never
 * checks).
 */
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { values } from "@tetsuo-ai/marketplace-sdk";
import { ModerationRejectError, resolveSpecAgainstHash } from "../src/signer.js";

const PAYLOAD = {
  kind: "agenc.marketplace.jobSpec",
  title: "Summarize three research papers",
  shortDescription: "Read the linked papers and produce a two-page summary.",
};

async function canonicalHex(payload: Record<string, unknown>): Promise<string> {
  return (await values.canonicalJobSpecHash(payload)).hex;
}

describe("resolveSpecAgainstHash (inline)", () => {
  it("accepts a payload whose canonical hash equals the target", async () => {
    const target = await canonicalHex(PAYLOAD);
    const resolved = await resolveSpecAgainstHash({
      targetHashHex: target,
      spec: PAYLOAD,
      what: "task spec",
    });
    expect(resolved.specHashHex).toBe(target);
    expect(resolved.payload).toEqual(PAYLOAD);
  });

  it("unwraps a job-spec envelope to its payload before hashing", async () => {
    const target = await canonicalHex(PAYLOAD);
    const resolved = await resolveSpecAgainstHash({
      targetHashHex: target,
      spec: { version: 1, payload: PAYLOAD },
      what: "task spec",
    });
    expect(resolved.specHashHex).toBe(target);
    expect(resolved.payload).toEqual(PAYLOAD);
  });

  it("REJECTS (422) a payload that does not hash to the target — never attests a mismatch", async () => {
    const target = await canonicalHex(PAYLOAD);
    await expect(
      resolveSpecAgainstHash({
        targetHashHex: target,
        spec: { ...PAYLOAD, title: "Tampered title" },
        what: "task spec",
      }),
    ).rejects.toMatchObject({ name: "ModerationRejectError", httpStatus: 422 });
  });

  it("REJECTS a target that matches neither canonical nor raw-byte binding", async () => {
    await expect(
      resolveSpecAgainstHash({
        targetHashHex: "ab".repeat(32),
        spec: PAYLOAD,
        rawText: JSON.stringify(PAYLOAD),
        what: "task spec",
      }),
    ).rejects.toBeInstanceOf(ModerationRejectError);
  });

  it("accepts the legacy content-addressed binding: sha256(raw bytes) == target", async () => {
    const text = JSON.stringify({ version: 1, payload: PAYLOAD });
    const rawHex = createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");
    const resolved = await resolveSpecAgainstHash({
      targetHashHex: rawHex,
      spec: JSON.parse(text) as Record<string, unknown>,
      rawText: text,
      what: "task spec",
    });
    expect(resolved.specHashHex).toBe(rawHex);
    expect(resolved.payload).toEqual(PAYLOAD);
  });

  it("rejects when neither spec nor specUri is provided", async () => {
    await expect(
      resolveSpecAgainstHash({ targetHashHex: "ab".repeat(32), what: "task spec" }),
    ).rejects.toMatchObject({ httpStatus: 400 });
  });
});
