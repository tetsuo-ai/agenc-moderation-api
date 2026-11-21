/**
 * The weekly moderation liveness heartbeat (revision 9).
 *
 * Drives the real job (heartbeat.ts) with only the network boundary mocked:
 * the RPC, the ModerationConfig / ProtocolConfig reads and the revision stamp.
 * Sent transactions are read back byte for byte.
 *
 * REVERT-SENSITIVE: with a window passed to the facade the data byte after
 * the discriminator is 1, not 0; with the protocol_config slot dropped the
 * instruction has two accounts (the revision 8 wire, refused by revision 9
 * with AccountNotEnoughKeys); with the revision, sender or due checks removed
 * the matching "sends nothing" test observes a sendTransaction.
 */
import { createPublicKey, generateKeyPairSync, verify as verifyEd25519 } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  AccountRole,
  createKeyPairSignerFromBytes,
  getCompiledTransactionMessageDecoder,
  getTransactionDecoder,
  type Address,
} from "@solana/kit";
import {
  AGENC_COORDINATION_PROGRAM_ADDRESS,
  findModerationConfigPda,
  findProtocolConfigPda,
  getModerationHeartbeatDiscriminatorBytes,
  getModerationHeartbeatInstructionDataDecoder,
} from "@tetsuo-ai/marketplace-sdk";
import { base58Encode } from "../src/base58.js";

const DAY = 24 * 60 * 60;

const state = vi.hoisted(() => ({
  events: [] as string[],
  signer: "",
  surfaceRevision: 9,
  config: null as null | { authority: string; moderationAuthority: string; updatedAt: bigint },
  owners: [] as string[],
  sent: [] as string[],
  /** Unix seconds the mocked chain stamps on a landed heartbeat. */
  chainNow: 0,
}));

vi.mock("@solana/kit", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@solana/kit")>();
  return {
    ...actual,
    createSolanaRpc: () => ({
      getLatestBlockhash: () => ({
        send: async () => ({
          value: { blockhash: base58Encode(new Uint8Array(32).fill(7)), lastValidBlockHeight: 99n },
        }),
      }),
      sendTransaction: (wire: string) => ({
        send: async () => {
          state.events.push("sendTransaction");
          state.sent.push(wire);
          // The heartbeat lands: the chain bumps updated_at.
          if (state.config) state.config.updatedAt = BigInt(state.chainNow);
          return "sig";
        },
      }),
      getSignatureStatuses: () => ({
        send: async () => ({ value: [{ err: null, confirmationStatus: "confirmed" }] }),
      }),
    }),
  };
});

vi.mock("@tetsuo-ai/marketplace-sdk", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@tetsuo-ai/marketplace-sdk")>();
  return {
    ...actual,
    getDeployedSurface: async () => {
      state.events.push("readStamp");
      return { surfaceRevision: state.surfaceRevision };
    },
    fetchMaybeModerationConfig: async () => {
      state.events.push("readModerationConfig");
      return state.config ? { exists: true, data: state.config } : { exists: false };
    },
    fetchMaybeProtocolConfig: async () => {
      state.events.push("readProtocolConfig");
      const owners = [...state.owners];
      while (owners.length < 5) owners.push("11111111111111111111111111111111");
      return { exists: true, data: { multisigOwners: owners, multisigOwnersLen: state.owners.length } };
    },
  };
});

import {
  buildModerationHeartbeatInstruction,
  HEARTBEAT_INTERVAL_SECONDS,
  runModerationHeartbeat,
  startHeartbeatTimer,
} from "../src/heartbeat.js";
import { createModerationApi } from "../src/router.js";
import { loadConfig } from "../src/config.js";

const OTHER = base58Encode(new Uint8Array(32).fill(4));
const CONFIG_AUTHORITY = base58Encode(new Uint8Array(32).fill(2));
const RPC = "https://rpc.test";
const NOW = 1_800_000_000;

let signerKey: ReturnType<typeof createPublicKey>;

function installSignerKey(): void {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(16);
  const publicKeyBytes = publicKey.export({ format: "der", type: "spki" }).subarray(12);
  process.env.MODERATION_SIGNER_SECRET = JSON.stringify([...seed, ...publicKeyBytes]);
  state.signer = base58Encode(publicKeyBytes);
  signerKey = publicKey;
}

/** The deployment's signer is the moderation authority; last heartbeat `ageDays` ago. */
function chainWithHeartbeat(ageDays: number, moderationAuthority = state.signer): void {
  state.config = {
    authority: CONFIG_AUTHORITY,
    moderationAuthority,
    updatedAt: BigInt(NOW - Math.round(ageDays * DAY)),
  };
}

function decodeSent(wire: string) {
  const transaction = getTransactionDecoder().decode(new Uint8Array(Buffer.from(wire, "base64")));
  const message = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
  // The service builds plain version-0 messages; anything else is a defect.
  if (message.version !== 0) throw new Error(`unexpected message version ${String(message.version)}`);
  const accounts = message.staticAccounts as readonly string[];
  return {
    transaction,
    header: message.header,
    accounts,
    instructions: message.instructions.map((instruction) => ({
      program: accounts[instruction.programAddressIndex]!,
      accounts: (instruction.accountIndices ?? []).map((index) => accounts[index]!),
      data: new Uint8Array(instruction.data ?? new Uint8Array()),
    })),
  };
}

beforeEach(() => {
  state.events = [];
  state.sent = [];
  state.surfaceRevision = 9;
  state.config = null;
  state.owners = [];
  state.chainNow = NOW;
});

afterEach(() => {
  vi.useRealTimers();
  delete process.env.MODERATION_SIGNER_SECRET;
  delete process.env.MODERATION_AUTHORITY_SECRET;
  delete process.env.HEARTBEAT_ENABLED;
  delete process.env.CRON_SECRET;
});

describe("the heartbeat instruction", () => {
  it("is the revision 9 wire built by the SDK facade: config, signer, the protocol_config slot, no window", async () => {
    installSignerKey();
    const signer = await createKeyPairSignerFromBytes(
      Uint8Array.from(JSON.parse(process.env.MODERATION_SIGNER_SECRET!) as number[]),
    );

    const instruction = await buildModerationHeartbeatInstruction(signer);

    const [moderationConfig] = await findModerationConfigPda();
    const [protocolConfig] = await findProtocolConfigPda();
    expect(instruction.programAddress).toBe(AGENC_COORDINATION_PROGRAM_ADDRESS);
    expect(instruction.accounts?.map((account) => [account.address, account.role])).toEqual([
      [moderationConfig, AccountRole.WRITABLE],
      [signer.address, AccountRole.READONLY_SIGNER],
      // Revision 9: the optional protocol_config slot is always filled.
      [protocolConfig, AccountRole.READONLY],
    ]);
    // `moderation_heartbeat(None)`: the discriminator and a None window, nothing else.
    const data = new Uint8Array(instruction.data ?? new Uint8Array());
    expect(Buffer.from(data).toString("hex")).toBe("d7b6fadb4786c60000");
    expect(Array.from(data.subarray(0, 8))).toEqual(Array.from(getModerationHeartbeatDiscriminatorBytes()));
    const decoded = getModerationHeartbeatInstructionDataDecoder().decode(data);
    expect(decoded.newWindowSecs).toEqual({ __option: "None" });
  });
});

describe("runModerationHeartbeat", () => {
  it("is off by default: reads nothing and sends nothing", async () => {
    installSignerKey();
    chainWithHeartbeat(30);

    const report = await runModerationHeartbeat({ rpcUrl: RPC, enabled: false });

    expect(report).toMatchObject({ sent: false, outcome: "disabled" });
    expect(state.events).toEqual([]);
  });

  it("does nothing without a signer", async () => {
    chainWithHeartbeat(30);

    const report = await runModerationHeartbeat({ rpcUrl: RPC, enabled: true, now: () => NOW });

    expect(report).toMatchObject({ sent: false, outcome: "no-signer" });
    expect(state.events).toEqual([]);
  });

  it.each([8, 10])("sends nothing while the program is stamped revision %i", async (stamp) => {
    installSignerKey();
    chainWithHeartbeat(30);
    state.surfaceRevision = stamp;

    const report = await runModerationHeartbeat({ rpcUrl: RPC, enabled: true, now: () => NOW });

    expect(report).toMatchObject({ sent: false, outcome: "unsupported-revision", surfaceRevision: stamp });
    expect(state.events).toEqual(["readStamp"]);
  });

  it("sends nothing when there is no ModerationConfig", async () => {
    installSignerKey();

    const report = await runModerationHeartbeat({ rpcUrl: RPC, enabled: true, now: () => NOW });

    expect(report).toMatchObject({ sent: false, outcome: "no-moderation-config" });
    expect(state.events).not.toContain("sendTransaction");
  });

  it("sends nothing when its signer may not heartbeat (a roster attestor is neither authority nor owner)", async () => {
    installSignerKey();
    chainWithHeartbeat(30, OTHER);
    state.owners = [CONFIG_AUTHORITY, OTHER];

    const report = await runModerationHeartbeat({ rpcUrl: RPC, enabled: true, now: () => NOW });

    expect(report).toMatchObject({ sent: false, outcome: "not-allowed", sender: state.signer });
    expect(state.events).toEqual(["readStamp", "readModerationConfig", "readProtocolConfig"]);
  });

  it("sends nothing when the last heartbeat is less than a week old, and says when it is due", async () => {
    installSignerKey();
    chainWithHeartbeat(3);

    const report = await runModerationHeartbeat({ rpcUrl: RPC, enabled: true, now: () => NOW });

    expect(report).toMatchObject({ sent: false, outcome: "not-due" });
    const last = NOW - 3 * DAY;
    expect(report.lastHeartbeatAt).toBe(new Date(last * 1000).toISOString());
    expect(report.nextDueAt).toBe(new Date((last + HEARTBEAT_INTERVAL_SECONDS - 3600) * 1000).toISOString());
    expect(state.events).not.toContain("sendTransaction");
  });

  it("sends one heartbeat, signed and paid by its signer, when the last one is a week old", async () => {
    installSignerKey();
    chainWithHeartbeat(8);

    const report = await runModerationHeartbeat({ rpcUrl: RPC, enabled: true, now: () => NOW });

    expect(report).toMatchObject({ sent: true, outcome: "sent", signature: expect.any(String), sender: state.signer });
    expect(state.sent).toHaveLength(1);
    const sent = decodeSent(state.sent[0]!);
    // The signer is the fee payer and the only signer.
    expect(sent.accounts[0]).toBe(state.signer);
    expect(sent.header.numSignerAccounts).toBe(1);
    const signature = sent.transaction.signatures[state.signer as Address];
    expect(signature).toBeInstanceOf(Uint8Array);
    expect(verifyEd25519(null, new Uint8Array(sent.transaction.messageBytes), signerKey, signature!)).toBe(true);
    // Exactly the heartbeat, with no window change and no co-signers.
    expect(sent.instructions).toHaveLength(1);
    const [moderationConfig] = await findModerationConfigPda();
    const [protocolConfig] = await findProtocolConfigPda();
    expect(sent.instructions[0]!.program).toBe(AGENC_COORDINATION_PROGRAM_ADDRESS);
    expect(sent.instructions[0]!.accounts).toEqual([moderationConfig, state.signer, protocolConfig]);
    expect(Buffer.from(sent.instructions[0]!.data).toString("hex")).toBe("d7b6fadb4786c60000");
  });

  it("sends on the seventh day even when the check runs a little early", async () => {
    installSignerKey();
    chainWithHeartbeat(7 - 0.5 / 24);

    const report = await runModerationHeartbeat({ rpcUrl: RPC, enabled: true, now: () => NOW });

    expect(report.sent).toBe(true);
  });

  it("accepts the config authority and a protocol owner as senders, as the program does", async () => {
    installSignerKey();
    state.config = { authority: state.signer, moderationAuthority: OTHER, updatedAt: BigInt(NOW - 8 * DAY) };
    expect((await runModerationHeartbeat({ rpcUrl: RPC, enabled: true, now: () => NOW })).sent).toBe(true);

    state.config = { authority: CONFIG_AUTHORITY, moderationAuthority: OTHER, updatedAt: BigInt(NOW - 8 * DAY) };
    state.owners = [CONFIG_AUTHORITY, state.signer];
    expect((await runModerationHeartbeat({ rpcUrl: RPC, enabled: true, now: () => NOW })).sent).toBe(true);
    expect(state.sent).toHaveLength(2);
  });
});

describe("the self-host timer", () => {
  it("checks shortly after boot and hourly, and sends at most once a week", async () => {
    // Only the timers are faked: the job reads the real clock, and loading the
    // key goes through WebCrypto, which fake timers do not drive.
    vi.useFakeTimers({ toFake: ["setTimeout", "setInterval", "clearTimeout", "clearInterval"] });
    installSignerKey();
    const realNow = Math.floor(Date.now() / 1000);
    state.chainNow = realNow;
    state.config = {
      authority: CONFIG_AUTHORITY,
      moderationAuthority: state.signer,
      updatedAt: BigInt(realNow - 10 * DAY),
    };
    const log = { log: vi.fn(), error: vi.fn() };
    const checks = () => state.events.filter((event) => event === "readStamp").length;

    const timer = startHeartbeatTimer({ rpcUrl: RPC }, log);
    try {
      expect(state.events).toEqual([]);
      await vi.advanceTimersByTimeAsync(30_000);
      await vi.waitFor(() => expect(state.sent).toHaveLength(1));
      const afterSend = checks();
      // The next hourly checks find it not due and send nothing.
      await vi.advanceTimersByTimeAsync(3 * 60 * 60 * 1000);
      await vi.waitFor(() => expect(checks()).toBeGreaterThan(afterSend));
      expect(state.sent).toHaveLength(1);
      expect(log.error).not.toHaveBeenCalled();
      expect(String(log.log.mock.calls[0]?.[0])).toContain("heartbeat: sent");
    } finally {
      timer.stop();
    }
  });
});

describe("GET /v1/cron/heartbeat", () => {
  const BASE = "http://svc.test";
  const cron = (secret?: string) =>
    new Request(`${BASE}/v1/cron/heartbeat`, {
      headers: secret === undefined ? {} : { authorization: `Bearer ${secret}` },
    });

  it("answers disabled and touches nothing while the job is off", async () => {
    installSignerKey();
    chainWithHeartbeat(30);
    const handler = createModerationApi();

    const response = await handler(cron("anything"));

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ ok: true, sent: false, outcome: "disabled" });
    expect(state.events).toEqual([]);
  });

  it("stays closed while the job is on but CRON_SECRET is not set", async () => {
    installSignerKey();
    chainWithHeartbeat(30);
    const handler = createModerationApi({ heartbeatEnabled: true, cronSecret: null });

    const response = await handler(cron("anything"));

    expect(response.status).toBe(503);
    expect(((await response.json()) as Record<string, unknown>).code).toBe("CRON_SECRET_MISSING");
    expect(state.events).toEqual([]);
  });

  it("refuses a caller without the cron secret, before any chain read", async () => {
    installSignerKey();
    chainWithHeartbeat(30);
    const handler = createModerationApi({ heartbeatEnabled: true, cronSecret: "s3cret-value" });

    for (const request of [cron(), cron("wrong"), cron("s3cret-valuE")]) {
      expect((await handler(request)).status).toBe(401);
    }
    expect(state.events).toEqual([]);
  });

  it("runs the job for the cron caller, and a second call the same day sends nothing", async () => {
    installSignerKey();
    // This trigger reads the real clock.
    const realNow = Math.floor(Date.now() / 1000);
    state.chainNow = realNow;
    state.config = {
      authority: CONFIG_AUTHORITY,
      moderationAuthority: state.signer,
      updatedAt: BigInt(realNow - 30 * DAY),
    };
    const handler = createModerationApi({ heartbeatEnabled: true, cronSecret: "s3cret-value" });

    const first = await handler(cron("s3cret-value"));
    expect(first.status).toBe(200);
    expect(await first.json()).toMatchObject({ ok: true, sent: true, outcome: "sent" });

    const second = await handler(cron("s3cret-value"));
    expect(await second.json()).toMatchObject({ ok: true, sent: false, outcome: "not-due" });
    expect(state.sent).toHaveLength(1);
  });
});

describe("configuration", () => {
  it("keeps the job off unless HEARTBEAT_ENABLED plainly turns it on", () => {
    expect(loadConfig().heartbeatEnabled).toBe(false);
    for (const on of ["true", "1", "on", "yes", " TRUE "]) {
      process.env.HEARTBEAT_ENABLED = on;
      expect(loadConfig().heartbeatEnabled).toBe(true);
    }
    for (const off of ["", "false", "0", "off", "no", "enabled", "maybe"]) {
      process.env.HEARTBEAT_ENABLED = off;
      expect(loadConfig().heartbeatEnabled).toBe(false);
    }
  });

  it("reads CRON_SECRET and discloses the job at /v1/info without the secret", async () => {
    expect(loadConfig().cronSecret).toBeNull();
    process.env.CRON_SECRET = "s3cret-value";
    process.env.HEARTBEAT_ENABLED = "true";
    expect(loadConfig().cronSecret).toBe("s3cret-value");

    const response = await createModerationApi()(new Request("http://svc.test/v1/info"));
    const text = await response.text();
    expect(JSON.parse(text).heartbeat).toEqual({ enabled: true, intervalSeconds: 7 * DAY });
    expect(text).not.toContain("s3cret-value");
  });
});
