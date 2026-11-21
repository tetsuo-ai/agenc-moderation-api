/**
 * The service's transactions on the real revision 9 program.
 *
 * The program runs in-process in LiteSVM: the revision 9 SDK's testing asset
 * (byte for byte the round2-production.so build of rev9/build cb3fca3), or
 * the file named by AGENC_TEST_PROGRAM_SO. Every key is a throwaway generated
 * here. The service's RPC reads are answered from the VM; a send executes in
 * the VM. Nothing touches a network.
 *
 * What it proves:
 *  - the buyer-paid task approval runs: the buyer pays the deposit as the
 *    record's rent payer, the service's signer pays nothing, the record says
 *    the creator paid, and close_task gives the deposit back to the buyer;
 *  - the listing approval keeps its shape and runs, and the signer ends even;
 *  - what the service refuses before signing (a task its signer created, a
 *    listing its signer provides, a payer that is not the creator) is what
 *    the program refuses (6432, 6434, 6433);
 *  - the weekly heartbeat runs on the revision 9 wire, bumps the deadman
 *    timestamp, leaves the window alone, and the revision 8 two-account wire
 *    is refused by this program.
 */
import { generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  appendTransactionMessageInstructions,
  createKeyPairSignerFromBytes,
  createTransactionMessage,
  getTransactionDecoder,
  lamports,
  partiallySignTransaction,
  pipe,
  setTransactionMessageFeePayerSigner,
  signTransactionMessageWithSigners,
  type Address,
  type Instruction,
  type KeyPairSigner,
} from "@solana/kit";
import {
  facade,
  findAgentPda,
  findEscrowPda,
  findListingModerationPda,
  findModerationConfigPda,
  findProtocolConfigPda,
  findTaskPda,
  findTaskValidationConfigPda,
  getListingModerationSize,
  getModerationConfigDecoder,
  getTaskMarkerSize,
  getTaskModerationDecoder,
  getTaskModerationSize,
  SURFACE_REVISION_OFFSET,
  values,
} from "@tetsuo-ai/marketplace-sdk";
import {
  seedModerationConfig,
  startLocalMarketplace,
  type LocalMarketplace,
} from "@tetsuo-ai/marketplace-sdk/testing";
import { FailedTransactionMetadata, type LiteSVM } from "litesvm";
import { base58Encode } from "../src/base58.js";
import { checkApprovalTransaction } from "./wallet-approval-check.js";

const rpcState = vi.hoisted(() => ({ svm: null as LiteSVM | null, sends: 0 }));

vi.mock("@solana/kit", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@solana/kit")>();
  const vm = (): LiteSVM => {
    if (!rpcState.svm) throw new Error("no VM");
    return rpcState.svm;
  };
  return {
    ...actual,
    createSolanaRpc: () => ({
      getAccountInfo: (pubkey: Address) => ({
        send: async () => {
          const account = vm().getAccount(pubkey);
          return {
            context: { slot: 1n },
            value: account.exists
              ? {
                  data: [Buffer.from(account.data).toString("base64"), "base64"],
                  owner: account.programAddress,
                  lamports: account.lamports,
                  space: account.space,
                  executable: account.executable,
                  rentEpoch: 0n,
                }
              : null,
          };
        },
      }),
      getMinimumBalanceForRentExemption: (size: bigint) => ({
        send: async () => vm().minimumBalanceForRentExemption(size),
      }),
      getLatestBlockhash: () => ({
        send: async () => ({
          value: { blockhash: vm().latestBlockhash(), lastValidBlockHeight: 100n },
        }),
      }),
      // A send runs in the VM, as a preflight would: a failure throws.
      sendTransaction: (wire: string) => ({
        send: async () => {
          rpcState.sends += 1;
          const transaction = actual
            .getTransactionDecoder()
            .decode(new Uint8Array(Buffer.from(wire, "base64")));
          const result = vm().sendTransaction(transaction);
          if (result instanceof FailedTransactionMetadata) {
            throw new Error(`${String(result.err())}\n${result.meta().logs().join("\n")}`);
          }
          return base58Encode(result.signature());
        },
      }),
      getSignatureStatuses: () => ({
        send: async () => ({ value: [{ err: null, confirmationStatus: "confirmed" }] }),
      }),
    }),
  };
});

import { attestListing, attestTask, ModerationRejectError, type AttestDeps } from "../src/signer.js";
import { runModerationHeartbeat } from "../src/heartbeat.js";

const PROGRAM_SO = process.env.AGENC_TEST_PROGRAM_SO?.trim() || undefined;
/**
 * Optional: a revision 8 program build, to show why the service signs only on
 * a revision 9 stamp. The test that needs it is skipped when this is unset.
 */
const REVISION8_SO = process.env.AGENC_TEST_REVISION8_SO?.trim() || undefined;
const REGISTRY = "https://registry.test";
const DEPS: AttestDeps = {
  rpcUrl: "https://local-rpc.test",
  attestationTtlSeconds: 0,
  jobSpecRegistryUrl: REGISTRY,
  jobSpecRegistryToken: null,
};
const PAYLOAD = {
  kind: "agenc.marketplace.jobSpec",
  title: "Summarize three research papers",
  shortDescription: "Read the linked papers and produce a two-page summary.",
};
const SIGNATURE_FEE = 5_000n;

let market: LocalMarketplace;
let svm: LiteSVM;
/** This service's signer: the cluster's moderation authority here. */
let service: KeyPairSigner;

function installServiceKey(): Uint8Array {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(16);
  const publicKeyBytes = publicKey.export({ format: "der", type: "spki" }).subarray(12);
  const bytes = Uint8Array.from([...seed, ...publicKeyBytes]);
  process.env.MODERATION_SIGNER_SECRET = JSON.stringify([...bytes]);
  return bytes;
}

/** Write the revision stamp the service reads (the seeded world stamps 1). */
async function stamp(revision: number): Promise<void> {
  const [pda] = await findProtocolConfigPda();
  const account = svm.getAccount(pda);
  if (!account.exists) throw new Error("ProtocolConfig missing");
  const data = Uint8Array.from(account.data);
  new DataView(data.buffer).setUint16(SURFACE_REVISION_OFFSET, revision, true);
  svm.setAccount({ ...account, data });
}

function balance(account: Address): bigint {
  return svm.getBalance(account) ?? 0n;
}

async function send(feePayer: KeyPairSigner, instructions: Instruction[], vm: LiteSVM = svm) {
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayerSigner(feePayer, m),
    (m) => vm.setTransactionMessageLifetimeUsingLatestBlockhash(m),
    (m) => appendTransactionMessageInstructions(instructions, m),
  );
  const result = vm.sendTransaction(await signTransactionMessageWithSigners(message));
  if (result instanceof FailedTransactionMetadata) {
    throw new Error(`tx failed: ${String(result.err())}\n${result.meta().logs().join("\n")}`);
  }
  return result;
}

/** The registry already serves the payload, so the retrievability gate passes. */
function registryServes(hashHex: string): void {
  const objectUrl = `${REGISTRY}/api/job-specs/${hashHex}`;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      expect((init?.method ?? "GET").toUpperCase()).toBe("GET");
      if (url !== objectUrl) return new Response("{}", { status: 404 });
      return new Response(
        JSON.stringify({
          schemaVersion: 1,
          kind: "agenc.marketplace.jobSpecEnvelope",
          integrity: {
            algorithm: "sha256",
            canonicalization: "json-stable-v1",
            payloadHash: hashHex,
            uri: objectUrl,
          },
          payload: PAYLOAD,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }),
  );
}

async function createTask(creator: KeyPairSigner, fill: number, vm: LiteSVM = svm): Promise<Address> {
  const taskId = new Uint8Array(32).fill(fill);
  const description = new Uint8Array(64);
  description.set((await values.canonicalJobSpecHash(PAYLOAD)).bytes);
  await send(
    creator,
    [
      await facade.createTaskHumanless({
        creator,
        taskId,
        description,
        requiredCapabilities: 1n,
        rewardAmount: 100_000_000n,
        deadline: vm.getClock().unixTimestamp + 86_400n,
        minReputation: 0,
        reviewWindowSecs: 3_600n,
        referrer: null,
        referrerFeeBps: 0,
      }),
    ],
    vm,
  );
  return (await findTaskPda({ creator: creator.address, taskId }))[0];
}

async function createListing(provider: KeyPairSigner, specHash: Uint8Array): Promise<Address> {
  const agentId = new Uint8Array(32).fill(21);
  await send(provider, [
    await facade.registerAgent({
      authority: provider,
      agentId,
      capabilities: 1n,
      endpoint: "http://provider.test",
      metadataUri: null,
      stakeAmount: 0n,
    }),
  ]);
  const [providerAgent] = await findAgentPda({ agentId });
  const listingId = new Uint8Array(32).fill(22);
  await send(provider, [
    await facade.createServiceListing({
      providerAgent,
      authority: provider,
      listingId,
      name: new Uint8Array(32).fill(1),
      category: new Uint8Array(32).fill(2),
      tags: new Uint8Array(64).fill(3),
      specHash,
      specUri: `${REGISTRY}/api/job-specs/${values.bytesToHex(specHash)}`,
      price: 1_000_000n,
      priceMint: null,
      requiredCapabilities: 1n,
      defaultDeadlineSecs: 3_600n,
      maxOpenJobs: 0,
      operator: null,
      operatorFeeBps: 0,
    }),
  ]);
  return (await facade.findListingPda({ providerAgent, listingId }))[0];
}

function recordInstruction(input: {
  task: Address;
  moderator: KeyPairSigner;
  rentPayer: KeyPairSigner;
  hash: Uint8Array;
}) {
  return facade.recordTaskModeration({
    task: input.task,
    moderator: input.moderator,
    rentPayer: input.rentPayer,
    jobSpecHash: input.hash,
    status: 0,
    riskScore: 0,
    categoryMask: 0n,
    policyHash: new Uint8Array(32).fill(1),
    scannerHash: new Uint8Array(32).fill(2),
    expiresAt: 0n,
  });
}

beforeEach(async () => {
  service = await createKeyPairSignerFromBytes(installServiceKey());
  market = await startLocalMarketplace({
    unixTimestamp: BigInt(Math.floor(Date.now() / 1000)),
    ...(PROGRAM_SO ? { programPath: PROGRAM_SO } : {}),
  });
  svm = market.svm;
  rpcState.svm = svm;
  rpcState.sends = 0;
  // This service's key is the cluster's moderation authority.
  await seedModerationConfig(svm, market.admin.address, service.address, true);
  svm.airdrop(service.address, lamports(1_000_000_000n));
});

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.MODERATION_SIGNER_SECRET;
  rpcState.svm = null;
});

describe("a buyer-paid task approval on the revision 9 program", () => {
  it("is paid by the buyer as rent payer, costs the service nothing, and comes back to the buyer at close", async () => {
    const buyer = market.payer;
    const task = await createTask(buyer, 31);
    await stamp(9);
    const hash = await values.canonicalJobSpecHash(PAYLOAD);
    registryServes(hash.hex);

    const result = await attestTask(DEPS, { task, jobSpecHash: hash.hex, spec: PAYLOAD, payer: buyer.address });

    // The service signed and sent nothing itself.
    expect(rpcState.sends).toBe(0);
    const rent = svm.minimumBalanceForRentExemption(BigInt(getTaskModerationSize()));
    expect(result.payment!.depositLamports).toBe(rent.toString());
    const wire = new Uint8Array(Buffer.from(result.payment!.transaction, "base64"));
    // What the revision 9 wallet checks before it signs.
    await checkApprovalTransaction(wire, {
      payer: buyer.address,
      moderator: service.address,
      target: { kind: "task", task, hash: hash.bytes },
      maxDepositLamports: rent,
    });

    const serviceBefore = balance(service.address);
    const buyerBefore = balance(buyer.address);
    const signed = await partiallySignTransaction([buyer.keyPair], getTransactionDecoder().decode(wire));
    const execution = svm.sendTransaction(signed);
    if (execution instanceof FailedTransactionMetadata) {
      throw new Error(`${String(execution.err())}\n${execution.meta().logs().join("\n")}`);
    }

    // The buyer paid the deposit and both signature fees; the service paid nothing.
    expect(balance(service.address)).toBe(serviceBefore);
    expect(buyerBefore - balance(buyer.address)).toBe(rent + 2n * SIGNATURE_FEE);
    const [record] = await facade.findTaskModerationPda({
      task,
      jobSpecHash: hash.bytes,
      moderator: service.address,
    });
    const recordAccount = svm.getAccount(record);
    if (!recordAccount.exists) throw new Error("record missing");
    expect(recordAccount.lamports).toBe(rent);
    const decoded = getTaskModerationDecoder().decode(recordAccount.data);
    expect(decoded.creator).toBe(buyer.address);
    expect(decoded.moderator).toBe(service.address);
    expect(decoded.status).toBe(0);
    // The record says the creator paid, so its rent goes back to the creator.
    expect(decoded.reserved[0]).toBe(1);
    expect(facade.taskModerationRentRecipient(decoded)).toBe(buyer.address);

    // The buyer cancels, then tidies with close_task.
    const feePayer = await market.fundedSigner();
    await send(feePayer, [
      await facade.cancelTask({ task, authority: buyer, workerBondAuthority: buyer.address }),
    ]);
    const [validationConfig] = await findTaskValidationConfigPda({ task });
    const [escrow] = await findEscrowPda({ task });
    const closeTo = async (recipient: Address) =>
      facade.closeTask({
        task,
        authority: buyer,
        taskJobSpec: null,
        children: [
          { kind: "creatorFunded", account: validationConfig },
          { kind: "namedRecipient", account: record, recipient },
        ],
      });
    // The program will not hand the buyer's deposit to the service: the
    // record's stored recipient (the creator, who paid) must be the one named.
    await expect(send(feePayer, [await closeTo(service.address)])).rejects.toThrow(
      /TaskChildRentRecipientRequired/,
    );

    const taskLamports = balance(task);
    const children = balance(validationConfig) + balance(record) + balance(escrow);
    const markerRent = svm.minimumBalanceForRentExemption(BigInt(getTaskMarkerSize()));
    const buyerBeforeClose = balance(buyer.address);
    svm.expireBlockhash();
    await send(feePayer, [await closeTo(buyer.address)]);

    // Everything above the marker's rent came back to the buyer, the
    // moderation deposit included, and the service got nothing.
    expect(balance(buyer.address) - buyerBeforeClose).toBe(taskLamports - markerRent + children);
    expect(svm.getAccount(record).exists).toBe(false);
    expect(balance(service.address)).toBe(serviceBefore);
  });

  it("refuses, as the program does, a payer that is not the task's creator (6433)", async () => {
    const buyer = market.payer;
    const stranger = await market.fundedSigner();
    const task = await createTask(buyer, 32);
    await stamp(9);
    const hash = await values.canonicalJobSpecHash(PAYLOAD);
    registryServes(hash.hex);

    const refused = await attestTask(DEPS, {
      task,
      jobSpecHash: hash.hex,
      spec: PAYLOAD,
      payer: stranger.address,
    }).then(
      () => null,
      (cause: unknown) => cause,
    );
    expect(refused).toBeInstanceOf(ModerationRejectError);
    expect((refused as ModerationRejectError).code).toBe("PAYER_NOT_TASK_CREATOR");

    await expect(
      send(stranger, [await recordInstruction({ task, moderator: service, rentPayer: stranger, hash: hash.bytes })]),
    ).rejects.toThrow(/InvalidModerationRentPayer/);
  });

  it("refuses, as the program does, a task created by its own signer (6432)", async () => {
    const task = await createTask(service, 33);
    await stamp(9);
    const hash = await values.canonicalJobSpecHash(PAYLOAD);
    registryServes(hash.hex);

    const refused = await attestTask(
      { ...DEPS, requesterPays: false },
      { task, jobSpecHash: hash.hex, spec: PAYLOAD },
    ).then(
      () => null,
      (cause: unknown) => cause,
    );
    expect(refused).toBeInstanceOf(ModerationRejectError);
    expect((refused as ModerationRejectError).code).toBe("MODERATOR_IS_TASK_CREATOR");
    expect(rpcState.sends).toBe(0);

    await expect(
      send(service, [await recordInstruction({ task, moderator: service, rentPayer: service, hash: hash.bytes })]),
    ).rejects.toThrow(/ModeratorIsTaskCreator/);
  });
});

describe("a listing approval on the revision 9 program", () => {
  it("keeps its transfer shape, runs, and leaves the service's signer even", async () => {
    const provider = await market.fundedSigner();
    const hash = await values.canonicalJobSpecHash(PAYLOAD);
    const listing = await createListing(provider, hash.bytes);
    await stamp(9);
    registryServes(hash.hex);

    const result = await attestListing(DEPS, { listing, spec: PAYLOAD, payer: provider.address });

    expect(rpcState.sends).toBe(0);
    const rent = svm.minimumBalanceForRentExemption(BigInt(getListingModerationSize()));
    const wire = new Uint8Array(Buffer.from(result.payment!.transaction, "base64"));
    const checked = await checkApprovalTransaction(wire, {
      payer: provider.address,
      moderator: service.address,
      target: { kind: "listing", listing, hash: hash.bytes },
      maxDepositLamports: rent,
    });
    expect(checked.depositLamports).toBe(rent);

    const serviceBefore = balance(service.address);
    const providerBefore = balance(provider.address);
    const signed = await partiallySignTransaction([provider.keyPair], getTransactionDecoder().decode(wire));
    const execution = svm.sendTransaction(signed);
    if (execution instanceof FailedTransactionMetadata) {
      throw new Error(`${String(execution.err())}\n${execution.meta().logs().join("\n")}`);
    }
    // The transfer in covers exactly the deposit the program takes out.
    expect(balance(service.address)).toBe(serviceBefore);
    expect(providerBefore - balance(provider.address)).toBe(rent + 2n * SIGNATURE_FEE);
    const [record] = await findListingModerationPda({ listing, jobSpecHash: hash.bytes, moderator: service.address });
    expect(svm.getAccount(record).exists).toBe(true);
  });

  it("refuses, as the program does, a listing its own signer provides (6434)", async () => {
    const hash = await values.canonicalJobSpecHash(PAYLOAD);
    const listing = await createListing(service, hash.bytes);
    await stamp(9);
    registryServes(hash.hex);
    const payer = await market.fundedSigner();

    const refused = await attestListing(DEPS, { listing, spec: PAYLOAD, payer: payer.address }).then(
      () => null,
      (cause: unknown) => cause,
    );
    expect(refused).toBeInstanceOf(ModerationRejectError);
    expect((refused as ModerationRejectError).code).toBe("MODERATOR_IS_LISTING_PROVIDER");

    await expect(
      send(service, [
        await facade.recordListingModeration({
          listing,
          moderator: service,
          jobSpecHash: hash.bytes,
          status: 0,
          riskScore: 0,
          categoryMask: 0n,
          policyHash: new Uint8Array(32).fill(1),
          scannerHash: new Uint8Array(32).fill(2),
          expiresAt: 0n,
        }),
      ]),
    ).rejects.toThrow(/ModeratorIsListingProvider/);
  });
});

describe("the weekly heartbeat on the revision 9 program", () => {
  it("bumps the deadman timestamp, leaves the window alone, and sends only once a week", async () => {
    await stamp(9);
    const [configPda] = await findModerationConfigPda();
    const read = () => {
      const account = svm.getAccount(configPda);
      if (!account.exists) throw new Error("ModerationConfig missing");
      return getModerationConfigDecoder().decode(account.data);
    };
    const before = read();
    expect(before.updatedAt).toBe(0n);
    const vmNow = () => Number(svm.getClock().unixTimestamp);
    const serviceBefore = balance(service.address);

    const report = await runModerationHeartbeat({ rpcUrl: DEPS.rpcUrl, enabled: true, now: vmNow });

    expect(report).toMatchObject({ sent: true, outcome: "sent" });
    expect(rpcState.sends).toBe(1);
    const after = read();
    expect(after.updatedAt).toBe(svm.getClock().unixTimestamp);
    // Same window bytes, same authorities: only the timestamp moved.
    expect(Array.from(after.reserved)).toEqual(Array.from(before.reserved));
    expect(after.moderationAuthority).toBe(service.address);
    // One signature fee from the service's signer.
    expect(serviceBefore - balance(service.address)).toBe(SIGNATURE_FEE);

    // The next check finds it not due.
    svm.expireBlockhash();
    const again = await runModerationHeartbeat({ rpcUrl: DEPS.rpcUrl, enabled: true, now: vmNow });
    expect(again).toMatchObject({ sent: false, outcome: "not-due" });
    expect(rpcState.sends).toBe(1);
  });

  it("is needed: the revision 8 two-account wire fails on this program", async () => {
    await stamp(9);
    const instruction = await facade.moderationHeartbeat({ authority: service, newWindowSecs: null });
    const revision8Wire = { ...instruction, accounts: instruction.accounts.slice(0, 2) };

    await expect(send(service, [revision8Wire as Instruction])).rejects.toThrow(
      /caused by account: protocol_config. Error Code: AccountNotEnoughKeys/,
    );
  });

  it("sends nothing on a revision 8 stamp", async () => {
    await stamp(8);

    const report = await runModerationHeartbeat({
      rpcUrl: DEPS.rpcUrl,
      enabled: true,
      now: () => Number(svm.getClock().unixTimestamp),
    });

    expect(report).toMatchObject({ sent: false, outcome: "unsupported-revision", surfaceRevision: 8 });
    expect(rpcState.sends).toBe(0);
  });
});

describe.skipIf(!REVISION8_SO)("why the service signs only on a revision 9 stamp (AGENC_TEST_REVISION8_SO)", () => {
  it("the revision 9 approval sent to a revision 8 program would charge the service's signer the deposit", async () => {
    const old = await startLocalMarketplace({
      unixTimestamp: BigInt(Math.floor(Date.now() / 1000)),
      programPath: REVISION8_SO!,
    });
    await seedModerationConfig(old.svm, old.admin.address, service.address, true);
    old.svm.airdrop(service.address, lamports(1_000_000_000n));
    const buyer = old.payer;
    const task = await createTask(buyer, 41, old.svm);
    const hash = await values.canonicalJobSpecHash(PAYLOAD);
    const rent = old.svm.minimumBalanceForRentExemption(BigInt(getTaskModerationSize()));
    const serviceBefore = old.svm.getBalance(service.address) ?? 0n;
    const buyerBefore = old.svm.getBalance(buyer.address) ?? 0n;

    // The exact revision 9 shape: the buyer named as rent payer and fee payer.
    await send(
      buyer,
      [await recordInstruction({ task, moderator: service, rentPayer: buyer, hash: hash.bytes })],
      old.svm,
    );

    // Revision 8 ignores the appended rent payer and charges the moderator.
    expect(serviceBefore - (old.svm.getBalance(service.address) ?? 0n)).toBe(rent);
    expect(buyerBefore - (old.svm.getBalance(buyer.address) ?? 0n)).toBe(2n * SIGNATURE_FEE);
  });
});
