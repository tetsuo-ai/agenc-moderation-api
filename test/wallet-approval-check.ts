/**
 * The approval check the revision 9 AgenC wallet (vendored by Desktop) runs
 * on every transaction this service hands out, before it adds the payer's
 * signature. Ported line for line from agenc-protocol
 * `packages/agenc-wallet/src/approval.ts` `checkApprovalTransaction`
 * (branch rev9/clients, f3b5820), so the tests hold the service to exactly
 * what Desktop accepts. Only the error type differs: a refusal throws
 * `WalletRefusal` with the wallet's own reason.
 *
 * For a job (revision 9): one `record_task_moderation` instruction, for this
 * task and hash, in which the payer is named once, as the record's rent payer
 * (its seventh account). For a service: at most a plain transfer from the
 * payer to the approver of no more than the deposit, then one
 * `record_listing_moderation` in which the payer takes no part.
 */
import {
  getCompiledTransactionMessageDecoder,
  getCompiledTransactionMessageEncoder,
  getTransactionDecoder,
  type Address,
  type Transaction,
} from "@solana/kit";
import {
  AGENC_COORDINATION_PROGRAM_ADDRESS,
  findListingModerationPda,
  findModerationAttestorPda,
  findModerationConfigPda,
  findTaskModerationPda,
  getRecordListingModerationDiscriminatorBytes,
  getRecordListingModerationInstructionDataDecoder,
  getRecordTaskModerationDiscriminatorBytes,
  getRecordTaskModerationInstructionDataDecoder,
} from "@tetsuo-ai/marketplace-sdk";

export type ApprovalTarget =
  | { kind: "task"; task: Address; hash: Uint8Array }
  | { kind: "listing"; listing: Address; hash: Uint8Array };

export class WalletRefusal extends Error {
  constructor(public readonly reason: string) {
    super(`approval transaction refused: ${reason}`);
    this.name = "WalletRefusal";
  }
}

const SYSTEM_PROGRAM_ADDRESS = "11111111111111111111111111111111";
const MAX_TRANSACTION_BYTES = 1232;
const STATUS_CLEAN = 0;
const SYSTEM_TRANSFER = 2;

function refuse(why: string): never {
  throw new WalletRefusal(why);
}

function sameBytes(a: ArrayLike<number>, b: ArrayLike<number>): boolean {
  if (a.length !== b.length) return false;
  for (let index = 0; index < a.length; index += 1) {
    if (a[index] !== b[index]) return false;
  }
  return true;
}

export interface CheckedApproval {
  transaction: Transaction;
  depositLamports: bigint;
}

export async function checkApprovalTransaction(
  wire: Uint8Array,
  expected: {
    payer: Address;
    moderator: Address;
    target: ApprovalTarget;
    maxDepositLamports: bigint;
  },
): Promise<CheckedApproval> {
  if (wire.length === 0 || wire.length > MAX_TRANSACTION_BYTES) refuse("not the size of a transaction");
  if (expected.payer === expected.moderator) refuse("the payer is the approver");

  let transaction: Transaction;
  let message: ReturnType<ReturnType<typeof getCompiledTransactionMessageDecoder>["decode"]>;
  try {
    transaction = getTransactionDecoder().decode(wire);
    message = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
  } catch {
    refuse("it does not decode");
  }
  if (message.version !== 0) refuse("not a version 0 message");
  if (
    !sameBytes(
      getCompiledTransactionMessageEncoder().encode(message),
      transaction.messageBytes,
    )
  ) {
    refuse("the message holds more than was read");
  }
  if ("addressTableLookups" in message && (message.addressTableLookups?.length ?? 0) > 0) {
    refuse("it uses lookup tables");
  }

  const accounts: readonly Address[] = message.staticAccounts;
  if (new Set(accounts).size !== accounts.length) refuse("an account is named twice");
  if (message.header.numSignerAccounts !== 2 || message.header.numReadonlySignerAccounts !== 0) {
    refuse("the wrong number of signers");
  }
  if (accounts[0] !== expected.payer) refuse("somebody else pays the fee");
  if (accounts[1] !== expected.moderator) refuse("somebody else signs the approval");
  const signers = Object.keys(transaction.signatures);
  if (
    signers.length !== 2 ||
    !(expected.payer in transaction.signatures) ||
    transaction.signatures[expected.moderator] == null
  ) {
    refuse("the approver has not signed it");
  }

  const instructions = message.instructions;
  if (instructions.length !== 1 && instructions.length !== 2) refuse("the wrong number of steps");
  if (expected.target.kind === "task" && instructions.length !== 1) {
    refuse("a job's approval pays its deposit by a transfer");
  }

  let depositLamports = 0n;
  if (instructions.length === 2) {
    const transfer = instructions[0]!;
    const indices = transfer.accountIndices ?? [];
    const data = transfer.data ?? new Uint8Array();
    if (accounts[transfer.programAddressIndex] !== SYSTEM_PROGRAM_ADDRESS) {
      refuse("the first step is not a transfer");
    }
    if (indices.length !== 2 || indices[0] !== 0 || indices[1] !== 1) {
      refuse("the transfer is not from the payer to the approver");
    }
    if (data.length !== 12) refuse("the transfer is malformed");
    const view = new DataView(Uint8Array.from(data).buffer);
    if (view.getUint32(0, true) !== SYSTEM_TRANSFER) refuse("the first step is not a plain transfer");
    depositLamports = view.getBigUint64(4, true);
    if (depositLamports === 0n || depositLamports > expected.maxDepositLamports) {
      refuse(`the transfer is ${depositLamports}, above the deposit of ${expected.maxDepositLamports}`);
    }
  }

  const approval = instructions[instructions.length - 1]!;
  if (accounts[approval.programAddressIndex] !== AGENC_COORDINATION_PROGRAM_ADDRESS) {
    refuse("the approval is not the marketplace's");
  }
  const { target, moderator } = expected;
  const [config] = await findModerationConfigPda();
  const [roster] = await findModerationAttestorPda({ attestor: moderator });
  const [record] =
    target.kind === "task"
      ? await findTaskModerationPda({ task: target.task, jobSpecHash: target.hash, moderator })
      : await findListingModerationPda({
          listing: target.listing,
          jobSpecHash: target.hash,
          moderator,
        });
  const subject = target.kind === "task" ? target.task : target.listing;
  const named = (approval.accountIndices ?? []).map((index) => accounts[index]);
  if (
    named.length !== (target.kind === "task" ? 7 : 6) ||
    named[0] !== config ||
    named[1] !== subject ||
    named[2] !== moderator ||
    named[3] !== record ||
    (named[4] !== roster && named[4] !== AGENC_COORDINATION_PROGRAM_ADDRESS) ||
    named[5] !== SYSTEM_PROGRAM_ADDRESS ||
    (target.kind === "task" && named[6] !== expected.payer)
  ) {
    refuse("the approval is for something else");
  }
  const payerPlaces = named.filter((account) => account === expected.payer).length;
  if (payerPlaces !== (target.kind === "task" ? 1 : 0)) {
    refuse("the payer takes part in the approval");
  }

  const decoder =
    target.kind === "task"
      ? getRecordTaskModerationInstructionDataDecoder()
      : getRecordListingModerationInstructionDataDecoder();
  const discriminator =
    target.kind === "task"
      ? getRecordTaskModerationDiscriminatorBytes()
      : getRecordListingModerationDiscriminatorBytes();
  const data = approval.data ?? new Uint8Array();
  if (data.length !== decoder.fixedSize) refuse("the approval is malformed");
  const fields = decoder.decode(data);
  if (!sameBytes(fields.discriminator, discriminator)) refuse("the second step is not an approval");
  if (!sameBytes(fields.jobSpecHash, target.hash)) refuse("the approval is for other words");
  if (fields.status !== STATUS_CLEAN) refuse("the approval does not pass the words");

  return { transaction, depositLamports };
}
