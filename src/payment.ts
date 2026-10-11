/** Creator-funded revision 5 records. This module never submits transactions. */
import {
  AccountRole, address, appendTransactionMessageInstructions, assertIsTransactionPartialSigner,
  compileTransaction, createSolanaRpc, createTransactionMessage, getBase64EncodedWireTransaction,
  partiallySignTransactionWithSigners, pipe, setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash, type Instruction, type TransactionSigner,
} from '@solana/kit';
import { AGENC_COORDINATION_PROGRAM_ADDRESS, getTaskModerationSize } from '@tetsuo-ai/marketplace-sdk';
import { ModerationRejectError } from './errors.js';

export interface PaymentPrice { priceLamports: number; rentLamports: number; serviceFeeLamports: number }
export interface PaymentOffer extends PaymentPrice { transaction: string; lastValidBlockHeight: number; recordPda: string; moderator: string }
export function validatePrice(price: PaymentPrice): void {
  if (![price.priceLamports,price.rentLamports,price.serviceFeeLamports].every(n=>Number.isSafeInteger(n) && n>=0) ||
      price.priceLamports !== price.rentLamports + price.serviceFeeLamports || price.priceLamports < price.rentLamports)
    throw new ModerationRejectError(503,'Invalid attestation price; transfer must cover rent.');
}
export async function readPaymentPrice(rpcUrl: string, serviceFeeLamports = 0): Promise<PaymentPrice> {
  const rent = await createSolanaRpc(rpcUrl).getMinimumBalanceForRentExemption(BigInt(getTaskModerationSize())).send();
  const price = {rentLamports:Number(rent),serviceFeeLamports,priceLamports:Number(rent)+serviceFeeLamports};
  validatePrice(price); return price;
}
export async function buildPaymentOffer(rpcUrl: string, creator: string, moderator: TransactionSigner,
  recordPda: string, instruction: Instruction, price: PaymentPrice): Promise<PaymentOffer> {
  validatePrice(price);
  // R receives the rent before the program debits it, and never pays network fees.
  if (creator === moderator.address) throw new ModerationRejectError(409,'Moderator must not be the fee payer.');
  if (instruction.programAddress !== AGENC_COORDINATION_PROGRAM_ADDRESS)
    throw new ModerationRejectError(503,'Unexpected record program.');
  const rpc=createSolanaRpc(rpcUrl);
  // Reissues retain their signed price. A rent increase cannot debit R's balance.
  const currentRent=await rpc.getMinimumBalanceForRentExemption(BigInt(getTaskModerationSize())).send();
  if (BigInt(price.rentLamports) < currentRent) throw new ModerationRejectError(409,'Rent increased; original payment cannot be reissued.');
  const {value:lifetime}=await rpc.getLatestBlockhash({commitment:'confirmed'}).send();
  if(lifetime.lastValidBlockHeight <= await rpc.getBlockHeight({commitment:'confirmed'}).send()) throw new ModerationRejectError(503,'RPC returned an expired blockhash.');
  const lastValidBlockHeight=Number(lifetime.lastValidBlockHeight);
  if(!Number.isSafeInteger(lastValidBlockHeight)) throw new ModerationRejectError(503,'Invalid block height.');
  const data=Buffer.alloc(12);data.writeUInt32LE(2,0);data.writeBigUInt64LE(BigInt(price.priceLamports),4);
  const transfer:Instruction={programAddress:address('11111111111111111111111111111111'),accounts:[
    {address:address(creator),role:AccountRole.WRITABLE_SIGNER},
    {address:moderator.address,role:AccountRole.WRITABLE},
  ],data};
  // No priority-fee or compute-budget instructions: exactly transfer, then record.
  const message=pipe(createTransactionMessage({version:0}),m=>setTransactionMessageFeePayer(address(creator),m),
    m=>setTransactionMessageLifetimeUsingBlockhash(lifetime,m),m=>appendTransactionMessageInstructions([transfer,instruction],m));
  assertIsTransactionPartialSigner(moderator);
  const signed=await partiallySignTransactionWithSigners([moderator],compileTransaction(message));
  if(!signed.signatures[moderator.address] || signed.signatures[address(creator)]) throw new ModerationRejectError(503,'Invalid partial signatures.');
  return {...price,transaction:getBase64EncodedWireTransaction(signed),lastValidBlockHeight,recordPda,moderator:moderator.address};
}
