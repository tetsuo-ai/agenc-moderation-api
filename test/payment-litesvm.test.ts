/** Real compiled revision 5 program, in-process LiteSVM and throwaway keys only.
 * Service RPC reads are adapted to the local VM; its send RPC is a hard failure. */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { address, createKeyPairSignerFromBytes, decompileTransactionMessage,
  getCompiledTransactionMessageDecoder, getTransactionDecoder, lamports, partiallySignTransaction,
  type Address, type Instruction, type Transaction } from '@solana/kit';
import { facade, findCompletionBondPda, findTaskPda, getTaskModerationDecoder, getTaskModerationSize, values } from '@tetsuo-ai/marketplace-sdk';
import { startLocalMarketplace, type LocalMarketplace } from '@tetsuo-ai/marketplace-sdk/testing';
import { FailedTransactionMetadata, type LiteSVM } from 'litesvm';
import { base58Encode } from '../src/base58.js';
import { installPayerFixture, installVerdictFixture } from './fixtures.js';
import { AttestationStore } from '../src/store.js';
import { attestTask, getStoredAttestation } from '../src/signer.js';

const rpcState=vi.hoisted(()=>({svm:null as LiteSVM|null,signature:'',receipt:null as unknown,readSizes:[] as bigint[],sendCalls:0}));
vi.mock('@solana/kit',async original=>({...await original<typeof import('@solana/kit')>(),createSolanaRpc:()=>({
 getAccountInfo:(pubkey:Address)=>({send:async()=>{
  const account=rpcState.svm!.getAccount(pubkey);
  return {context:{slot:1n},value:account.exists ? {data:[Buffer.from(account.data).toString('base64'),'base64'],owner:account.programAddress,lamports:account.lamports,space:account.space,executable:account.executable,rentEpoch:0n} : null};
 }}),
 getGenesisHash:()=>({send:async()=> 'genesis-local-litesvm'}),
 getMinimumBalanceForRentExemption:(size:bigint)=>({send:async()=>{rpcState.readSizes.push(size);return rpcState.svm!.minimumBalanceForRentExemption(size);}}),
 getLatestBlockhash:()=>({send:async()=>({value:{blockhash:rpcState.svm!.latestBlockhash(),lastValidBlockHeight:100n}})}),
 getBlockHeight:()=>({send:async()=>1n}),
 getSignaturesForAddress:()=>({send:async()=>[{signature:rpcState.signature,err:null}]}),
 getTransaction:()=>({send:async()=>rpcState.receipt}),
 sendTransaction:()=>({send:async()=>{rpcState.sendCalls++;throw Error('Service must never submit a transaction');}}),
})}));
const PAYLOAD={title:'Summarize three research papers'};
let fixture:ReturnType<typeof installVerdictFixture>,store:AttestationStore,market:LocalMarketplace;
let R:Awaited<ReturnType<typeof createKeyPairSignerFromBytes>>,task:Address,hash:string;
beforeEach(async()=>{
 fixture=installVerdictFixture();installPayerFixture();store=new AttestationStore(':memory:');
 R=await createKeyPairSignerFromBytes(Uint8Array.from(JSON.parse(process.env.MODERATION_SIGNER_SECRET!)));
 market=await startLocalMarketplace({unixTimestamp:BigInt(Math.floor(Date.now()/1000))});
 Object.assign(rpcState,{svm:market.svm,signature:'',receipt:null,readSizes:[],sendCalls:0});
 market.svm.airdrop(R.address,lamports(10_000_000_000n));
 // Register the actual R roster entry using a throwaway key, inside LiteSVM.
 await market.clientFor(R).send([await facade.registerModerationAttestor({attestor:R})]);
 const taskId=new Uint8Array(32).fill(17);const committed=await values.canonicalJobSpecHash(PAYLOAD);hash=committed.hex;
 const description=new Uint8Array(64);description.set(committed.bytes);
 await market.client.send([await facade.createTaskHumanless({creator:market.payer,taskId,description,requiredCapabilities:1n,
  rewardAmount:100_000_000n,deadline:BigInt(Math.floor(Date.now()/1000)+86400),minReputation:0,reviewWindowSecs:3600n})]);
 [task]=await findTaskPda({creator:market.payer.address,taskId});
 vi.stubGlobal('fetch',vi.fn(async(_input,init)=>{expect(init?.method ?? 'GET').toBe('GET');return new Response(JSON.stringify(PAYLOAD));}));
});
afterEach(()=>{store?.close();fixture?.cleanup();delete process.env.MODERATION_SIGNER_SECRET;vi.unstubAllGlobals();rpcState.svm=null;});
function zeroModeratorBalance() {
 const account=market.svm.getAccount(R.address);if(!account.exists) throw Error('R missing');
 market.svm.setAccount({...account,lamports:lamports(0n)});
}
function deps(fee=0) {return {rpcUrl:'https://local-rpc.test',attestationTtlSeconds:72*3600,store,attestationServiceFeeLamports:fee};}
async function coSign(wire:string) {
 return partiallySignTransaction([market.payer.keyPair],getTransactionDecoder().decode(Buffer.from(wire,'base64')));
}
function journalReceipt(tx:Transaction,signature:Uint8Array) {
 rpcState.signature=base58Encode(signature);
 const message=decompileTransactionMessage(getCompiledTransactionMessageDecoder().decode(tx.messageBytes));
 const instructions:Instruction[]=[...message.instructions];
 const keys=[...new Set(instructions.flatMap(ix=>[ix.programAddress,...ix.accounts!.map(a=>a.address)]))];
 rpcState.receipt={meta:{err:null},transaction:{message:{accountKeys:keys,instructions:instructions.map(ix=>({
  programIdIndex:keys.indexOf(ix.programAddress),accounts:ix.accounts!.map(a=>keys.indexOf(a.address)),data:base58Encode(new Uint8Array(ix.data!)),
 }))}}};
}
it.each([0,12345])('executes the API offer against the compiled program; R never decreases with fee %i',async fee=>{
 const moderatorBefore=fee===0 ? 0n : market.svm.minimumBalanceForRentExemption(0n);
 const wallet=market.svm.getAccount(R.address);if(!wallet.exists) throw Error('R missing');
 market.svm.setAccount({...wallet,lamports:lamports(moderatorBefore)});
 const creatorBefore=market.svm.getBalance(market.payer.address)!;
 const result=await attestTask(deps(fee),{task,jobSpecHash:hash,spec:PAYLOAD});
 const rent=market.svm.minimumBalanceForRentExemption(BigInt(getTaskModerationSize()));
 expect(rent).toBe(2519520n);expect(result.rentLamports).toBe(Number(rent));expect(rpcState.readSizes.every(n=>n===BigInt(getTaskModerationSize()))).toBe(true);
 expect(result.signedVerdict!.body.payment).toEqual({recordPda:result.recordPda,payer:market.payer.address,priceLamports:Number(rent)+fee});
 const signed=await coSign(result.transaction!);const execution=market.svm.sendTransaction(signed);
 if(execution instanceof FailedTransactionMetadata) throw Error(execution.err()+'\n'+execution.meta().logs().join('\n'));
 expect(market.svm.getBalance(R.address) ?? 0n).toBe(moderatorBefore+BigInt(fee));
 expect(creatorBefore-market.svm.getBalance(market.payer.address)!).toBe(rent+BigInt(fee)+10_000n);
 const account=market.svm.getAccount(address(result.recordPda!));if(!account.exists) throw Error('Record missing');
 expect(account.lamports).toBe(rent);expect(account.data.length).toBe(getTaskModerationSize());
 const record=getTaskModerationDecoder().decode(account.data);expect(record.creator).toBe(market.payer.address);expect(record.moderator).toBe(R.address);expect(record.status).toBe(0);
 journalReceipt(signed,execution.signature());
 const paid=await getStoredAttestation(deps(fee),task,hash);expect(paid?.transaction).toBeUndefined();expect(paid?.attestation?.signature).toBe(rpcState.signature);
 // Exercise actual close_task rent destination too, after creator cancellation.
 await market.client.send([await facade.cancelTask({task,authority:market.payer,workerBondAuthority:market.payer.address})]);
 const [creatorCompletionBond]=await findCompletionBondPda({task,party:market.payer.address});
 await market.client.send([await facade.closeTask({task,authority:market.payer,creatorCompletionBond,taskJobSpec:null,
  children:[{kind:'namedRecipient',account:address(result.recordPda!),recipient:R.address}]})]);
 expect(market.svm.getBalance(R.address)).toBe(moderatorBefore+rent+BigInt(fee));expect(market.svm.getAccount(address(result.recordPda!)).exists).toBe(false);
 expect(rpcState.sendCalls).toBe(0);
});
it('real program failure rolls back the transfer and preserves R balance',async()=>{
 const result=await attestTask(deps(),{task,jobSpecHash:hash,spec:PAYLOAD});
 // The on-chain roster exits after the offer; record_task_moderation must fail.
 await market.clientFor(R).send([await facade.requestAttestorExit({attestor:R})]);
 zeroModeratorBalance();const creatorBefore=market.svm.getBalance(market.payer.address)!;
 const execution=market.svm.sendTransaction(await coSign(result.transaction!));
 expect(execution).toBeInstanceOf(FailedTransactionMetadata);expect((execution as FailedTransactionMetadata).meta().logs().join('\n')).toContain('AttestorExiting');
 expect(market.svm.getBalance(R.address) ?? 0n).toBe(0n);expect(creatorBefore-market.svm.getBalance(market.payer.address)!).toBe(10_000n);
 expect(market.svm.getAccount(address(result.recordPda!)).exists).toBe(false);expect(rpcState.sendCalls).toBe(0);
});
