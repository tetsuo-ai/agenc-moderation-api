/** Real signing core, with every RPC and registry boundary mocked. No live transactions. */
import { join } from 'node:path';
import { createHash, sign, verify } from 'node:crypto';
import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest';
import { values, getTaskModerationSize, AGENC_COORDINATION_PROGRAM_ADDRESS, parseRecordTaskModerationInstruction } from '@tetsuo-ai/marketplace-sdk';
import { getTransactionDecoder, getCompiledTransactionMessageDecoder, decompileTransactionMessage, partiallySignTransaction, createKeyPairSignerFromBytes, address, type Transaction } from '@solana/kit';
import { base58Encode } from '../src/base58.js';
import { installVerdictFixture, installPayerFixture, creatorFixture, recordReceipt } from './fixtures.js';
import { AttestationStore, DEFAULT_SPEND_LIMITS } from '../src/store.js';
import { creatorRequestBytes } from '../src/binding.js';
import { documentBytes, publicKeyFromAddress } from '../src/verdict.js';
import { moderationPolicyHashBytes } from '../src/policy.js';
import { scannerHashBytes } from '../src/scan.js';
const state = vi.hoisted(()=>({creator:'',hash:'',moderator:'',status:0,workers:0,completions:0,exists:true,pinned:'',record:null as any,balance:1_000_000_000n,rent:2519520n,blockhashByte:7,lastValid:100n,receiptUnrelated:false,fee:5200n,events:[] as string[],registry:true,timeout:false,height:1n,sendError:false}));
vi.mock('@solana/kit',async original=>{const actual=await original<typeof import('@solana/kit')>();return {...actual,partiallySignTransactionWithSigners:async(...args:Parameters<typeof actual.partiallySignTransactionWithSigners>)=>{state.events.push('transaction-sign');return actual.partiallySignTransactionWithSigners(...args);},createSolanaRpc:()=>({
 getGenesisHash:()=>({send:async()=> 'genesis-test'}),
 getLatestBlockhash:()=>({send:async()=>({value:{blockhash:base58Encode(new Uint8Array(32).fill(state.blockhashByte)),lastValidBlockHeight:state.lastValid}})}),
 getFeeForMessage:()=>({send:async()=>({value:state.fee})}),
 getMinimumBalanceForRentExemption:(size:bigint)=>({send:async()=>{expect(size).toBe(BigInt(getTaskModerationSize()));return state.rent;}}),
 getTransaction:()=>({send:async()=>{const receipt=await recordReceipt(state.record ?? record());if(state.receiptUnrelated)receipt.transaction.message.instructions[0].data=base58Encode(new Uint8Array(8));return receipt;}}),
 getSignaturesForAddress:()=>({send:async()=>[{signature:base58Encode(new Uint8Array(64).fill(9)),err:null}]}),
 getBalance:()=>({send:async()=>{state.events.push('balance');return {value:state.balance};}}),
 sendTransaction:()=>({send:async()=>{state.events.push('send');if(state.sendError) throw new Error('ambiguous');return 'sig';}}),
 getSignatureStatuses:()=>({send:async()=>({value:state.timeout ? [null] : [{err:null,confirmationStatus:'confirmed'}]})}),
 getBlockHeight:()=>({send:async()=>state.height})
})};});
vi.mock('@tetsuo-ai/marketplace-sdk',async original=>({...await original<typeof import('@tetsuo-ai/marketplace-sdk')>(),
 fetchMaybeTask:async()=>({exists:state.exists,data:{creator:state.creator,status:state.status,currentWorkers:state.workers,completions:state.completions,description:Buffer.from(state.hash,'hex')}}),
 fetchMaybeTaskJobSpec:async()=>state.pinned ? {exists:true,data:{jobSpecHash:Buffer.from(state.pinned,'hex'),jobSpecUri:'https://spec.test'}} : {exists:false},
 fetchMaybeTaskModeration:async()=>{state.events.push('record-read');return state.record ? {exists:true,data:state.record} : {exists:false};},
 fetchMaybeModerationConfig:async()=>({exists:true,data:{moderationAuthority:base58Encode(new Uint8Array(32).fill(4))}}),
 fetchMaybeModerationAttestor:async()=>({exists:true,data:{attestor:state.moderator,exitAt:0n}})
}));
vi.mock('../src/ssrf-fetch.js',async original=>({...await original<typeof import('../src/ssrf-fetch.js')>(),fetchJobSpecBody:async()=>{const text=JSON.stringify(PAYLOAD);return {text,sha256:createHash('sha256').update(text).digest('hex')};}}));
import { attestTask, type AttestDeps } from '../src/signer.js';
import { createModerationApi } from '../src/router.js';
import { __resetRateLimiterForTests } from '../src/rate-limit.js';
const TASK='9UEu2Gv9Q7DwBtumR2rUSq5g8v7b6mxn26ZNQCky82RJ';
const PAYLOAD={title:'Summarize three research papers'};
let creator:ReturnType<typeof creatorFixture>;
let fixture: ReturnType<typeof installVerdictFixture>; let payer: ReturnType<typeof installPayerFixture>; let store: AttestationStore; let deps: AttestDeps; let hash: string;
beforeEach(async()=>{
 fixture=installVerdictFixture();payer=installPayerFixture();creator=creatorFixture();store=new AttestationStore(':memory:');
 hash=(await values.canonicalJobSpecHash(PAYLOAD)).hex;
 Object.assign(state,{creator:creator.address,moderator:payer.address,hash,status:0,workers:0,completions:0,exists:true,pinned:'',record:null,balance:1_000_000_000n,fee:5200n,events:[],registry:true,timeout:false,height:1n,sendError:false,rent:2519520n,blockhashByte:7,lastValid:100n,receiptUnrelated:false});
 deps={rpcUrl:'https://rpc.test',attestationTtlSeconds:72*3600,jobSpecRegistryUrl:'https://registry.test',store};
 vi.stubGlobal('fetch',vi.fn(async(_input,init)=>{expect(init?.method ?? 'GET').toBe('GET');return new Response(JSON.stringify(PAYLOAD),{status:state.registry?200:404});}));
 __resetRateLimiterForTests();
});
afterEach(()=>{store.close();fixture.cleanup();delete process.env.MODERATION_SIGNER_SECRET;delete process.env.CONFIRMATION_TIMEOUT_MS;vi.unstubAllGlobals();});
function params(){return {task:TASK,jobSpecHash:hash,spec:PAYLOAD};}
function record(){return {task:TASK,creator:state.creator,moderator:state.moderator,jobSpecHash:Buffer.from(hash,'hex'),status:0,riskScore:0,categoryMask:0n,policyHash:moderationPolicyHashBytes(),scannerHash:scannerHashBytes(),recordedAt:BigInt(Math.floor(Date.now()/1000)),expiresAt:BigInt(Math.floor(Date.now()/1000)+72*3600)};}
function authorization(){const auth={issuedAt:new Date().toISOString(),nonce:'ab'.repeat(16)};return {...auth,signature:sign(null,creatorRequestBytes(state.creator,TASK,hash,auth),creator.privateKey).toString('hex')};}
describe('desktop intake money path',()=>{
 it('refuses the unauthenticated rent drain before registry traffic or signing',async()=>{
  state.hash='ab'.repeat(32);
  await expect(attestTask(deps,params())).rejects.toMatchObject({httpStatus:403});
  expect(fetch).not.toHaveBeenCalled();expect(state.events).not.toContain('send');expect(state.events).not.toContain('transaction-sign');expect(store.get(TASK)).toBeUndefined();
 });
 it.each(['missing','closed','workers','completions','pinned'])('refuses invalid task condition: %s',async kind=>{
  if(kind==='missing') state.exists=false;if(kind==='closed') state.status=1;if(kind==='workers') state.workers=1;if(kind==='completions') state.completions=1;if(kind==='pinned') state.pinned='ab'.repeat(32);
  await expect(attestTask(deps,params())).rejects.toBeDefined();expect(state.events).not.toContain('send');expect(state.events).not.toContain('transaction-sign');
 });
 it('accepts creator wallet authorization and consumes nonce once',async()=>{
  state.hash='ab'.repeat(32);const auth=authorization();
  const result=await attestTask(deps,{...params(),creatorAuthorization:auth});expect(result.transaction).toBeTruthy();
  expect(await attestTask(deps,{...params(),creatorAuthorization:auth})).toEqual(result);
 });
 it('refuses stale creator signatures',async()=>{
  state.hash='ab'.repeat(32);const auth=authorization();auth.issuedAt=new Date(Date.now()-600000).toISOString();
  await expect(attestTask(deps,{...params(),creatorAuthorization:auth})).rejects.toMatchObject({httpStatus:403});expect(state.events).not.toContain('send');expect(state.events).not.toContain('transaction-sign');
 });
 it('requires retrievable content and never mints tickets by default',async()=>{
  state.registry=false;await expect(attestTask(deps,params())).rejects.toMatchObject({code:'SPEC_NOT_RETRIEVABLE'});expect(state.events).not.toContain('send');expect(state.events).not.toContain('transaction-sign');
 });
 it('signs a domain separated verdict with V and includes R and record PDA',async()=>{
  const result=await attestTask(deps,params());expect(state.events).not.toContain('balance');expect(result.moderator).toBe(payer.address);expect(result.recordPda).toBeTruthy();
  expect(result.signedVerdict?.body).toMatchObject({kind:'task-intake',genesisHash:'genesis-test',creator:creator.address,record:{moderator:payer.address}});
  const doc=result.signedVerdict!;expect(verify(null,documentBytes(doc.body),fixture.verdict.publicKey,Buffer.from(doc.signature,'hex'))).toBe(true);
  expect(verify(null,documentBytes(doc.body),payer.publicKey,Buffer.from(doc.signature,'hex'))).toBe(false);
 });
 it('reuses an unexpired result only after checking its chain PDA',async()=>{
  const first=await attestTask(deps,params());state.record=record();state.events=[];
  const second=await attestTask(deps,params());expect(second.transaction).toBeUndefined();expect(second.signedVerdict!.body.payment).toEqual(first.signedVerdict!.body.payment);expect(second.attestation?.signature).toBeTruthy();expect(state.events).toContain('record-read');expect(state.events).not.toContain('send');expect(state.events).not.toContain('transaction-sign');
 });
 it('fails closed when a cached chain record disappears',async()=>{
  state.record=record();await attestTask(deps,params());state.record=null;state.events=[];
  await expect(attestTask(deps,params())).rejects.toMatchObject({httpStatus:409});expect(state.events).not.toContain('send');expect(state.events).not.toContain('transaction-sign');
 });
 it('refuses a second live hash for a task',async()=>{
  await attestTask(deps,params());const spec={title:'Another paper'};const next=(await values.canonicalJobSpecHash(spec)).hex;state.hash=next;
  await expect(attestTask(deps,{task:TASK,jobSpecHash:next,spec})).rejects.toMatchObject({httpStatus:409});
 });
 it('does not depend on R balance, spend caps or network fee estimation',async()=>{
  deps.spendLimits={...DEFAULT_SPEND_LIMITS,hourlyLamports:0,dailyLamports:0};state.balance=0n;state.fee=100001n;
  expect((await attestTask(deps,params())).transaction).toBeTruthy();expect(state.events).not.toContain('balance');expect(state.events).not.toContain('send');
  expect(store.db.prepare('SELECT COUNT(*) AS n FROM spend').get()).toEqual({n:0});
 });
 it('compat preflight never signs, pays, persists a verdict, or pins',async()=>{
  state.registry=false;
  const handler=createModerationApi();const response=await handler(new Request('http://svc.test/api/task-moderation/attest',{method:'POST',body:JSON.stringify({taskPda:TASK,jobSpecHash:hash,jobSpec:PAYLOAD,preflightOnly:true})}));
  expect(response.status).toBe(200);expect(await response.json()).toMatchObject({preflightOnly:true,wouldAttest:true,attested:false,moderator:payer.address,moderation:{status:'clean'},txSignature:null});
  expect(state.events).not.toContain('send');expect(state.events).not.toContain('transaction-sign');expect(state.events).not.toContain('transaction-sign');expect(fetch).not.toHaveBeenCalled();expect(response.headers.has('access-control-allow-origin')).toBe(false);
 });
 it('reissues only after expiry with identical signed verdict, price and one admission',async()=>{
  deps.attestationServiceFeeLamports=1234;
  const first=await attestTask(deps,params());state.events=[];
  expect(await attestTask(deps,params())).toEqual(first);expect(state.events).not.toContain('transaction-sign');
  state.height=101n;state.blockhashByte=8;state.lastValid=200n;deps.attestationServiceFeeLamports=9999;
  const reissued=await attestTask(deps,params());expect(reissued.transaction).not.toBe(first.transaction);expect(reissued.lastValidBlockHeight).toBe(200);
  expect(reissued.signedVerdict).toEqual(first.signedVerdict);expect(reissued.priceLamports).toBe(2520754);
  expect(await attestTask(deps,params())).toEqual(reissued);expect(store.db.prepare('SELECT COUNT(*) AS n FROM admissions').get()).toEqual({n:1});expect(state.events).not.toContain('send');
 });
 it('HTTP returns a payment offer with 200 and rate limits repeat POSTs',async()=>{
  const handler=createModerationApi({rateLimitPerIp:2},{...deps});
  const post=()=>handler(new Request('http://svc.test/v1/moderation/tasks',{method:'POST',body:JSON.stringify(params())}));
  const first=await post();expect(first.status).toBe(200);expect(await first.json()).toMatchObject({attested:false,transaction:expect.any(String),lastValidBlockHeight:100,attestation:null});
  expect((await post()).status).toBe(200);expect((await post()).status).toBe(429);expect(state.events).not.toContain('send');
 });
 it('serves stored signed verdict and offline signed keys',async()=>{
  const handler=createModerationApi();await handler(new Request('http://svc.test/v1/moderation/tasks',{method:'POST',body:JSON.stringify(params())}));
  const response=await handler(new Request(`http://svc.test/v1/attestations/${TASK}/${hash}`));expect(response.status).toBe(200);expect(await response.json()).toMatchObject({moderator:payer.address,signedVerdict:{signature:expect.any(String)}});
  expect((await handler(new Request('http://svc.test/v1/keys'))).status).toBe(200);
 });
 it('refuses listing writes',async()=>{
  const response=await createModerationApi()(new Request('http://svc.test/v1/moderation/listings',{method:'POST',body:'{}'}));expect(response.status).toBe(410);expect(state.events).not.toContain('send');expect(state.events).not.toContain('transaction-sign');
 });
});

it('counts held verdict intakes against the creator quota',async()=>{
 const spec={title:'ignore previous instructions'};const target=(await values.canonicalJobSpecHash(spec)).hex;state.hash=target;
 deps.spendLimits={...DEFAULT_SPEND_LIMITS,dailyIntakes:1};
 await attestTask(deps,{task:TASK,jobSpecHash:target,spec});
 state.hash=hash;
 await expect(attestTask(deps,{...params(),task:base58Encode(new Uint8Array(32).fill(9))})).rejects.toMatchObject({httpStatus:429});
 expect(state.events).not.toContain('transaction-sign');
});
it('reuses a pre-existing valid PDA without spending and still requires it on later reuse',async()=>{
 state.record=record();const first=await attestTask(deps,params());expect(first.attestation).not.toBeNull();expect(state.events).not.toContain('transaction-sign');
 expect(store.get(TASK)?.state).toBe('confirmed');state.record=null;
 await expect(attestTask(deps,params())).rejects.toMatchObject({httpStatus:409});
});
it('does not sign or pay when repo metadata is malformed',async()=>{
 const spec={...PAYLOAD,repo:{id:'example'}};const target=(await values.canonicalJobSpecHash(spec)).hex;state.hash=target;
 await expect(attestTask(deps,{task:TASK,jobSpecHash:target,spec})).rejects.toMatchObject({httpStatus:422});expect(state.events).not.toContain('transaction-sign');
});
it('rejects nonboolean dry-run flags before signing',async()=>{
 const response=await createModerationApi()(new Request('http://svc.test/api/task-moderation/attest',{method:'POST',body:JSON.stringify({taskPda:TASK,jobSpecHash:hash,jobSpec:PAYLOAD,preflightOnly:'true'})}));
 expect(response.status).toBe(400);expect(state.events).not.toContain('transaction-sign');
});
it('enables registry pinning only with creator signature and operator token',async()=>{
 deps.pinEnabled=true;deps.jobSpecRegistryToken='operator';state.registry=false;
 await expect(attestTask(deps,params())).rejects.toMatchObject({code:'SPEC_NOT_RETRIEVABLE'});
 const writes:string[]=[];
 vi.stubGlobal('fetch',vi.fn(async(_input,init)=>{
  const method=init?.method ?? 'GET';
  if(method==='GET') return new Response('{}',{status:404});
  expect(method).toBe('PUT');expect((init?.headers as Record<string,string>).authorization).toBe('Bearer operator');writes.push(method);
  return new Response(JSON.stringify({jobSpecHash:hash}),{status:201});
 }));
 const result=await attestTask(deps,{...params(),creatorAuthorization:authorization()});expect(result.pinned).toBe(true);expect(writes).toEqual(['PUT']);
});

function decodeWire(wire:string) {
 const tx=getTransactionDecoder().decode(Buffer.from(wire,'base64'));
 const compiled=getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
 return {tx,compiled,message:decompileTransactionMessage(compiled)};
}
async function creatorSigns(wire:string) {
 const {tx}=decodeWire(wire);
 const seed=creator.privateKey.export({format:'der',type:'pkcs8'}).subarray(-32);
 const pub=creator.publicKey.export({format:'der',type:'spki'}).subarray(-32);
 const signer=await createKeyPairSignerFromBytes(Buffer.concat([seed,pub]));
 return partiallySignTransaction([signer.keyPair],tx);
}
/** Precise revision 5 money model: fee is charged to payer; instruction writes
 * roll back atomically on failure. init_if_needed charges moderator exact rent.
 * This is deliberately a mock, not an execution of the compiled Solana program. */
function executeRecordMock(tx:Transaction, failRecord=false) {
 const compiled=getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
 const message=decompileTransactionMessage(compiled);
 for(const [signer,sig] of Object.entries(tx.signatures)) {
  if(!sig || !verify(null,Buffer.from(tx.messageBytes),publicKeyFromAddress(signer),sig)) throw Error('Missing or invalid signature');
 }
 const fee=10_000n;
 const before=new Map([[state.creator,1_000_000_000n],[state.moderator,state.balance]]);
 before.set(message.feePayer.address,before.get(message.feePayer.address)!-fee);
 const working=new Map(before);
 try {
  const transfer=message.instructions[0];const bytes=Buffer.from(transfer.data!);
  if(transfer.programAddress!=='11111111111111111111111111111111' || bytes.readUInt32LE(0)!==2) throw Error('Invalid transfer');
  const from=transfer.accounts![0].address,to=transfer.accounts![1].address,amount=bytes.readBigUInt64LE(4);
  if(working.get(from)!<amount) throw Error('Insufficient funds');
  working.set(from,working.get(from)!-amount);working.set(to,(working.get(to) ?? 0n)+amount);
  const parsed=parseRecordTaskModerationInstruction(message.instructions[1] as Parameters<typeof parseRecordTaskModerationInstruction>[0]);
  if(failRecord || parsed.data.status!==0 || parsed.accounts.task.address!==TASK || parsed.accounts.moderator.address!==state.moderator) throw Error('Record failed');
  // Exact init_if_needed payer behavior: rent is debited only on creation.
  if(!state.record) {
   const rent=state.rent,payerAddress=parsed.accounts.moderator.address;
   if(working.get(payerAddress)!<rent) throw Error('Rent unavailable');
   working.set(payerAddress,working.get(payerAddress)!-rent);
   working.set(parsed.accounts.taskModeration.address,rent);
  }
  // Runtime rent transition: a newly nonzero system wallet must be rent exempt.
  const finalModerator=working.get(state.moderator)!;
  if(before.get(state.moderator)===0n && finalModerator>0n && finalModerator<890880n) throw Error('System wallet rent exemption');
  state.record={...parsed.data,task:TASK,creator:state.creator,moderator:state.moderator,recordedAt:BigInt(Math.floor(Date.now()/1000))};
  return {success:true,balances:working,fee};
 } catch { return {success:false,balances:before,fee}; }
}
it.each([0,12345])('returns exactly transfer + record with creator fee payer and valid R-only signature (fee %i)',async serviceFee=>{
 deps.attestationServiceFeeLamports=serviceFee;
 const offer=await attestTask(deps,params());const {tx,compiled,message}=decodeWire(offer.transaction!);
 expect(message.feePayer.address).toBe(creator.address);expect(compiled.header.numSignerAccounts).toBe(2);
 expect(message.instructions).toHaveLength(2);
 const [transfer,instruction]=message.instructions;
 expect(transfer.programAddress).toBe('11111111111111111111111111111111');
 expect(transfer.accounts!.map(a=>a.address)).toEqual([creator.address,payer.address]);
 const data=Buffer.from(transfer.data!);expect(data.length).toBe(12);expect(data.readUInt32LE(0)).toBe(2);expect(data.readBigUInt64LE(4)).toBe(2519520n+BigInt(serviceFee));
 expect(instruction.programAddress).toBe(AGENC_COORDINATION_PROGRAM_ADDRESS);
 const parsed=parseRecordTaskModerationInstruction(instruction as Parameters<typeof parseRecordTaskModerationInstruction>[0]);
 expect(parsed.accounts.moderator.address).toBe(payer.address);expect(parsed.accounts.task.address).toBe(TASK);expect(parsed.accounts.taskModeration.address).toBe(offer.recordPda);
 expect(parsed.data.status).toBe(0);expect(Buffer.from(parsed.data.jobSpecHash).toString('hex')).toBe(hash);
 expect(parsed.data.expiresAt).toBe(BigInt(Date.parse(String(offer.signedVerdict!.body.expiresAt))/1000));
 expect(Object.keys(tx.signatures)).toEqual([creator.address,payer.address]);
 expect(!tx.signatures[address(creator.address)] || Array.from(tx.signatures[address(creator.address)]!).every(n=>n===0)).toBe(true);
 expect(verify(null,Buffer.from(tx.messageBytes),payer.publicKey,tx.signatures[address(payer.address)]!)).toBe(true);
 expect(offer).toMatchObject({rentLamports:2519520,priceLamports:2519520+serviceFee,serviceFeeLamports:serviceFee,moderator:payer.address});
 const verdict=offer.signedVerdict!;expect(verdict.body.payment).toEqual({recordPda:offer.recordPda,priceLamports:2519520+serviceFee,payer:creator.address});
 expect(verify(null,documentBytes(verdict.body),fixture.verdict.publicKey,Buffer.from(verdict.signature,'hex'))).toBe(true);
 const tampered={...verdict.body,payment:{...(verdict.body.payment as object),priceLamports:1}};
 expect(verify(null,documentBytes(tampered),fixture.verdict.publicKey,Buffer.from(verdict.signature,'hex'))).toBe(false);
});
it.each([0,10000])('creator co-signs and pays atomically; R gains only service fee %i',async fee=>{
 state.balance=fee===0 ? 0n : 890880n;deps.attestationServiceFeeLamports=fee;
 const moderatorBefore=state.balance;const offer=await attestTask(deps,params());const signed=await creatorSigns(offer.transaction!);
 const execution=executeRecordMock(signed);expect(execution.success).toBe(true);
 expect(execution.balances.get(payer.address)).toBe(moderatorBefore+BigInt(fee));
 expect(execution.balances.get(creator.address)).toBe(1_000_000_000n-BigInt(offer.priceLamports!)-execution.fee);
 expect(execution.balances.get(offer.recordPda!)).toBe(state.rent);
 const paid=await attestTask(deps,params());expect(paid.transaction).toBeUndefined();expect(paid.signedVerdict!.body.record).toMatchObject({txSignature:expect.any(String)});
 // close_task returns TaskModeration rent to R under the unchanged program.
 execution.balances.set(payer.address,execution.balances.get(payer.address)!+execution.balances.get(offer.recordPda!)!);
 expect(execution.balances.get(payer.address)).toBe(moderatorBefore+BigInt(fee)+state.rent);expect(state.events).not.toContain('send');
});
it('failed record rolls back creator transfer and leaves R unchanged',async()=>{
 state.balance=17n;const offer=await attestTask(deps,params());const tx=await creatorSigns(offer.transaction!);
 const failure=executeRecordMock(tx,true);expect(failure.success).toBe(false);
 expect(failure.balances.get(payer.address)).toBe(17n);expect(failure.balances.get(creator.address)).toBe(1_000_000_000n-failure.fee);expect(state.record).toBeNull();
});
it('refuses R as creator/fee payer before partially signing',async()=>{
 state.creator=payer.address;
 await expect(attestTask(deps,params())).rejects.toMatchObject({httpStatus:409});expect(state.events).not.toContain('transaction-sign');
});
it.each([-1,0.5,Number.MAX_SAFE_INTEGER])('rejects invalid/overflowing service fee %s',async fee=>{
 deps.attestationServiceFeeLamports=fee;
 await expect(attestTask(deps,params())).rejects.toMatchObject({httpStatus:503});expect(state.events).not.toContain('transaction-sign');
});
it('does not reissue at a price that would expose R to an increased rent charge',async()=>{
 const first=await attestTask(deps,params());state.height=101n;state.rent++;
 await expect(attestTask(deps,params())).rejects.toMatchObject({httpStatus:409});expect(store.get(TASK)!.result).toBe(JSON.stringify(first));
});
it.each(['daily','hourly','outstanding'])('enforces creator %s cap for payment offers',async mode=>{
 deps.spendLimits={...DEFAULT_SPEND_LIMITS,...(mode==='daily'?{dailyIntakes:1}:mode==='hourly'?{hourlyTasks:1}:{outstandingTransactions:1})};
 const first=await attestTask(deps,params());
 await expect(attestTask(deps,{...params(),task:base58Encode(new Uint8Array(32).fill(8))})).rejects.toMatchObject({httpStatus:429});
 expect(await attestTask(deps,params())).toEqual(first);
 // A confirmed record releases the outstanding slot, without resetting quotas.
 if(mode==='outstanding') {state.record=record();await attestTask(deps,params());state.record=null;expect((await attestTask(deps,{...params(),task:base58Encode(new Uint8Array(32).fill(8))})).transaction).toBeTruthy();}
});
it('publishes one live offer across concurrent POSTs',async()=>{
 const [a,b]=await Promise.all([attestTask(deps,params()),attestTask(deps,params())]);expect(a).toEqual(b);
 expect(store.db.prepare('SELECT COUNT(*) AS n FROM admissions').get()).toEqual({n:1});expect(store.db.prepare('SELECT COUNT(*) AS n FROM intakes').get()).toEqual({n:1});
});
it('rejects an existing record with the wrong creator',async()=>{
 const offer=await attestTask(deps,params());state.record=record();
 // Altering the record changes the expected receipt payload and must fail binding.
 state.record.creator=base58Encode(new Uint8Array(32).fill(11));
 await expect(attestTask(deps,params())).rejects.toMatchObject({httpStatus:409});expect(store.get(TASK)!.result).toBe(JSON.stringify(offer));
});

it('does not treat unrelated PDA mentions as a record receipt',async()=>{
 await attestTask(deps,params());state.record=record();state.receiptUnrelated=true;
 await expect(attestTask(deps,params())).rejects.toMatchObject({httpStatus:502});
 expect(store.get(TASK)?.state).toBe('awaiting-payment');
});
it('HTTP GET reconciles payment after the task has moved beyond intake state',async()=>{
 const handler=createModerationApi({},deps);
 const offer=await attestTask(deps,params());state.record=record();state.status=2;state.workers=1;
 const response=await handler(new Request(`http://svc.test/v1/attestations/${TASK}/${hash}`));expect(response.status).toBe(200);
 const paid=await response.json();expect(paid.transaction).toBeUndefined();expect(paid.signedVerdict.body.payment).toEqual(offer.signedVerdict!.body.payment);
 expect(verify(null,documentBytes(paid.signedVerdict.body),fixture.verdict.publicKey,Buffer.from(paid.signedVerdict.signature,'hex'))).toBe(true);
});

it('preserves the payment offer, creator authorization and quote through restart and expiry',async()=>{
 store.close();const path=join(fixture.directory,'payments.sqlite');store=new AttestationStore(path);deps.store=store;
 state.hash='a'.repeat(64);const auth=authorization();const first=await attestTask(deps,{...params(),creatorAuthorization:auth});
 store.close();store=new AttestationStore(path);deps.store=store;
 expect(await attestTask(deps,{...params(),creatorAuthorization:auth})).toEqual(first);
 const time=Date.now();const now=vi.spyOn(Date,'now').mockReturnValue(time+6*60000);
 state.height=101n;state.blockhashByte=8;state.lastValid=200n;
 try {
  const reissued=await attestTask(deps,{...params(),creatorAuthorization:auth});expect(reissued.signedVerdict).toEqual(first.signedVerdict);expect(reissued.transaction).not.toBe(first.transaction);
  expect(store.db.prepare('SELECT COUNT(*) AS n FROM nonces').get()).toEqual({n:1});expect(store.db.prepare('SELECT COUNT(*) AS n FROM admissions').get()).toEqual({n:1});
 } finally {now.mockRestore();}
});
it('atomically caps concurrent offers for distinct tasks while allowing a different creator',async()=>{
 deps.spendLimits={...DEFAULT_SPEND_LIMITS,outstandingTransactions:1};
 const other=base58Encode(new Uint8Array(32).fill(8));
 const attempts=await Promise.allSettled([attestTask(deps,params()),attestTask(deps,{...params(),task:other})]);
 expect(attempts.filter(r=>r.status==='fulfilled')).toHaveLength(1);expect(attempts.filter(r=>r.status==='rejected')).toHaveLength(1);
 const rejected=attempts.find(r=>r.status==='rejected') as PromiseRejectedResult;expect(rejected.reason).toMatchObject({httpStatus:429});
 expect(store.db.prepare("SELECT COUNT(*) AS n FROM intakes WHERE state='awaiting-payment'").get()).toEqual({n:1});
 state.creator=creatorFixture().address;
 expect((await attestTask(deps,{...params(),task:base58Encode(new Uint8Array(32).fill(10))})).transaction).toBeTruthy();
});
it('compat endpoint carries all payment offer fields with no paid signature',async()=>{
 deps.attestationServiceFeeLamports=42;
 const handler=createModerationApi({},deps);
 const response=await handler(new Request('http://svc.test/api/task-moderation/attest',{method:'POST',body:JSON.stringify({taskPda:TASK,jobSpecHash:hash,jobSpec:PAYLOAD})}));
 expect(response.status).toBe(200);expect(await response.json()).toMatchObject({attested:false,txSignature:null,transaction:expect.any(String),lastValidBlockHeight:100,priceLamports:2519562,rentLamports:2519520,serviceFeeLamports:42,recordPda:expect.any(String),signedVerdict:{body:{payment:{payer:creator.address,priceLamports:2519562}}}});
});
