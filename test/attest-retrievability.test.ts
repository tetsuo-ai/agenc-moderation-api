/** Real signing core, with every RPC and registry boundary mocked. No live transactions. */
import { createHash, sign, verify } from 'node:crypto';
import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest';
import { values } from '@tetsuo-ai/marketplace-sdk';
import { base58Encode } from '../src/base58.js';
import { installVerdictFixture, installPayerFixture } from './fixtures.js';
import { AttestationStore, DEFAULT_SPEND_LIMITS } from '../src/store.js';
import { creatorRequestBytes } from '../src/binding.js';
import { documentBytes } from '../src/verdict.js';
import { moderationPolicyHashBytes } from '../src/policy.js';
import { scannerHashBytes } from '../src/scan.js';
const state = vi.hoisted(()=>({creator:'',hash:'',moderator:'',status:0,workers:0,completions:0,exists:true,pinned:'',record:null as any,balance:1_000_000_000n,fee:5200n,events:[] as string[],registry:true,timeout:false,height:1n,sendError:false}));
vi.mock('@solana/kit',async original=>{const actual=await original<typeof import('@solana/kit')>();return {...actual,signTransactionMessageWithSigners:async(...args:Parameters<typeof actual.signTransactionMessageWithSigners>)=>{state.events.push('transaction-sign');return actual.signTransactionMessageWithSigners(...args);},createSolanaRpc:()=>({
 getGenesisHash:()=>({send:async()=> 'genesis-test'}),
 getLatestBlockhash:()=>({send:async()=>({value:{blockhash:base58Encode(new Uint8Array(32).fill(7)),lastValidBlockHeight:100n}})}),
 getFeeForMessage:()=>({send:async()=>({value:state.fee})}),
 getMinimumBalanceForRentExemption:()=>({send:async()=>2519520n}),
 getBalance:()=>({send:async()=>{state.events.push('balance');return {value:state.balance};}}),
 sendTransaction:()=>({send:async()=>{state.events.push('send');if(state.sendError) throw new Error('ambiguous');return 'sig';}}),
 getSignatureStatuses:()=>({send:async()=>({value:state.timeout ? [null] : [{err:null,confirmationStatus:'confirmed'}]})}),
 getBlockHeight:()=>({send:async()=>state.height})
})};});
vi.mock('@tetsuo-ai/marketplace-sdk',async original=>({...await original<typeof import('@tetsuo-ai/marketplace-sdk')>(),
 fetchMaybeTask:async()=>({exists:state.exists,data:{creator:state.creator,status:state.status,currentWorkers:state.workers,completions:state.completions,description:Buffer.from(state.hash,'hex')}}),
 fetchMaybeTaskJobSpec:async()=>state.pinned ? {exists:true,data:{jobSpecHash:Buffer.from(state.pinned,'hex'),jobSpecUri:'https://spec.test'}} : {exists:false},
 fetchMaybeTaskModeration:async()=>{state.events.push('record-read');return state.record ? {exists:true,data:state.record} : {exists:false};},
 fetchMaybeModerationConfig:async()=>({exists:true,data:{moderationAuthority:state.moderator}})
}));
vi.mock('../src/ssrf-fetch.js',async original=>({...await original<typeof import('../src/ssrf-fetch.js')>(),fetchJobSpecBody:async()=>{const text=JSON.stringify(PAYLOAD);return {text,sha256:createHash('sha256').update(text).digest('hex')};}}));
import { attestTask, type AttestDeps } from '../src/signer.js';
import { createModerationApi } from '../src/router.js';
import { __resetRateLimiterForTests } from '../src/rate-limit.js';
const TASK='9UEu2Gv9Q7DwBtumR2rUSq5g8v7b6mxn26ZNQCky82RJ';
const PAYLOAD={title:'Summarize three research papers'};
let fixture: ReturnType<typeof installVerdictFixture>; let payer: ReturnType<typeof installPayerFixture>; let store: AttestationStore; let deps: AttestDeps; let hash: string;
beforeEach(async()=>{
 fixture=installVerdictFixture();payer=installPayerFixture();store=new AttestationStore(':memory:');
 hash=(await values.canonicalJobSpecHash(PAYLOAD)).hex;
 Object.assign(state,{creator:payer.address,moderator:payer.address,hash,status:0,workers:0,completions:0,exists:true,pinned:'',record:null,balance:1_000_000_000n,fee:5200n,events:[],registry:true,timeout:false,height:1n,sendError:false});
 deps={rpcUrl:'https://rpc.test',attestationTtlSeconds:72*3600,jobSpecRegistryUrl:'https://registry.test',store};
 vi.stubGlobal('fetch',vi.fn(async(_input,init)=>{expect(init?.method ?? 'GET').toBe('GET');return new Response(JSON.stringify(PAYLOAD),{status:state.registry?200:404});}));
 __resetRateLimiterForTests();
});
afterEach(()=>{store.close();fixture.cleanup();delete process.env.MODERATION_SIGNER_SECRET;delete process.env.CONFIRMATION_TIMEOUT_MS;vi.unstubAllGlobals();});
function params(){return {task:TASK,jobSpecHash:hash,spec:PAYLOAD};}
function record(){return {task:TASK,creator:state.creator,moderator:state.moderator,jobSpecHash:Buffer.from(hash,'hex'),status:0,policyHash:moderationPolicyHashBytes(),scannerHash:scannerHashBytes(),recordedAt:BigInt(Math.floor(Date.now()/1000)),expiresAt:BigInt(Math.floor(Date.now()/1000)+72*3600)};}
function authorization(){const auth={issuedAt:new Date().toISOString(),nonce:'ab'.repeat(16)};return {...auth,signature:sign(null,creatorRequestBytes(state.creator,TASK,hash,auth),payer.privateKey).toString('hex')};}
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
  const result=await attestTask(deps,{...params(),creatorAuthorization:auth});expect(result.attestation).not.toBeNull();
  await expect(attestTask(deps,{...params(),creatorAuthorization:auth})).rejects.toMatchObject({httpStatus:409});
 });
 it('refuses stale creator signatures',async()=>{
  state.hash='ab'.repeat(32);const auth=authorization();auth.issuedAt=new Date(Date.now()-600000).toISOString();
  await expect(attestTask(deps,{...params(),creatorAuthorization:auth})).rejects.toMatchObject({httpStatus:403});expect(state.events).not.toContain('send');expect(state.events).not.toContain('transaction-sign');
 });
 it('requires retrievable content and never mints tickets by default',async()=>{
  state.registry=false;await expect(attestTask(deps,params())).rejects.toMatchObject({code:'SPEC_NOT_RETRIEVABLE'});expect(state.events).not.toContain('send');expect(state.events).not.toContain('transaction-sign');
 });
 it('signs a domain separated verdict with V and includes R and record PDA',async()=>{
  const result=await attestTask(deps,params());expect(state.events).toContain('balance');expect(result.moderator).toBe(payer.address);expect(result.recordPda).toBeTruthy();
  expect(result.signedVerdict?.body).toMatchObject({kind:'task-intake',genesisHash:'genesis-test',creator:payer.address,record:{moderator:payer.address}});
  const doc=result.signedVerdict!;expect(verify(null,documentBytes(doc.body),fixture.verdict.publicKey,Buffer.from(doc.signature,'hex'))).toBe(true);
  expect(verify(null,documentBytes(doc.body),payer.publicKey,Buffer.from(doc.signature,'hex'))).toBe(false);
 });
 it('reuses an unexpired result only after checking its chain PDA',async()=>{
  const first=await attestTask(deps,params());state.record=record();state.events=[];
  const second=await attestTask(deps,params());expect(second).toEqual(first);expect(state.events).toContain('record-read');expect(state.events).not.toContain('send');expect(state.events).not.toContain('transaction-sign');
 });
 it('fails closed when a cached chain record disappears',async()=>{
  await attestTask(deps,params());state.events=[];
  await expect(attestTask(deps,params())).rejects.toMatchObject({httpStatus:409});expect(state.events).not.toContain('send');expect(state.events).not.toContain('transaction-sign');
 });
 it('refuses a second live hash for a task',async()=>{
  await attestTask(deps,params());const spec={title:'Another paper'};const next=(await values.canonicalJobSpecHash(spec)).hex;state.hash=next;
  await expect(attestTask(deps,{task:TASK,jobSpecHash:next,spec})).rejects.toMatchObject({httpStatus:409});
 });
 it.each(['hour','day','floor','fee'])('enforces %s spend guard before sending',async guard=>{
  deps.spendLimits={...DEFAULT_SPEND_LIMITS};
  if(guard==='hour') deps.spendLimits.hourlyLamports=1;if(guard==='day') deps.spendLimits.dailyLamports=1;if(guard==='floor') state.balance=100_000_000n;if(guard==='fee') state.fee=100001n;
  await expect(attestTask(deps,params())).rejects.toBeDefined();expect(state.events).not.toContain('send');expect(state.events).not.toContain('transaction-sign');
 });
 it('compat preflight never signs, pays, persists a verdict, or pins',async()=>{
  state.registry=false;
  const handler=createModerationApi();const response=await handler(new Request('http://svc.test/api/task-moderation/attest',{method:'POST',body:JSON.stringify({taskPda:TASK,jobSpecHash:hash,jobSpec:PAYLOAD,preflightOnly:true})}));
  expect(response.status).toBe(200);expect(await response.json()).toMatchObject({preflightOnly:true,wouldAttest:true,attested:false,moderator:payer.address,moderation:{status:'clean'},txSignature:null});
  expect(state.events).not.toContain('send');expect(state.events).not.toContain('transaction-sign');expect(state.events).not.toContain('transaction-sign');expect(fetch).not.toHaveBeenCalled();expect(response.headers.has('access-control-allow-origin')).toBe(false);
 });
 it.each(['timeout','expired','ambiguous'])('persists signature and never resends after %s',async kind=>{
  state.timeout=true;process.env.CONFIRMATION_TIMEOUT_MS='0';if(kind==='expired') state.height=101n;if(kind==='ambiguous') state.sendError=true;
  const first=await attestTask(deps,params());expect(first.pending).toBe(true);expect(store.get(TASK)?.signature).toBe(first.attestation?.signature);
  state.events=[];const second=await attestTask(deps,params());expect(second.pending).toBe(true);expect(second.attestation?.signature).toBe(first.attestation?.signature);expect(state.events).not.toContain('send');expect(state.events).not.toContain('transaction-sign');
 });
 it('HTTP confirmation timeout returns 202 with signature',async()=>{
  state.timeout=true;process.env.CONFIRMATION_TIMEOUT_MS='0';
  const handler=createModerationApi();const response=await handler(new Request('http://svc.test/v1/moderation/tasks',{method:'POST',body:JSON.stringify(params())}));
  expect(response.status).toBe(202);expect(await response.json()).toMatchObject({pending:true,attested:false,attestation:{signature:expect.any(String)}});
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
