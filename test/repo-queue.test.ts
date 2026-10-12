/** End-to-end HTTP + durable SQLite + real worker/signatures. Every RPC,
 * GitHub, registry and container boundary is mocked; no live transactions. */
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeEach, afterEach, expect, it, vi } from 'vitest';
import { getTransactionDecoder, getCompiledTransactionMessageDecoder, decompileTransactionMessage } from '@solana/kit';
import { AGENC_COORDINATION_PROGRAM_ADDRESS, values, parseRecordTaskModerationInstruction, findModerationAttestorPda } from '@tetsuo-ai/marketplace-sdk';
import { base58Encode } from '../src/base58.js';
import { installPayerFixture, installVerdictFixture, creatorFixture, recordReceipt } from './fixtures.js';
import { AttestationStore, DEFAULT_SPEND_LIMITS } from '../src/store.js';
import { documentBytes, keyAddress } from '../src/verdict.js';
import { creatorRequestBytes } from '../src/binding.js';
import { moderationPolicyHashBytes } from '../src/policy.js';
import { scannerHash } from '../worker/rules.js';
const state=vi.hoisted(()=>({creator:'',moderator:'',hash:'',status:0,workers:0,completions:0,pinned:false,
 record:null as any,height:1n,blockhashByte:7,lastValid:100n,balance:1_000_000_000n,events:[] as string[],timeout:false,subHash:'',subTask:'',subStatus:1,claimWorker:'agent',hosted:[] as string[]}));
vi.mock('@solana/kit',async original=>({...await original<typeof import('@solana/kit')>(),createSolanaRpc:()=>({
 getGenesisHash:()=>({send:async()=> 'genesis-test'}),
 getLatestBlockhash:()=>({send:async()=>({value:{blockhash:base58Encode(new Uint8Array(32).fill(state.blockhashByte)),lastValidBlockHeight:state.lastValid}})}),
 getFeeForMessage:()=>({send:async()=>({value:5200n})}),
 getMinimumBalanceForRentExemption:()=>({send:async()=>2519520n}),
 getTransaction:()=>({send:async()=>recordReceipt(record())}),
 getSignaturesForAddress:()=>({send:async()=>[{signature:base58Encode(new Uint8Array(64).fill(9)),err:null}]}),
 getBalance:()=>({send:async()=>({value:state.balance})}),
 sendTransaction:()=>({send:async()=>{state.events.push('send');if(!state.timeout)state.record=record();return 'mock-signature';}}),
 getSignatureStatuses:()=>({send:async()=>({value:state.timeout?[null]:[{err:null,confirmationStatus:'confirmed'}]})}),
 getBlockHeight:()=>({send:async()=>state.height})
})}));
vi.mock('@tetsuo-ai/marketplace-sdk',async original=>({...await original<typeof import('@tetsuo-ai/marketplace-sdk')>(),
 fetchMaybeTask:async()=>({exists:true,data:{creator:state.creator,status:state.status,currentWorkers:state.workers,completions:state.completions,description:Buffer.from(state.hash,'hex')}}),
 fetchMaybeTaskJobSpec:async()=>state.pinned?{exists:true,data:{jobSpecHash:Buffer.from(state.hash,'hex'),jobSpecUri:'https://spec.test'}}:{exists:false},
 fetchMaybeTaskModeration:async()=>state.record?{exists:true,data:state.record}:{exists:false},
 fetchMaybeModerationConfig:async()=>({exists:true,data:{moderationAuthority:base58Encode(new Uint8Array(32).fill(4))}}),
 fetchMaybeModerationAttestor:async()=>({exists:true,data:{attestor:state.moderator,exitAt:0n}}),
 fetchMaybeTaskSubmission:async()=>({exists:true,data:{task:state.subTask,claim:TASK,worker:'agent',status:state.subStatus,proofHash:Buffer.from(state.subHash,'hex')}}),
 fetchMaybeTaskClaim:async()=>({exists:true,data:{task:TASK,worker:state.claimWorker}}),
 findTaskSubmissionPda:async()=>[SUBMISSION]
}));
// URIs under https://mock.test/ serve PAYLOAD only while listed in state.hosted.
vi.mock('../src/ssrf-fetch.js',async original=>{const actual=await original<typeof import('../src/ssrf-fetch.js')>();return {...actual,fetchJobSpecBody:async(uri:string)=>{
 if(!uri.startsWith('https://mock.test/')) return actual.fetchJobSpecBody(uri);
 if(!state.hosted.includes(uri)) throw new actual.JobSpecCheckError('not hosted');
 const bytesBuffer=Buffer.from(JSON.stringify(PAYLOAD));
 return {text:bytesBuffer.toString('utf8'),bytesBuffer,bytes:bytesBuffer.length,contentType:'application/json',sha256:createHash('sha256').update(bytesBuffer).digest('hex')};
}};});
import { createModerationApi } from '../src/router.js';
import { ATTESTATION_READ_CACHE_MS, type AttestDeps } from '../src/signer.js';
import { RETRY_DELAYS_MS, runDevelopmentWorkerOnce } from '../src/repo-queue.js';
import { __resetRateLimiterForTests } from '../src/rate-limit.js';
import { processJob, type WorkerDeps } from '../worker/consumer.js';
import { signQueueRequest, runHttpWorkerOnce } from '../worker/queue-http.js';
import { signReport } from '../worker/protocol.js';
import { check, hash, type Report } from '../worker/types.js';
import type { Sandbox } from '../worker/container.js';
import { ARTIFACT_BYTES, DIGEST, RESULT_TREE, SPEC, TASK, TREE, cleanTree, entry, github } from './worker-fixtures.js';
const SUBMISSION=base58Encode(new Uint8Array(32).fill(2));
const W=generateKeyPairSync('ed25519');
const PAYLOAD={title:'Fix public repo',custom:{github:SPEC}};
let creator:ReturnType<typeof creatorFixture>;
let fixture:ReturnType<typeof installVerdictFixture>,payer:ReturnType<typeof installPayerFixture>,store:AttestationStore;
let deps:AttestDeps, handler:ReturnType<typeof createModerationApi>,worker:WorkerDeps,box:ReturnType<typeof sandbox>;
function sandbox() {
 return {clone:vi.fn(async()=>({treeSha:TREE,entries:cleanTree()})),
  apply:vi.fn(async()=>({checks:[check('patch-apply','pass')],snapshot:{treeSha:RESULT_TREE,entries:cleanTree()}})),
  test:vi.fn(async()=>({exitCode:0 as number|null,timedOut:false,outputSha256:hash('test output')})),close:vi.fn(async()=>{})} satisfies Sandbox;
}
function record() { const committedHash=store.get(TASK)?.hash ?? state.hash; return {task:TASK,creator:state.creator,moderator:state.moderator,jobSpecHash:Buffer.from(committedHash,'hex'),
 status:0,riskScore:0,categoryMask:0n,policyHash:moderationPolicyHashBytes(),scannerHash:Buffer.from(scannerHash(DIGEST),'hex'),recordedAt:BigInt(Math.floor(Date.now()/1000)),
 // A minute of margin: this record exists before the verdict, which must not outlive it across a second boundary.
 expiresAt:BigInt(Math.floor(Date.now()/1000)+72*3600+60)}; }
function api() { return createModerationApi({storePath:join(fixture.directory,'queue.sqlite'),rateLimitPerIp:1000,rateLimitGlobal:1000},deps); }
function post(path:string,body:unknown) { return handler(new Request('https://signer.test'+path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)})); }
function intake(task=TASK) { return post('/v1/moderation/tasks',{task,jobSpecHash:state.hash,spec:PAYLOAD,specUri:'https://spec.test'}); }
function transport(path:string,payload:Record<string,unknown>={},key=W.privateKey) { return post(path,signQueueRequest('worker-1',path,payload,key)); }
function get() { return handler(new Request(`https://signer.test/v1/attestations/${TASK}/${state.hash}`)); }
function spend() { return store.db.prepare('SELECT COUNT(*) AS n, COALESCE(SUM(lamports),0) AS total FROM spend').get() as {n:number;total:number}; }
async function lease() { return (await transport('/internal/worker/pull')).json() as Promise<{jobId:string;leaseToken:string;job:Report['job']}>; }
async function review(leaseData:Awaited<ReturnType<typeof lease>>,report?:Awaited<ReturnType<typeof processJob>>) {
 return transport('/internal/worker/reports',{...leaseData,report:report ?? await processJob(leaseData.job,worker)});
}
async function acceptedIntake() { expect((await intake()).status).toBe(202);expect(await runDevelopmentWorkerOnce(deps,worker)).toBe(true);expect((await get()).status).toBe(200); }
function deliverable() { return post('/v1/moderation/deliverables',{task:TASK,submissionPda:SUBMISSION,artifactSha256:hash(ARTIFACT_BYTES)}); }
function readySubmission() { state.pinned=true;state.status=2;state.workers=1; }
/** Run every retry of an infrastructure hold: the intake stays pending and no job runs before its time. */
async function exhaustRetries() {
 for(let i=0;i<RETRY_DELAYS_MS.length;i++) {
  const pending=await (await intake()).json();expect(pending).toMatchObject({pending:true});
  expect(pending.retryAfterSeconds).toBeGreaterThanOrEqual(RETRY_DELAYS_MS[i]!/1000-1);
  expect(await runDevelopmentWorkerOnce(deps,worker)).toBe(false);
  store.db.prepare("UPDATE jobs SET leaseUntil=0 WHERE state='retry'").run();
  expect(await runDevelopmentWorkerOnce(deps,worker)).toBe(true);
 }
}
beforeEach(async()=>{
 fixture=installVerdictFixture();payer=installPayerFixture();creator=creatorFixture();store=new AttestationStore(join(fixture.directory,'queue.sqlite'));
 Object.assign(state,{creator:creator.address,moderator:payer.address,hash:(await values.canonicalJobSpecHash(PAYLOAD)).hex,
  status:0,workers:0,completions:0,pinned:false,record:null,height:1n,blockhashByte:7,lastValid:100n,balance:1_000_000_000n,events:[],timeout:false,
  subHash:hash(ARTIFACT_BYTES),subTask:TASK,subStatus:1,claimWorker:'agent',hosted:[]});
 deps={rpcUrl:'https://rpc.test',attestationTtlSeconds:72*3600,store,repository:{imageDigest:DIGEST,workers:{'worker-1':keyAddress(W.privateKey)},github:github()}};
 box=sandbox();worker={workerId:'worker-1',reportKey:W.privateKey,imageDigest:DIGEST,github:github(),sandbox:()=>box,
  artifactBytes:async()=>ARTIFACT_BYTES,osv:async ds=>({results:ds.map(()=>({}))})};
 vi.stubGlobal('fetch',vi.fn(async(_url,init)=>{expect(init?.method ?? 'GET').toBe('GET');return new Response(JSON.stringify(PAYLOAD));}));
 __resetRateLimiterForTests();handler=api();
});
afterEach(()=>{store.close();fixture.cleanup();delete process.env.MODERATION_SIGNER_SECRET;delete process.env.CONFIRMATION_TIMEOUT_MS;vi.unstubAllGlobals();});
it('queues HTTP intake, worker pulls/posts, and returns a verifiable repo-bound V verdict',async()=>{
 const first=await intake();expect(first.status).toBe(202);expect(await first.json()).toMatchObject({pending:true,jobId:expect.any(String),retryAfterSeconds:5,attested:false});
 expect((await get()).status).toBe(404);expect(state.events).toEqual([]);
 const fetcher=(async(input:any,init:any)=>handler(new Request(input,init))) as typeof fetch;
 expect(await runHttpWorkerOnce('https://signer.test',worker,fetcher)).toBe(true);
 const done=await (await intake()).json();expect(done.attested).toBe(false);expect(done.transaction).toEqual(expect.any(String));expect(done.signedVerdict.body).toMatchObject({kind:'task-intake',scope:'repository',verdict:'clean',repo:{id:123,owner:SPEC.owner,name:SPEC.repo,licenseSpdx:'MIT',baseCommit:SPEC.baseCommit,treeSha:TREE,allowedPathsHash:expect.any(String),testCommandHash:expect.any(String),maxDiffBytes:SPEC.maxDiffBytes},record:{pda:expect.any(String),txSignature:null}});
 const tx=getTransactionDecoder().decode(Buffer.from(done.transaction,'base64'));
 const message=decompileTransactionMessage(getCompiledTransactionMessageDecoder().decode(tx.messageBytes));
 expect(message.feePayer.address).toBe(creator.address);expect(message.instructions).toHaveLength(2);
 expect(message.instructions[0].programAddress).toBe('11111111111111111111111111111111');
 expect(Buffer.from(message.instructions[0].data!).readBigUInt64LE(4)).toBe(BigInt(done.priceLamports));
 const parsed=parseRecordTaskModerationInstruction(message.instructions[1] as Parameters<typeof parseRecordTaskModerationInstruction>[0]);
 const [roster]=await findModerationAttestorPda({attestor:parsed.accounts.moderator.address});
 expect(parsed.accounts.moderationAttestor?.address).toBe(roster);expect(parsed.accounts.taskModeration.address).toBe(done.recordPda);
 expect(Buffer.from(parsed.data.scannerHash).toString('hex')).toBe(done.signedVerdict.body.scannerHash);
 expect(verify(null,Buffer.from(tx.messageBytes),payer.publicKey,tx.signatures[parsed.accounts.moderator.address]!)).toBe(true);
 expect(verify(null,documentBytes(done.signedVerdict.body),fixture.verdict.publicKey,Buffer.from(done.signedVerdict.signature,'hex'))).toBe(true);
 expect((await (await get()).json()).signedVerdict).toEqual(done.signedVerdict);expect(state.events).toEqual([]);expect(spend()).toEqual({n:0,total:0});
 expect(await runHttpWorkerOnce('https://signer.test',worker,fetcher)).toBe(false);
});
// The real answer for a GitHub-bound task, for the AgenC Desktop tests
// (tests/fixtures/marketplace/attestor/github-intake.json there). Runs only on demand:
//   EXPORT_DESKTOP_GITHUB_FIXTURE=/path/github-intake.json npx vitest run test/repo-queue.test.ts -t "Desktop fixture"
it.runIf(!!process.env.EXPORT_DESKTOP_GITHUB_FIXTURE)('exports the Desktop fixture for a GitHub-bound intake',async()=>{
 await intake();expect(await runDevelopmentWorkerOnce(deps,worker)).toBe(true);
 const response=await intake();const text=await response.text();const body=JSON.parse(text).signedVerdict.body;
 expect(body).toMatchObject({kind:'task-intake',scope:'repository',verdict:'clean',record:{pda:expect.any(String)}});
 writeFileSync(process.env.EXPORT_DESKTOP_GITHUB_FIXTURE!,JSON.stringify({
  note:'Real POST /v1/moderation/tasks answer for a job spec with custom.github: HTTP intake, worker report and attestTask from agenc-moderation-api test/repo-queue.test.ts. Throwaway keys; RPC, GitHub and the container are mocked.',
  now:Date.now(),rootPublicKey:keyAddress(fixture.root.privateKey),manifest:fixture.manifest,
  context:{task:TASK,creator:creator.address,jobSpecHash:state.hash,jobSpecUri:body.jobSpecUri ?? 'https://spec.test',rosterKey:payer.address,
   chain:{cluster:'mainnet',genesisHash:'genesis-test',programId:AGENC_COORDINATION_PROGRAM_ADDRESS}},
  status:response.status,text},null,2)+'\n');
});
it.each(['hold','reject'])('stores %s reasons without an on-chain record or spend',async outcome=>{
 if(outcome==='hold') box.clone.mockRejectedValue(Error('mock sandbox outage'));
 else box.clone.mockResolvedValue({treeSha:TREE,entries:[...cleanTree(),entry('src/secret','-----BEGIN PRIVATE KEY-----')]});
 await intake();expect(await runDevelopmentWorkerOnce(deps,worker)).toBe(true);
 if(outcome==='hold') await exhaustRetries();
 const res=await intake();expect(res.status).toBe(200);const result=await res.json();
 expect(result.verdict).toBe(outcome==='hold'?'suspicious':'blocked');expect(result.signedVerdict.body.reasons.length).toBeGreaterThan(0);
 expect(result.attestation).toBeNull();expect(result.signedVerdict.body.record.pda).toBeNull();expect((await get()).status).toBe(200);
 expect(state.events).toEqual([]);expect(spend()).toEqual({n:0,total:0});
});
it('rejects forged transport, domain substitution, replay and forged worker reports',async()=>{
 await intake();expect((await transport('/internal/worker/pull',{},payer.privateKey)).status).toBe(403);
 const auth=signQueueRequest('worker-1','/internal/worker/pull',{},W.privateKey);
 const pulled=await post('/internal/worker/pull',auth);expect(pulled.status).toBe(200);
 expect((await post('/internal/worker/pull',auth)).status).toBe(409);
 expect((await post('/internal/worker/reports',auth)).status).toBe(403);
 const l=await pulled.json();const r=await processJob(l.job,worker);r.signature='00'.repeat(64);
 expect((await review(l,r)).status).toBe(403);expect((await get()).status).toBe(404);expect(state.events).toEqual([]);
});
it('rejects a signed report whose job, image or required checks are forged',async()=>{
 await intake();const l=await lease();const original=await processJob(l.job,worker);
 for(const body of [{...original.body,imageDigest:'sha256:'+'f'.repeat(64)},
  {...original.body,job:{...original.body.job,taskPda:SUBMISSION}},
  {...original.body,checks:original.body.checks.filter(c=>c.id!=='secrets')}]) {
  expect((await review(l,signReport(body,W.privateKey))).status).toBeGreaterThanOrEqual(400);
 }
 expect(state.events).toEqual([]);expect(store.job(l.jobId)?.reviewed).toBeNull();
});
it('retries intake/report idempotently without extra quota or spend',async()=>{
 const first=await (await intake()).json();const retry=await (await intake()).json();expect(retry.jobId).toBe(first.jobId);expect(spend().n).toBe(0);
 const l=await lease(),r=await processJob(l.job,worker);expect((await review(l,r)).status).toBe(200);
 expect((await review(l,r)).status).toBe(200);expect((await intake()).status).toBe(200);expect(state.events).toEqual([]);expect(spend().n).toBe(0);
 expect(store.db.prepare('SELECT COUNT(*) AS n FROM admissions').get()).toEqual({n:1});
});
it('persists queue and leases across restart and refuses an obsolete lease',async()=>{
 await intake();const old=await lease();const path=join(fixture.directory,'queue.sqlite');store.close();store=new AttestationStore(path);deps.store=store;handler=api();
 expect((await intake()).status).toBe(202);expect((await transport('/internal/worker/pull')).status).toBe(204);
 store.db.prepare('UPDATE jobs SET leaseUntil=0').run();const fresh=await lease();expect(fresh.jobId).toBe(old.jobId);expect(fresh.leaseToken).not.toBe(old.leaseToken);
 expect((await review(old)).status).toBe(409);expect((await review(fresh)).status).toBe(200);expect((await get()).status).toBe(200);expect(spend().n).toBe(0);
});
it('reconciles a creator-submitted transaction on GET without sending',async()=>{
 await intake();await runDevelopmentWorkerOnce(deps,worker);
 const offered=await (await intake()).json();expect(offered.transaction).toBeTruthy();expect((await get()).status).toBe(200);
 // GET reuses its chain read for a few seconds, so look again after that window.
 const now=vi.spyOn(Date,'now').mockReturnValue(Date.now()+ATTESTATION_READ_CACHE_MS+1);
 try {
  state.record=record();const paid=await (await get()).json();expect(paid.attested).toBe(true);expect(paid.transaction).toBeUndefined();expect(paid.signedVerdict.body.record.txSignature).toBeTruthy();expect(state.events).toEqual([]);expect(spend().n).toBe(0);
 } finally { now.mockRestore(); }
});
it.each(['quota','outstanding'])('enforces %s guard before admitting worker jobs',async guard=>{
 deps.spendLimits={...DEFAULT_SPEND_LIMITS,...(guard==='quota'?{dailyIntakes:0}:{outstandingTransactions:0})};
 handler=api();expect((await intake()).status).toBe(429);
 expect(store.intakeJob(TASK,state.hash)).toBeUndefined();expect(spend().n).toBe(0);expect(state.events).toEqual([]);
});
it('admits jobs even with zero R balance and zero spend budgets',async()=>{
 deps.spendLimits={...DEFAULT_SPEND_LIMITS,hourlyLamports:0,dailyLamports:0};state.balance=0n;handler=api();
 expect((await intake()).status).toBe(202);expect(spend().n).toBe(0);
});
it('bounds concurrent queued reservations and counts held jobs against quota',async()=>{
 deps.spendLimits={...DEFAULT_SPEND_LIMITS,dailyIntakes:1};handler=api();await intake();
 expect((await intake(SUBMISSION)).status).toBe(429);
 box.clone.mockRejectedValue(Error('outage'));await runDevelopmentWorkerOnce(deps,worker);
 expect((await intake(SUBMISSION)).status).toBe(429);expect(spend().n).toBe(0);
});
it('refuses task/spec/creator changes during signer rechecks',async()=>{
 await intake();const l=await lease(),report=await processJob(l.job,worker);state.workers=1;
 expect((await review(l,report)).status).toBe(409);expect(state.events).toEqual([]);expect((await get()).status).toBe(404);
});
it('runs deliverable review through the queue and binds submission/artifact/intake',async()=>{
 await acceptedIntake();readySubmission();const first=await deliverable();expect(first.status).toBe(202);
 const body=await first.json();expect((await (await deliverable()).json()).jobId).toBe(body.jobId);
 expect(await runDevelopmentWorkerOnce(deps,worker)).toBe(true);const done=await deliverable();expect(done.status).toBe(200);
 const result=await done.json();expect(result.signedVerdict.body).toMatchObject({kind:'deliverable-review',scope:'repository',verdict:'clean',submissionPda:SUBMISSION,artifactSha256:hash(ARTIFACT_BYTES),resultTreeSha:RESULT_TREE,intakeHash:expect.any(String),tests:{exitCode:0}});
 expect(verify(null,documentBytes(result.signedVerdict.body),fixture.verdict.publicKey,Buffer.from(result.signedVerdict.signature,'hex'))).toBe(true);
 expect((await handler(new Request(`https://signer.test/v1/deliverable-reviews/${TASK}/${SUBMISSION}/${hash(ARTIFACT_BYTES)}`))).status).toBe(200);
 expect(state.events).toEqual([]);expect(spend().n).toBe(0);
});
it('stores a failed deliverable and never sends another chain transaction',async()=>{
 await acceptedIntake();readySubmission();box.test.mockResolvedValue({exitCode:1,timedOut:false,outputSha256:hash('failed')});
 await deliverable();await runDevelopmentWorkerOnce(deps,worker);const result=await (await deliverable()).json();
 expect(result.signedVerdict.body.verdict).toBe('blocked');expect(result.signedVerdict.body.reasons.length).toBeGreaterThan(0);expect(state.events).toEqual([]);expect(spend().n).toBe(0);
});
it.each(['hash','task','status','claim'])('rejects deliverable submission %s mismatch before enqueue',async mode=>{
 await acceptedIntake();readySubmission();if(mode==='hash')state.subHash='0'.repeat(64);if(mode==='task')state.subTask=SUBMISSION;if(mode==='status')state.subStatus=2;if(mode==='claim')state.claimWorker='other';
 expect((await deliverable()).status).toBe(409);expect(store.db.prepare("SELECT COUNT(*) AS n FROM jobs WHERE kind='deliverable'").get()).toEqual({n:0});
});
it('requires accepted intake and caps deliverable scanner admissions',async()=>{
 await acceptedIntake();readySubmission();deps.spendLimits={...DEFAULT_SPEND_LIMITS,dailyIntakes:1};handler=api();
 expect((await deliverable()).status).toBe(429);expect(state.events).toEqual([]);
});

it.each(['hold','reject'])('stores negative GitHub %s reports even without immutable repo facts',async outcome=>{
 const negative=outcome==='hold' ? github(()=>{throw Error('GitHub offline');}) : github(url=>url.includes('/license?')?{license:{spdx_id:'GPL-3.0'}}:undefined);
 deps.repository!.github=negative;worker.github=negative;handler=api();await intake();await runDevelopmentWorkerOnce(deps,worker);
 if(outcome==='hold') await exhaustRetries();
 const done=await (await get()).json();expect(done.verdict).toBe(outcome==='hold'?'suspicious':'blocked');expect(done.signedVerdict.body.repo).toBeNull();
 expect(done.signedVerdict.body.reasons.length).toBeGreaterThan(0);expect(spend().n).toBe(0);expect(state.events).toEqual([]);
});
it('scans again after a transient outage and attests the repo once it recovers',async()=>{
 box.clone.mockRejectedValueOnce(Error('mock sandbox outage'));
 await intake();expect(await runDevelopmentWorkerOnce(deps,worker)).toBe(true);
 expect((await get()).status).toBe(404);
 const pending=await (await intake()).json();expect(pending).toMatchObject({pending:true});expect(pending.retryAfterSeconds).toBeGreaterThan(50);
 store.db.prepare("UPDATE jobs SET leaseUntil=0 WHERE state='retry'").run();
 expect(await runDevelopmentWorkerOnce(deps,worker)).toBe(true);
 const done=await (await intake()).json();
 expect(done.signedVerdict.body).toMatchObject({verdict:'clean',scope:'repository'});expect(done.transaction).toEqual(expect.any(String));
 expect(store.db.prepare('SELECT attempts FROM jobs').get()).toEqual({attempts:1});
});
it('reuses the originally admitted creator authorization and checks the current creator',async()=>{
 const target=state.hash;state.hash='a'.repeat(64);
 const auth={issuedAt:new Date().toISOString(),nonce:'ab'.repeat(16)};
 const creatorAuthorization={...auth,signature:sign(null,creatorRequestBytes(creator.address,TASK,target,auth),creator.privateKey).toString('hex')};
 const body={task:TASK,jobSpecHash:target,spec:PAYLOAD,creatorAuthorization};
 const first=await post('/v1/moderation/tasks',body);expect(first.status).toBe(202);
 expect((await post('/v1/moderation/tasks',body)).status).toBe(202);
 // R completion uses the admitted wallet proof rather than the description.
 await runDevelopmentWorkerOnce(deps,worker);
 expect((await post('/v1/moderation/tasks',body)).status).toBe(200);expect(spend().n).toBe(0);expect(state.events).toEqual([]);
});
it('counts queued jobs against the creator outstanding transaction cap',async()=>{
 deps.spendLimits={...DEFAULT_SPEND_LIMITS,outstandingTransactions:1};handler=api();expect((await intake()).status).toBe(202);
 expect((await intake(SUBMISSION)).status).toBe(429);expect(spend()).toEqual({n:0,total:0});
});
it('keeps one live hash while a repository worker job is pending',async()=>{
 await intake();const other={...PAYLOAD,title:'Different work'};const otherHash=(await values.canonicalJobSpecHash(other)).hex;state.hash=otherHash;
 expect((await post('/v1/moderation/tasks',{task:TASK,jobSpecHash:otherHash,spec:other})).status).toBe(409);expect(spend().n).toBe(0);
});
it('preserves a reviewed report when retrievability fails and resumes on Desktop retry',async()=>{
 await intake();const l=await lease(),r=await processJob(l.job,worker);
 vi.stubGlobal('fetch',vi.fn(async()=>new Response('{}',{status:404})));
 expect((await review(l,r)).status).toBe(200);expect(store.job(l.jobId)?.state).toBe('reviewed');expect((await get()).status).toBe(404);expect(state.events).toEqual([]);
 vi.stubGlobal('fetch',vi.fn(async()=>new Response(JSON.stringify(PAYLOAD))));
 expect((await intake()).status).toBe(200);expect(state.events).toEqual([]);expect(spend().n).toBe(0);
});
it('finalizes with the spec URI of the request that opened the intake',async()=>{
 const CREATOR_URI='https://mock.test/creator-spec',OTHER_URI='https://mock.test/other-spec';
 expect((await post('/v1/moderation/tasks',{task:TASK,jobSpecHash:state.hash,spec:PAYLOAD,specUri:CREATOR_URI})).status).toBe(202);
 // Finalization fails once: the registry and the creator URI both miss.
 const l=await lease(),r=await processJob(l.job,worker);
 vi.stubGlobal('fetch',vi.fn(async()=>new Response('{}',{status:404})));
 expect((await review(l,r)).status).toBe(200);expect((await get()).status).toBe(404);
 // Anyone may POST for a committed hash. A different URI is neither refused nor used: it cannot finalize with it.
 state.hosted=[OTHER_URI];
 expect((await post('/v1/moderation/tasks',{task:TASK,jobSpecHash:state.hash,spec:PAYLOAD,specUri:OTHER_URI})).status).not.toBe(200);
 expect((await get()).status).toBe(404);
 // A retry without a URI resumes with the URI bound at enqueue.
 state.hosted=[CREATOR_URI];
 const done=await post('/v1/moderation/tasks',{task:TASK,jobSpecHash:state.hash,spec:PAYLOAD});expect(done.status).toBe(200);
 expect((await done.json()).signedVerdict.body.jobSpecUri).toBe(CREATOR_URI);expect(state.events).toEqual([]);expect(spend().n).toBe(0);
});
it('does not lock the creator out when a third party opens the intake first with its own URI',async()=>{
 const CREATOR_URI='https://mock.test/creator-spec',OTHER_URI='https://mock.test/other-spec';
 state.hosted=[OTHER_URI,CREATOR_URI];
 expect((await post('/v1/moderation/tasks',{task:TASK,jobSpecHash:state.hash,spec:PAYLOAD,specUri:OTHER_URI})).status).toBe(202);
 const creator=await post('/v1/moderation/tasks',{task:TASK,jobSpecHash:state.hash,spec:PAYLOAD,specUri:CREATOR_URI});
 expect(creator.status).not.toBe(409);expect([200,202]).toContain(creator.status);
});
it('returns a receipt without a payment offer when reusing an existing valid chain record',async()=>{
 await intake();state.record=record();await runDevelopmentWorkerOnce(deps,worker);
 const paid=await (await get()).json();expect(paid.attested).toBe(true);expect(paid.transaction).toBeUndefined();expect(paid.signedVerdict.body.record.txSignature).toBeTruthy();expect(state.events).toEqual([]);expect(spend().n).toBe(0);
});
it('recovers a deliverable review journaled immediately before a crash',async()=>{
 await acceptedIntake();readySubmission();await deliverable();await runDevelopmentWorkerOnce(deps,worker);
 store.db.prepare("UPDATE jobs SET state='reviewed',result=NULL WHERE kind='deliverable'").run();
 const done=await deliverable();expect(done.status).toBe(200);expect((await done.json()).signedVerdict.body.kind).toBe('deliverable-review');expect(state.events).toEqual([]);
});
it('keeps development worker execution disabled in production',async()=>{
 const old=process.env.NODE_ENV;process.env.NODE_ENV='production';
 try { await expect(runDevelopmentWorkerOnce(deps,worker)).rejects.toThrow('forbidden'); }
 finally { process.env.NODE_ENV=old; }
 expect(box.clone).not.toHaveBeenCalled();
});

it('reissues an expired repo offer with the same verdict, fee and one worker job',async()=>{
 deps.attestationServiceFeeLamports=987;handler=api();await intake();await runDevelopmentWorkerOnce(deps,worker);
 const first=await (await intake()).json();expect(first.priceLamports).toBe(2520507);
 state.height=101n;state.blockhashByte=8;state.lastValid=200n;deps.attestationServiceFeeLamports=9999;
 const second=await (await intake()).json();expect(second.transaction).not.toBe(first.transaction);expect(second.lastValidBlockHeight).toBe(200);
 expect(second.signedVerdict).toEqual(first.signedVerdict);expect(second.priceLamports).toBe(first.priceLamports);expect(second.serviceFeeLamports).toBe(987);
 expect((await (await intake()).json()).transaction).toBe(second.transaction);
 expect(store.db.prepare('SELECT COUNT(*) AS n FROM jobs').get()).toEqual({n:1});expect(store.db.prepare('SELECT COUNT(*) AS n FROM admissions').get()).toEqual({n:1});expect(state.events).toEqual([]);
});
