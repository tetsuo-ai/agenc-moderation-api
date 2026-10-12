/** Trusted durable bridge. Only the signer owns this database; workers receive
 * job snapshots and leases, never keys or authoritative chain context. */
import { address, createSolanaRpc } from '@solana/kit';
import { fetchMaybeTask, fetchMaybeTaskJobSpec, fetchMaybeTaskSubmission, fetchMaybeTaskClaim,
  findTaskJobSpecPda, findTaskSubmissionPda } from '@tetsuo-ai/marketplace-sdk';
import { attestTask, loadModeratorSigner, type AttestDeps, type ModerationResult } from './signer.js';
import { getStore, DEFAULT_SPEND_LIMITS, retryAfterSeconds, type QueueContext, type StoredJob } from './store.js';
import { loadKeyManifest, type SignedDocument } from './verdict.js';
import { ModerationRejectError } from './errors.js';
import { reviewWorkerReport, type RepoReviewContext } from './repo-review.js';
import { IMAGE, infrastructureHold, objectHash, validateJob, type Job, type Report } from '../worker/types.js';
import { verifyReport } from '../worker/protocol.js';
import { processJob, type WorkerDeps } from '../worker/consumer.js';

export interface DeliverableResult { verdict: import('./scan.js').Verdict; moderator:string|null; attestation:null; signedVerdict:SignedDocument; pending?:false }
function deliverableResult(reviewed:SignedDocument):DeliverableResult {
  return {verdict:reviewed.body.verdict as DeliverableResult['verdict'],moderator:(reviewed.body.record as {moderator:string|null}).moderator,attestation:null,signedVerdict:reviewed};
}
/** Waits before a job whose report only said infrastructure failed runs again. After the
 * last one the hold is kept as the final answer, so a repo cannot force endless scans. */
export const RETRY_DELAYS_MS = [60_000, 180_000, 600_000] as const;
export const pendingJob = (job:StoredJob) => ({pending:true as const,jobId:job.id,retryAfterSeconds:retryAfterSeconds(job)});
function settings(deps:AttestDeps) {
  if(!deps.repository || !IMAGE.test(deps.repository.imageDigest) || !Object.keys(deps.repository.workers).length) throw new ModerationRejectError(503,'Worker configuration required.');
  return deps.repository;
}
function intakeKeys():Record<string,string> {
  const keys=loadKeyManifest().body.keys as Array<{keyId:string;publicKey:string;purpose:string;notBefore:string;notAfter:string;revoked?:boolean}>;
  return Object.fromEntries(keys.filter(k=>k.purpose==='verdict' && !k.revoked && Date.parse(k.notBefore)<=Date.now() && Date.parse(k.notAfter)>Date.now()).map(k=>[k.keyId,k.publicKey]));
}
async function contextFor(deps:AttestDeps,stored:StoredJob,job:Job):Promise<RepoReviewContext> {
  const store=deps.store ?? getStore(), saved=JSON.parse(stored.context) as QueueContext;
  if(objectHash(JSON.parse(stored.job)) !== objectHash(job)) throw new ModerationRejectError(409,'Queue binding mismatch.');
  const rpc=createSolanaRpc(deps.rpcUrl),task=await fetchMaybeTask(rpc,address(job.taskPda));
  if(!task.exists || task.data.creator !== saved.creator) throw new ModerationRejectError(409,'Task creator changed.');
  const [specPda]=await findTaskJobSpecPda({task:address(job.taskPda)});
  const pin=await fetchMaybeTaskJobSpec(rpc,specPda);
  if(pin.exists && Buffer.from(pin.data.jobSpecHash).toString('hex') !== job.jobSpecHash) throw new ModerationRejectError(409,'Pin changed.');
  const ctx:RepoReviewContext={taskPda:job.taskPda,creator:saved.creator,jobSpecHash:job.jobSpecHash,payload:saved.payload,
    genesisHash:await rpc.getGenesisHash().send(),cluster:deps.cluster ?? 'mainnet'};
  if(job.kind==='repo-intake') {
    if(task.data.status !== 0 || task.data.currentWorkers !== 0 || task.data.completions !== 0 ||
      (!saved.authenticatedCreator && Buffer.from(task.data.description).subarray(0,32).toString('hex') !== job.jobSpecHash)) throw new ModerationRejectError(409,'Intake binding changed.');
  } else {
    if(!pin.exists || ![0,1,2].includes(task.data.status)) throw new ModerationRejectError(409,'Review requires a live task and pinned spec.');
    const sub=await fetchMaybeTaskSubmission(rpc,address(job.artifact!.submissionPda));
    if(!sub.exists) throw new ModerationRejectError(404,'Submission missing.');
    const [expected]=await findTaskSubmissionPda({claim:sub.data.claim});
    const claim=await fetchMaybeTaskClaim(rpc,sub.data.claim);
    if(expected !== job.artifact!.submissionPda || sub.data.task !== job.taskPda || sub.data.status !== 1 ||
      !claim.exists || claim.data.task !== job.taskPda || claim.data.worker !== sub.data.worker ||
      Buffer.from(sub.data.proofHash).toString('hex') !== job.artifact!.sha256) throw new ModerationRejectError(409,'Submission binding mismatch.');
    const intake=store.get(job.taskPda);
    if(!intake?.result || intake.expires<=Date.now()) throw new ModerationRejectError(409,'Stored intake required.');
    ctx.intake=(JSON.parse(intake.result) as ModerationResult).signedVerdict;
    ctx.submission={taskPda:job.taskPda,submissionPda:job.artifact!.submissionPda,artifactSha256:Buffer.from(sub.data.proofHash).toString('hex')};
  }
  return ctx;
}
export async function enqueueDeliverable(deps:AttestDeps,params:{task:string;submissionPda:string;artifactSha256:string}) {
  settings(deps);
  const store=deps.store ?? getStore(),intakeJob=store.intakeJob(params.task,store.get(params.task)?.hash ?? '');
  if(!intakeJob) throw new ModerationRejectError(409,'Repository intake required.');
  const base=JSON.parse(intakeJob.job) as Job;
  const job=validateJob({...base,kind:'deliverable',artifact:{sha256:params.artifactSha256,submissionPda:params.submissionPda}});
  const existing=store.deliverableJob(params.task,params.submissionPda,params.artifactSha256);
  if(existing?.result && existing.expires>Date.now()) return JSON.parse(existing.result) as DeliverableResult;
  const candidate=existing ?? {...intakeJob,job:JSON.stringify(job)};
  const ctx=await contextFor(deps,candidate,job);
  // Reuse phase 2's accepted-intake checks at report time; early checks prevent
  // spending scanner quota on a known held intake.
  if(ctx.intake?.body.verdict !== 'clean' || ctx.intake.body.scope !== 'repository') throw new ModerationRejectError(409,'Clean repository intake required.');
  if(existing?.reviewed && !existing.result) {
    const reviewed=JSON.parse(existing.reviewed) as SignedDocument;
    const result=deliverableResult(reviewed);
    store.finishJob(existing.id,result,Date.parse(String(reviewed.body.expiresAt))); return result;
  }
  if(existing) return pendingJob(existing);
  return pendingJob(store.enqueueDeliverable(job,JSON.parse(intakeJob.context) as QueueContext,deps.spendLimits ?? DEFAULT_SPEND_LIMITS));
}
/** Authenticate and atomically journal the rechecked report+nonce before any
 * chain action. Failures after this point can be resumed through Desktop POST. */
export async function acceptQueuedReport(deps:AttestDeps,workerId:string,input:{jobId:string;leaseToken:string;report:SignedDocument<Report>}) {
  if(!input || typeof input.jobId !== 'string' || !/^[0-9a-f-]{36}$/.test(input.jobId) || typeof input.leaseToken !== 'string' || !/^[0-9a-f]{48}$/.test(input.leaseToken) || !input.report || typeof input.report !== 'object') throw new ModerationRejectError(400,'Malformed worker report request.');
  const config=settings(deps),store=deps.store ?? getStore(),stored=store.job(input.jobId);
  if(!stored || stored.worker !== workerId || stored.lease !== input.leaseToken) throw new ModerationRejectError(409,'Lease mismatch.');
  if(stored.report) {
    if(objectHash(JSON.parse(stored.report)) !== objectHash(input.report)) throw new ModerationRejectError(409,'Different report already recorded.');
    if(stored.kind === 'deliverable' && !stored.result && stored.reviewed) {
      const reviewed=JSON.parse(stored.reviewed) as SignedDocument;
      store.finishJob(stored.id,deliverableResult(reviewed),Date.parse(String(reviewed.body.expiresAt)));
    }
    return {accepted:true,jobId:stored.id};
  }
  if(stored.state !== 'leased' || stored.leaseUntil<=Date.now()) throw new ModerationRejectError(409,'Lease expired.');
  try {
    const verified=verifyReport(input.report,config.workers);
    if(verified.workerId !== workerId) throw new Error('Worker mismatch');
  } catch { throw new ModerationRejectError(403,'Invalid worker report.'); }
  const moderator=await loadModeratorSigner();
  let nonce: {worker:string;value:string}|undefined;
  const reviewed=await reviewWorkerReport({workers:config.workers,imageDigest:config.imageDigest,github:config.github,
    moderator:moderator.address,intakeKeys:intakeKeys(),resolveContext:job=>contextFor(deps,stored,job),
    consumeNonce:(worker,value)=>{nonce={worker,value};}},input.report);
  await contextFor(deps,stored,validateJob(input.report.body.job));
  // A GitHub, OSV or Podman outage is not a finding about the repo: scan again later.
  const attempt=stored.attempts ?? 0;
  const retry=reviewed.body.verdict === 'suspicious' && infrastructureHold(reviewed.body.checks as Report['checks']) && attempt < RETRY_DELAYS_MS.length;
  // Another report may have won while the independent reads were in flight.
  store.db.exec('BEGIN IMMEDIATE');
  try {
    const current=store.job(stored.id)!;
    if(current.state !== 'leased' || current.lease !== input.leaseToken || current.leaseUntil<=Date.now()) throw new ModerationRejectError(409,'Lease changed.');
    store.consumeNonce('report:'+nonce!.worker,nonce!.value);
    if(retry) store.retryJob(stored.id,Date.now()+RETRY_DELAYS_MS[attempt]!);
    else store.saveReview(stored.id,reviewed,input.report);
    store.db.exec('COMMIT');
  } catch(e) { store.db.exec('ROLLBACK');throw e; }
  if(retry) { store.audit('repo-retry',{jobId:stored.id,attempt:attempt+1}); return {accepted:true,jobId:stored.id}; }
  if(input.report.body.job.kind==='deliverable') {
    const result=deliverableResult(reviewed);
    store.finishJob(stored.id,result,Date.parse(String(reviewed.body.expiresAt)));
  } else {
    const saved=JSON.parse(stored.context) as QueueContext;
    // Report ack must survive retryable chain/retrievability errors; the report
    // remains durable and the existing Desktop POST resumes finalization.
    try { await attestTask(deps,{task:stored.task,jobSpecHash:stored.hash,spec:saved.payload,specUri:saved.specUri}); }
    catch { store.audit('repo-finalization-pending',{jobId:stored.id}); }
  }
  return {accepted:true,jobId:stored.id};
}
/** Explicit development harness: runs the actual worker and signer in process.
 * Tests provide a mock Sandbox and mock RPC; production must use HTTP leases. */
export async function runDevelopmentWorkerOnce(deps:AttestDeps,worker:WorkerDeps):Promise<boolean> {
  if(process.env.NODE_ENV==='production') throw new Error('Development worker forbidden in production');
  const store=deps.store ?? getStore(),job=store.leaseJob(worker.workerId);
  if(!job) return false;
  const report=await processJob(JSON.parse(job.job) as Job,worker);
  await acceptQueuedReport(deps,worker.workerId,{jobId:job.id,leaseToken:job.lease!,report});return true;
}
