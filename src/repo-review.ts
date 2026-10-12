/** Internal signer seam. Never imports the transaction sender. Callers supply
 * a context from trusted task/submission reads and phase-1 creator binding. */
import { verify, type KeyObject } from 'node:crypto';
import { values } from '@tetsuo-ai/marketplace-sdk';
import { AGENC_COORDINATION_PROGRAM_ADDRESS } from '@tetsuo-ai/marketplace-sdk';
import { authorizedVerdictKey, documentBytes, keyAddress, publicKeyFromAddress, signDocument, type SignedDocument } from './verdict.js';
import { moderationPolicyHashHex } from './policy.js';
import { scanPayload } from './scan.js';
import { assertJsonDepth } from './json-depth.js';
import { scannerHash } from '../worker/rules.js';
import { verifyReport } from '../worker/protocol.js';
import { GITHUB_CHECKS, GithubClient } from '../worker/github.js';
import { TREE_CHECKS } from '../worker/tree.js';
import { PATCH_CHECKS } from '../worker/artifact.js';
import { check, decision, objectHash, SHA40, SHA256, validateJob, type Job, type Report } from '../worker/types.js';

export interface RepoReviewContext {
  taskPda:string; creator:string; jobSpecHash:string; payload:Record<string,unknown>;
  genesisHash:string; cluster:string;
  // For deliverables, verified submission data and the accepted repo intake.
  submission?:{submissionPda:string;artifactSha256:string;taskPda:string};
  intake?:SignedDocument;
}
export interface RepoReviewDeps {
  workers:Readonly<Record<string,string>>; imageDigest:string; github?:GithubClient;
  moderator:string|null;
  /** MUST resolve the actual committed job spec, validate task state and creator
   * authorization using phase-1 binding, and read submission ownership/task/hash.
   * Do not implement this by reflecting the submitted worker report. */
  resolveContext:(job:Job)=>Promise<RepoReviewContext>;
  /** Atomic durable replay guard. Existing store.consumeNonce is suitable. */
  consumeNonce:(workerId:string,nonce:string)=>void;
  verdictKey?:()=>{key:KeyObject;keyId:string};
  /** Root-manifest-authorized historical V keys for intake verification. */
  intakeKeys:Readonly<Record<string,string>>;
  now?:()=>number;
}
function acceptedIntake(doc:SignedDocument|undefined,ctx:RepoReviewContext,deps:RepoReviewDeps,now:number) {
  const b = doc?.body;
  if (!doc || !b || b.v !== 1 || b.kind !== 'task-intake' || b.verdict !== 'clean' || b.scope !== 'repository' ||
      b.taskPda !== ctx.taskPda || b.creator !== ctx.creator || b.jobSpecHash !== ctx.jobSpecHash ||
      b.cluster !== ctx.cluster || b.genesisHash !== ctx.genesisHash || b.programId !== AGENC_COORDINATION_PROGRAM_ADDRESS ||
      b.scannerHash !== scannerHash(deps.imageDigest) || b.policyHash !== moderationPolicyHashHex() ||
      !Number.isFinite(Date.parse(String(b.issuedAt))) || Date.parse(String(b.issuedAt)) > now ||
      !(Date.parse(String(b.expiresAt)) > now) || typeof b.keyId !== 'string' ||
      !Object.hasOwn(deps.intakeKeys,b.keyId) || !/^[0-9a-f]{128}$/.test(doc.signature) ||
      !verify(null,documentBytes(b),publicKeyFromAddress(deps.intakeKeys[b.keyId]),Buffer.from(doc.signature,'hex'))) throw new Error('Valid repository intake required');
  return b;
}
export async function reviewWorkerReport(deps:RepoReviewDeps,input:SignedDocument<Report>):Promise<SignedDocument> {
  assertJsonDepth(input);
  const now = deps.now?.() ?? Date.now();
  const report = verifyReport(input,deps.workers,now);
  const job = validateJob(report.job);
  const bundle = scannerHash(deps.imageDigest);
  if (report.imageDigest !== deps.imageDigest || report.scannerHash !== bundle) throw new Error('Worker bundle/image mismatch');
  const {key,keyId} = deps.verdictKey?.() ?? authorizedVerdictKey(deps.moderator);
  const pub = keyAddress(key);
  if (key.asymmetricKeyType !== 'ed25519' || pub === deps.moderator || Object.values(deps.workers).some(k=>
    k === pub || k === deps.moderator || Object.values(deps.intakeKeys).includes(k))) throw new Error('Worker, verdict and roster keys must be separate');
  const ctx = await deps.resolveContext(job);
  assertJsonDepth(ctx.payload);
  const declaredHash = (await values.canonicalJobSpecHash(ctx.payload)).hex;
  const custom = ctx.payload.custom as {github?:unknown}|undefined;
  if (ctx.taskPda !== job.taskPda || ctx.jobSpecHash !== job.jobSpecHash || declaredHash !== job.jobSpecHash ||
      objectHash(custom?.github) !== objectHash(job.github)) throw new Error('Declared spec/task/hash mismatch');
  if (!ctx.creator || !ctx.genesisHash || !ctx.cluster) throw new Error('Missing signer context');
  let intake:Record<string,unknown>|null = null;
  if (job.kind === 'deliverable') {
    const sub = ctx.submission;
    if (!sub || sub.taskPda !== job.taskPda || sub.submissionPda !== job.artifact?.submissionPda ||
        sub.artifactSha256 !== job.artifact?.sha256) throw new Error('Submission binding mismatch');
    intake = acceptedIntake(ctx.intake,ctx,deps,now);
  }
  // Verify even hold/reject reports against current cheap facts. Failure does
  // not produce a clean verdict or convert worker errors into approval.
  const github = deps.github ?? new GithubClient();
  const fresh = await github.inspect(job.github,report.repo?.id);
  if (report.verdict === 'pass' && (!fresh.facts || fresh.checks.some(c=>c.verdict !== 'pass') || !report.repo)) throw new Error('Signer GitHub recheck failed');
  if (report.repo && (!fresh.facts || objectHash(fresh.facts) !== objectHash(report.repo))) throw new Error('Signer GitHub recheck failed');
  if (intake && report.repo && objectHash(intake.repo) !== objectHash(repoBinding(report))) throw new Error('Attested base/repo mismatch');
  if (report.verdict === 'pass') {
    const required = [...GITHUB_CHECKS,'checkout-binding',...TREE_CHECKS,'lockfiles','osv'];
    if (job.kind === 'deliverable') required.push(...PATCH_CHECKS,'patch-apply',...TREE_CHECKS.map(id=>'result-'+id),
      'result-lockfiles','new-dependencies-osv','head-binding','tests');
    if (required.some(id=>!report.checks.some(c=>c.id === id && c.verdict === 'pass'))) throw new Error('Missing required worker check');
  }
  if (job.kind === 'deliverable' && report.artifact) {
    const a = report.artifact;
    if (a.sha256 !== job.artifact?.sha256 || a.manifest.baseCommit !== job.github.baseCommit ||
      objectHash(a.manifest.repo) !== objectHash(report.repo ? {id:report.repo.id,owner:report.repo.owner,name:report.repo.name}:null) ||
      !SHA256.test(a.manifest.patchSha256) || !SHA40.test(a.manifest.headCommit)) throw new Error('Deliverable manifest binding');
    if (report.verdict === 'pass' && (!a.resultTreeSha || !SHA40.test(a.resultTreeSha) ||
      await github.headTree(job.github,a.manifest.headCommit) !== a.resultTreeSha ||
      !report.tests || report.tests.exitCode !== 0 || report.tests.timedOut || !SHA256.test(report.tests.outputSha256))) throw new Error('Signer head/test recheck failed');
  } else if (job.kind === 'deliverable' && report.verdict === 'pass') throw new Error('Missing artifact');
  deps.consumeNonce(report.workerId,report.nonce);
  const payloadPolicy = scanPayload(ctx.payload);
  const checks = [...report.checks,...fresh.checks.map(c=>({...c,id:'signer-'+c.id})),check('payload-policy',payloadPolicy.verdict === 'clean' ? 'pass':
    payloadPolicy.verdict === 'blocked' ? 'reject':'hold',...(payloadPolicy.reasons ?? []))];
  for(const c of checks) if(c.verdict !== 'pass' && !c.reasons.length) c.reasons.push(c.id+': '+c.verdict);
  const outcome = decision(checks);
  const expires = Math.min(now+72*3600_000, intake ? Date.parse(String(intake.expiresAt)) : Infinity);
  const body:Record<string,unknown> = {v:1,kind:job.kind === 'repo-intake' ? 'task-intake':'deliverable-review',
    scope:'repository',taskPda:job.taskPda,creator:ctx.creator,jobSpecHash:job.jobSpecHash,
    cluster:ctx.cluster,genesisHash:ctx.genesisHash,programId:AGENC_COORDINATION_PROGRAM_ADDRESS,
    policyHash:moderationPolicyHashHex(),scannerHash:bundle,imageDigest:report.imageDigest,repo:repoBinding(report) ?? intake?.repo ?? null,
    verdict:outcome === 'pass' ? 'clean':outcome === 'hold' ? 'suspicious':'blocked',
    riskScore:Math.max(payloadPolicy.riskScore,outcome === 'reject' ? 100:outcome === 'hold' ? 60:0),
    categories:payloadPolicy.categories ?? [],reasons:checks.flatMap(c=>c.reasons),
    checks,instructionFiles:report.instructionFiles,reportHash:objectHash(report),workerId:report.workerId,
    record:{moderator:deps.moderator,pda:null,txSignature:null},issuedAt:new Date(now).toISOString(),
    expiresAt:new Date(expires).toISOString(),nonce:report.nonce,keyId};
  if (job.kind === 'deliverable') Object.assign(body,{submissionPda:job.artifact!.submissionPda,
    artifactSha256:job.artifact!.sha256,manifest:report.artifact?.manifest ?? null,
    resultTreeSha:report.artifact?.resultTreeSha ?? null,tests:report.tests,intakeHash:objectHash(ctx.intake!.body)});
  return signDocument(body,key);
}
function repoBinding(report:Report) {
  const r = report.repo;
  if(!r) return null;
  return {id:r.id,owner:r.owner,name:r.name,licenseSpdx:r.licenseSpdx,baseCommit:r.baseCommit,treeSha:r.treeSha,
    allowedPathsHash:objectHash(report.job.github.allowedPaths),maxDiffBytes:report.job.github.maxDiffBytes,
    testCommandHash:objectHash(report.job.github.testCommand)};
}
