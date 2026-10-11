import type { KeyObject } from 'node:crypto';
import type { SignedDocument } from '../src/verdict.js';
import { check, decision, hash, IMAGE, objectHash, validateJob, type Artifact, type Job, type Report } from './types.js';
import { scannerHash } from './rules.js';
import { scanTree } from './tree.js';
import { checkOsv, newDependencies, parseLocks, type OsvQuery } from './dependencies.js';
import { parseArtifact, scanPatch } from './artifact.js';
import { reportTimes, signReport } from './protocol.js';
import type { GithubClient } from './github.js';
import type { Sandbox } from './container.js';

export interface WorkerDeps {
  workerId:string; reportKey:KeyObject; imageDigest:string; github:GithubClient;
  sandbox:()=>Sandbox; artifactBytes:(sha256:string)=>Promise<Buffer>; osv:OsvQuery;
  now?:()=>number;
}
export async function processJob(input: Job, deps: WorkerDeps): Promise<SignedDocument<Report>> {
  const job = validateJob(input);
  if (!IMAGE.test(deps.imageDigest) || !/^[A-Za-z0-9_-]{1,64}$/.test(deps.workerId)) throw new Error('Worker config');
  const report:Report = {v:1,workerId:deps.workerId,job,jobHash:objectHash(job),imageDigest:deps.imageDigest,
    scannerHash:scannerHash(deps.imageDigest),...reportTimes(deps.now?.()),verdict:'hold',checks:[],repo:null,
    artifact:null,tests:null,instructionFiles:[]};
  let sandbox:Sandbox|null = null;
  try {
    const github = await deps.github.inspect(job.github);
    report.checks.push(...github.checks); report.repo = github.facts;
    if (github.facts && decision(report.checks) === 'pass') {
      sandbox = deps.sandbox();
      const base = await sandbox.clone(job.github);
      const license = base.entries.find(e=>/^(?:LICENSE|LICENCE)(?:\.md|\.txt)?$/i.test(e.path));
      report.checks.push(check('checkout-binding',base.treeSha === github.facts.treeSha && license &&
        license.mode !== '120000' && hash(license.data) === github.facts.licenseFileSha256 ? 'pass':'reject'));
      const tree = scanTree(base.entries,job.github);
      report.instructionFiles = tree.instructionFiles;
      if (report.instructionFiles.length > 100) {
        report.instructionFiles = report.instructionFiles.slice(0,100);
        report.checks.push(check('instruction-quota','hold','Instruction list incomplete'));
      }
      report.checks.push(...tree.checks);
      const locks = parseLocks(base.entries);
      report.checks.push(...locks.checks,await checkOsv(locks.dependencies,deps.osv));
      if (job.kind === 'deliverable' && job.artifact && decision(report.checks) === 'pass') {
        const artifact:Artifact = parseArtifact(await deps.artifactBytes(job.artifact.sha256),job.artifact.sha256);
        report.artifact = {sha256:job.artifact.sha256,manifest:artifact.manifest,resultTreeSha:null};
        const diff = scanPatch(artifact,job.github,github.facts);
        report.checks.push(...diff.checks);
        if (decision(report.checks) !== 'reject') {
          const applied = await sandbox.apply(artifact,job.github);
          report.checks.push(...applied.checks);
          if (applied.snapshot) {
            report.artifact.resultTreeSha = applied.snapshot.treeSha;
            const resultScan = scanTree(applied.snapshot.entries,job.github);
            report.checks.push(...resultScan.checks.map(c=>({...c,id:'result-'+c.id})));
            report.instructionFiles = [...new Set([...report.instructionFiles,...resultScan.instructionFiles])].slice(0,100);
            const next = parseLocks(applied.snapshot.entries);
            report.checks.push(...next.checks.map(c=>({...c,id:'result-'+c.id})),
              {...await checkOsv(newDependencies(locks.dependencies,next.dependencies),deps.osv),id:'new-dependencies-osv'});
            try {
              const headTree = await deps.github.headTree(job.github,artifact.manifest.headCommit);
              report.checks.push(check('head-binding',headTree === applied.snapshot.treeSha ? 'pass':'reject'));
            } catch { report.checks.push(check('head-binding','hold','Head commit unavailable or ancestry unverifiable')); }
            if (decision(report.checks) === 'pass' && next.npmSupported) {
              report.tests = await sandbox.test(job.github);
              report.checks.push(check('tests',report.tests.exitCode === 0 && !report.tests.timedOut ? 'pass':'reject',
                ...(report.tests.timedOut ? ['Test timeout']:report.tests.exitCode !== 0 ? ['Tests failed']:[])));
            }
          }
        }
      }
    }
  } catch { report.checks.push(check('worker-error','hold','Incomplete worker check; untrusted details omitted')); }
  finally {
    try { await sandbox?.close(); }
    catch { report.checks.push(check('cleanup','hold','Sandbox cleanup failed')); }
  }
  report.verdict = decision(report.checks);
  Object.assign(report,reportTimes(deps.now?.()));
  return signReport(report,deps.reportKey);
}
/** Sequential queue contract. The queue owns durable leases/ack/redelivery;
 * this consumer authenticates results and processes one job at a time. */
export async function consumeQueue(jobs:AsyncIterable<Job>,deps:WorkerDeps,
  emit:(report:SignedDocument<Report>)=>Promise<void>):Promise<void> {
  for await (const job of jobs) await emit(await processJob(job,deps));
}
