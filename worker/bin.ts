#!/usr/bin/env node
import { createPrivateKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { once } from 'node:events';
import { consumeQueue } from './consumer.js';
import { ContainerSandbox, type ContainerConfig } from './container.js';
import { GithubClient } from './github.js';
import { ArtifactRegistry } from './artifact.js';
import { jsonTransport } from './http.js';
import { validateJob, type Job } from './types.js';

async function* inputJobs():AsyncGenerator<Job> {
  let pending = Buffer.alloc(0);
  for await (const raw of process.stdin) {
    pending = Buffer.concat([pending,Buffer.from(raw)]);
    let newline:number;
    while ((newline=pending.indexOf(10)) >= 0) {
      if (newline > 32_768) throw new Error('Queue line size');
      const line = pending.subarray(0,newline); pending = pending.subarray(newline+1);
      if (line.length) yield validateJob(JSON.parse(line.toString('utf8')));
    }
    if (pending.length > 32_768) throw new Error('Queue line size');
  }
  if (pending.length) yield validateJob(JSON.parse(pending.toString('utf8')));
}
async function main() {
  if (process.env.VERDICT_KEY_FILE || process.env.VERDICT_KEY_SECRET || process.env.MODERATION_SIGNER_SECRET_FILE ||
      process.env.MODERATION_SIGNER_SECRET || process.env.MODERATION_AUTHORITY_SECRET) throw new Error('Signer credentials forbidden on worker');
  const path = process.argv[2];
  if (!path || !process.env.REPORT_KEY_FILE) throw new Error('Worker config and report key file required');
  const config = JSON.parse(readFileSync(path,'utf8')) as ContainerConfig & {workerId:string;artifactRegistryUrl:string};
  if (!['podman','docker'].includes(config.cli)) throw new Error('Invalid engine');
  const reportKey = createPrivateKey(readFileSync(process.env.REPORT_KEY_FILE));
  if (reportKey.asymmetricKeyType !== 'ed25519') throw new Error('Ed25519 report key required');
  const registry = new ArtifactRegistry(config.artifactRegistryUrl);
  const osv = jsonTransport(['api.osv.dev']);
  await consumeQueue(inputJobs(),{workerId:config.workerId,reportKey,imageDigest:config.image.split('@')[1],github:new GithubClient(),
    sandbox:()=>new ContainerSandbox(config),artifactBytes:sha=>registry.bytes(sha),
    osv:deps=>osv('https://api.osv.dev/v1/querybatch',{queries:deps.map(d=>({package:{name:d.name,ecosystem:d.ecosystem},version:d.version}))})},
  async report=>{ if (!process.stdout.write(JSON.stringify(report)+'\n')) await once(process.stdout,'drain'); });
}
main().catch(()=>{process.stderr.write('Worker failed; queue item must remain unacknowledged\n');process.exitCode=1;});
