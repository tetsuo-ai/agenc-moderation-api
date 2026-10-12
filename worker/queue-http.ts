import { randomBytes, sign, verify, type KeyObject } from 'node:crypto';
import { documentBytes, publicKeyFromAddress, type SignedDocument } from '../src/verdict.js';
import type { Report, Job } from './types.js';
import { processJob, type WorkerDeps } from './consumer.js';
export const QUEUE_DOMAIN = Buffer.concat([Buffer.from([255]),Buffer.from('agenc-worker-queue/v1'),Buffer.from([0])]);
export interface QueueRequest { workerId:string; path:string; issuedAt:string; nonce:string; payload:Record<string,unknown> }
export function signQueueRequest(workerId:string,path:string,payload:Record<string,unknown>,key:KeyObject):SignedDocument<QueueRequest> {
  const body={workerId,path,payload,issuedAt:new Date().toISOString(),nonce:randomBytes(16).toString('hex')};
  return {body,signature:sign(null,documentBytes(body,QUEUE_DOMAIN),key).toString('hex')};
}
export function verifyQueueRequest(input:SignedDocument<QueueRequest>,path:string,workers:Readonly<Record<string,string>>):QueueRequest {
  const b=input?.body,now=Date.now();
  if(!b || !Object.hasOwn(workers,b.workerId) || b.path !== path || !/^[0-9a-f]{32}$/.test(b.nonce) ||
    !Number.isFinite(Date.parse(b.issuedAt)) || new Date(b.issuedAt).toISOString() !== b.issuedAt || Date.parse(b.issuedAt)>now+30_000 || Date.parse(b.issuedAt)<now-60_000 ||
    !b.payload || typeof b.payload !== 'object' || Array.isArray(b.payload) || !/^[0-9a-f]{128}$/.test(input.signature) ||
    !verify(null,documentBytes(b,QUEUE_DOMAIN),publicKeyFromAddress(workers[b.workerId]),Buffer.from(input.signature,'hex'))) throw new Error('Worker transport authentication');
  return b;
}
export interface Lease { jobId:string; leaseToken:string; leaseExpiresAt:string; job:Job }
/** One sequential iteration. Retrying a report uses a fresh transport nonce and
 * the exact original report; the signer acknowledges it after durable review. */
export async function runHttpWorkerOnce(url:string,deps:WorkerDeps,fetcher:typeof fetch=fetch):Promise<boolean> {
  async function post(path:string,payload:Record<string,unknown>) {
    const res=await fetcher(new URL(path,url),{method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify(signQueueRequest(deps.workerId,path,payload,deps.reportKey)),redirect:'error',signal:AbortSignal.timeout(120_000)});
    if(!res.ok) throw new Error(`Queue refused ${res.status}`); return res;
  }
  const pulled=await post('/internal/worker/pull',{});
  if(pulled.status===204) return false;
  const lease=await pulled.json() as Lease;
  const report:SignedDocument<Report>=await processJob(lease.job,deps);
  // Preserve the same in-memory report on transient network failure. A process
  // crash redelivers the job after its durable lease expires.
  for(let attempt=0;;attempt++) {
    try { await post('/internal/worker/reports',{jobId:lease.jobId,leaseToken:lease.leaseToken,report}); return true; }
    catch(e) { if(attempt>=2) throw e; await new Promise(resolve=>setTimeout(resolve,1000)); }
  }
}
