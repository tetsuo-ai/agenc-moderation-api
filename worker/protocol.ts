import { randomBytes, sign, verify, type KeyObject } from 'node:crypto';
import { documentBytes, publicKeyFromAddress, type SignedDocument } from '../src/verdict.js';
import { decision, IMAGE, LIMITS, objectHash, SHA40, SHA256, validateJob, type Report } from './types.js';
export const REPORT_DOMAIN = Buffer.concat([Buffer.from([255]), Buffer.from('agenc-worker-report/v1'), Buffer.from([0])]);
export function signReport(body: Report, key: KeyObject): SignedDocument<Report> {
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('Ed25519 report key required');
  return { body, signature: sign(null, documentBytes(body, REPORT_DOMAIN), key).toString('hex') };
}
export function reportTimes(now = Date.now()) {
  return { issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 10 * 60_000).toISOString(), nonce: randomBytes(16).toString('hex') };
}
/** Authorized report keys are a separate allowlist, never the V/R manifest. */
export function verifyReport(input: SignedDocument<Report>, workers: Readonly<Record<string, string>>, now = Date.now()): Report {
  const encoded = JSON.stringify(input);
  if (!encoded || Buffer.byteLength(encoded) > LIMITS.reportBytes) throw new Error('Report size');
  const doc = JSON.parse(encoded) as SignedDocument<Report>;
  const r = doc.body;
  if (!r || r.v !== 1 || typeof r.workerId !== 'string' || !Object.hasOwn(workers, r.workerId) ||
      !/^[0-9a-f]{128}$/.test(doc.signature) ||
      !verify(null, documentBytes(r, REPORT_DOMAIN), publicKeyFromAddress(workers[r.workerId]), Buffer.from(doc.signature, 'hex'))) throw new Error('Invalid worker signature');
  const issued = Date.parse(r.issuedAt), expires = Date.parse(r.expiresAt);
  if (!Number.isFinite(issued) || new Date(issued).toISOString() !== r.issuedAt || issued > now + 30_000 ||
      issued < now - 10 * 60_000 || !(expires > now) || expires <= issued || expires - issued > 10 * 60_000 ||
      !/^[0-9a-f]{32}$/.test(r.nonce) || !IMAGE.test(r.imageDigest) || !SHA256.test(r.scannerHash) ||
      !Array.isArray(r.checks) || r.checks.length > 200 || !r.checks.length ||
      !Array.isArray(r.instructionFiles) || r.instructionFiles.length > 100 || r.instructionFiles.some(p=>typeof p !== 'string' || p.length > 1024) ||
      r.checks.some(c => !c || typeof c.id !== 'string' || !['pass','hold','reject'].includes(c.verdict) ||
        !Array.isArray(c.reasons) || c.reasons.some(s => typeof s !== 'string' || s.length > 1024)) ||
      new Set(r.checks.map(c=>c.id)).size !== r.checks.length || r.verdict !== decision(r.checks)) throw new Error('Invalid report schema');
  const job = validateJob(r.job);
  if (r.jobHash !== objectHash(job)) throw new Error('Report job hash');
  if (r.repo && (!Number.isSafeInteger(r.repo.id) || r.repo.id <= 0 || !SHA40.test(r.repo.treeSha) ||
    !SHA40.test(r.repo.baseCommit) || !SHA256.test(r.repo.licenseFileSha256))) throw new Error('Invalid repo facts');
  return r;
}
