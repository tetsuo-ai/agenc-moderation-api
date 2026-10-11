import { createHash } from 'node:crypto';
import { canonicalJson } from '../src/verdict.js';

export type Decision = 'pass' | 'hold' | 'reject';
export interface Check { id: string; verdict: Decision; reasons: string[] }
export interface GithubSpec {
  owner: string; repo: string; license: string; baseCommit: string;
  issueUrl?: string; workType: string; allowedPaths: string[]; maxDiffBytes: number;
  testCommand: string; needsNetworkForInstall: boolean;
}
export interface Job {
  kind: 'repo-intake' | 'deliverable'; taskPda: string; jobSpecHash: string;
  github: GithubSpec;
  artifact?: { sha256: string; submissionPda: string };
}
export interface RepoFacts {
  id: number; owner: string; name: string; licenseSpdx: string; baseCommit: string;
  treeSha: string; defaultBranch: string; licenseFileSha256: string;
}
export interface TreeEntry { path: string; mode: string; data: Buffer }
export interface Manifest {
  repo: { id: number; owner: string; name: string }; baseCommit: string;
  headCommit: string; patchSha256: string;
}
export interface Artifact { manifest: Manifest; patch: Buffer }
export interface Report {
  v: 1; workerId: string; job: Job; jobHash: string; scannerHash: string;
  imageDigest: string; issuedAt: string; expiresAt: string; nonce: string;
  verdict: Decision; checks: Check[]; repo: RepoFacts | null;
  artifact: { sha256: string; manifest: Manifest; resultTreeSha: string | null } | null;
  instructionFiles: string[];
  tests: { exitCode: number | null; timedOut: boolean; outputSha256: string } | null;
}
export const SHA40 = /^[0-9a-f]{40}$/;
export const SHA256 = /^[0-9a-f]{64}$/;
export const IMAGE = /^sha256:[0-9a-f]{64}$/;
export const LIMITS = Object.freeze({ repoKiB: 100_000, treeBytes: 64 * 1024 * 1024,
  fileBytes: 2 * 1024 * 1024, entries: 10_000, patchBytes: 2 * 1024 * 1024,
  artifactBytes: 3 * 1024 * 1024, dependencies: 1000, reportBytes: 256 * 1024,
  tmpfsBytes: 512 * 1024 * 1024, memoryBytes: 768 * 1024 * 1024,
  pids: 128, cpus: 1, phaseMs: 120_000, jobMs: 600_000 });
export const LICENSES = ['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC'] as const;
export function hash(value: Buffer | string): string { return createHash('sha256').update(value).digest('hex'); }
export function objectHash(value: unknown): string { return hash(canonicalJson(value)); }
export function check(id: string, verdict: Decision, ...reasons: string[]): Check { return { id, verdict, reasons }; }
/** Hold reasons that mean a check could not run (GitHub, OSV, Podman), not that the repo is risky. */
export const INFRA_HOLD = Object.freeze({
  worker: 'Incomplete worker check; untrusted details omitted',
  github: 'GitHub unavailable or incomplete facts',
  osv: 'OSV unavailable, malformed or paginated',
  cleanup: 'Sandbox cleanup failed',
  head: 'Head commit unavailable or ancestry unverifiable',
});
const INFRA_REASONS: ReadonlySet<string> = new Set(Object.values(INFRA_HOLD));
/** True when the only checks that did not pass are holds caused by infrastructure. */
export function infrastructureHold(checks: Check[]): boolean {
  const open = checks.filter(c => c.verdict !== 'pass');
  return open.length > 0 && open.every(c => c.verdict === 'hold' && c.reasons.length > 0 && c.reasons.every(r => INFRA_REASONS.has(r)));
}
export function decision(checks: Check[]): Decision {
  return checks.some(c => c.verdict === 'reject') ? 'reject' : checks.some(c => c.verdict === 'hold') ? 'hold' : 'pass';
}
export function safePath(path: unknown): path is string {
  return typeof path === 'string' && path.length > 0 && path.length <= 1024 &&
    !/[\\\x00-\x20\x7f]/.test(path) && !path.startsWith('/') &&
    path.split('/').every(p => p && p !== '.' && p !== '..' && p.toLowerCase() !== '.git');
}
export function inAllowed(path: string, allowed: string[]): boolean {
  return allowed.some(p => path === p || path.startsWith(p + '/'));
}
export function validateJob(input: unknown): Job {
  // Make a private JSON snapshot so callers cannot mutate a binding across awaits.
  const encoded = JSON.stringify(input);
  if (!encoded || Buffer.byteLength(encoded) > 32_768) throw new Error('Invalid job size');
  const j = JSON.parse(encoded) as Job;
  if (!j || !['repo-intake', 'deliverable'].includes(j.kind) ||
      !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(j.taskPda) || !SHA256.test(j.jobSpecHash)) throw new Error('Invalid job');
  const g = j.github;
  if (!g || !/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(g.owner) ||
      !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/.test(g.repo) || !SHA40.test(g.baseCommit) ||
      typeof g.license !== 'string' || typeof g.workType !== 'string' || !g.workType ||
      !Array.isArray(g.allowedPaths) || !g.allowedPaths.length || g.allowedPaths.length > 100 ||
      !g.allowedPaths.every(safePath) || new Set(g.allowedPaths).size !== g.allowedPaths.length ||
      !Number.isSafeInteger(g.maxDiffBytes) || g.maxDiffBytes <= 0 || g.maxDiffBytes > LIMITS.patchBytes ||
      typeof g.testCommand !== 'string' || g.testCommand.length > 1024 ||
      typeof g.needsNetworkForInstall !== 'boolean') throw new Error('Invalid GitHub spec');
  if (g.issueUrl !== undefined && !new RegExp(`^https://github\\.com/${g.owner}/${g.repo.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/issues/[1-9][0-9]*$`, 'i').test(g.issueUrl)) throw new Error('Invalid issue URL');
  if (j.kind === 'deliverable' ? !j.artifact || !SHA256.test(j.artifact.sha256) ||
      !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(j.artifact.submissionPda) : j.artifact !== undefined) throw new Error('Invalid artifact binding');
  return j;
}
