import { check, hash, inAllowed, LIMITS, safePath, SHA40, SHA256, type Artifact, type Check, type GithubSpec, type RepoFacts } from './types.js';
import { INSTALL_SCRIPTS, isInstruction, secret } from './rules.js';
import { LOCKFILES } from './dependencies.js';
import { jsonTransport, type JsonRequest } from './http.js';

/** Registry object wire format: {manifest,patchBase64}. SHA-256 commits to the
 * entire exact UTF-8 object bytes, not only to the patch or a reserialization. */
export function parseArtifact(bytes: Buffer, sha256: string): Artifact {
  if (bytes.length > LIMITS.artifactBytes || hash(bytes) !== sha256) throw new Error('Artifact digest/size');
  const obj = JSON.parse(bytes.toString('utf8'));
  if (!obj || typeof obj.patchBase64 !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(obj.patchBase64)) throw new Error('Artifact encoding');
  const patch = Buffer.from(obj.patchBase64,'base64'), m = obj.manifest;
  if (!m || !SHA40.test(m.baseCommit) || !SHA40.test(m.headCommit) || !SHA256.test(m.patchSha256) ||
      !m.repo || !Number.isSafeInteger(m.repo.id) || m.repo.id <= 0 || typeof m.repo.owner !== 'string' || typeof m.repo.name !== 'string' ||
      hash(patch) !== m.patchSha256) throw new Error('Manifest/patch digest');
  return {manifest:m,patch};
}
export class ArtifactRegistry {
  private readonly root: URL;
  constructor(root: string) {
    this.root = new URL(root);
    if (this.root.protocol !== 'https:' || this.root.username || this.root.password || this.root.search || this.root.hash || this.root.port) throw new Error('Registry URL');
  }
  async fetch(sha256: string): Promise<Artifact> {
    return parseArtifact(await this.bytes(sha256),sha256);
  }
  async bytes(sha256: string): Promise<Buffer> {
    if (!SHA256.test(sha256)) throw new Error('Artifact hash');
    // Registry must expose immutable objects wrapped as {bytesBase64}; the
    // digest is of decoded exact object bytes. Transport never follows redirects.
    const get: JsonRequest = jsonTransport([this.root.hostname],LIMITS.artifactBytes*2);
    const reply = await get(`${this.root.href.replace(/\/$/,'')}/artifacts/${sha256}`) as {bytesBase64:string};
    if (!reply || typeof reply.bytesBase64 !== 'string') throw new Error('Registry response');
    const bytes = Buffer.from(reply.bytesBase64,'base64');
    if (bytes.length > LIMITS.artifactBytes || hash(bytes) !== sha256) throw new Error('Artifact digest/size');
    return bytes;
  }
}
export interface PatchScan { checks: Check[]; paths: string[] }
export const PATCH_CHECKS = ['manifest','diff-size','diff-paths','diff-binary','diff-sensitive','diff-secrets'];
export function scanPatch(artifact: Artifact, spec: GithubSpec, repo: RepoFacts): PatchScan {
  const {manifest:m,patch} = artifact, text = patch.toString('utf8');
  const checks: Check[] = [check('manifest',m.baseCommit === spec.baseCommit && m.baseCommit === repo.baseCommit &&
    m.repo.id === repo.id && m.repo.owner === repo.owner && m.repo.name === repo.name && SHA40.test(m.headCommit) &&
    hash(patch) === m.patchSha256 ? 'pass' : 'reject','Manifest must bind the exact attested repository/base')];
  checks.push(check('diff-size',patch.length <= spec.maxDiffBytes && patch.length <= LIMITS.patchBytes ? 'pass':'reject'));
  const paths: string[] = [], problems: string[] = [], sensitive: string[] = [];
  const headers = [...text.matchAll(/^diff --git a\/([^\n]+) b\/([^\n]+)$/gm)];
  if (!headers.length || text.includes('\0') || Buffer.from(text).compare(patch) !== 0 || !text.startsWith('diff --git ')) problems.push('Malformed/unsupported patch');
  for (const h of headers) {
    for (const path of [h[1],h[2]]) {
      if (!safePath(path) || !inAllowed(path,spec.allowedPaths)) problems.push('Path outside allowedPaths or unsafe');
      paths.push(path);
      if (isInstruction(path) || /^\.github\/workflows\//.test(path) || /(^|\/)(\.gitconfig|\.gitattributes|\.gitmodules|\.npmrc|\.yarnrc(?:\.yml)?|pip\.conf)$/.test(path) ||
        /(^|\/)(build\.rs|setup\.py|Makefile)$/.test(path) || /(^|\/)\.husky\//.test(path)) sensitive.push('Sensitive configuration/instruction file');
    }
  }
  // Git's --numstat and actual index delta are independently checked after
  // apply; do not allow quoted paths or renames to evade lexical screening.
  if (/^(?:rename|copy) (?:from|to) /m.test(text) || /^diff --git .*"/m.test(text)) problems.push('Renames/copies/quoted paths require explicit support');
  const binary = /^(?:GIT binary patch|Binary files |(?:new|old) mode 120000|(?:new|deleted) file mode (?:120000|160000))/m.test(text);
  if (paths.some(p=>/(^|\/)package\.json$/.test(p)) && INSTALL_SCRIPTS.some(s=>new RegExp(`^[+-].*"${s}"\\s*:`, 'm').test(text))) sensitive.push('Install hook changed');
  if (paths.some(p=>LOCKFILES.test(p)) && /^[+-].*(?:https?:|git\+|registry|resolved|integrity)/m.test(text)) sensitive.push('Lockfile source/integrity changed');
  checks.push(check('diff-paths',problems.length ? 'reject':'pass',...new Set(problems)),
    check('diff-binary',binary ? 'reject':'pass'),check('diff-sensitive',sensitive.length ? 'hold':'pass',...new Set(sensitive)),
    check('diff-secrets',secret.test(text) ? 'reject':'pass',...(secret.test(text) ? ['Potential secret (redacted)']:[])));
  return {checks,paths:[...new Set(paths)]};
}
