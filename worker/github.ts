import { check, hash, INFRA_HOLD, LICENSES, LIMITS, SHA40, type Check, type GithubSpec, type RepoFacts } from './types.js';
import { licenseFromFile } from './rules.js';
import { readFileSync } from 'node:fs';
import { jsonTransport, type JsonRequest } from './http.js';

const GITHUB_TOKEN = /^(?:github_pat_[A-Za-z0-9_]{20,255}|gh[pousr]_[A-Za-z0-9]{20,255})$/;
/** A read-only token for public repositories raises GitHub's limit from 60 to 5000 requests an
 * hour. It comes from GITHUB_TOKEN_FILE (a systemd credential); without it GitHub is called anonymously. */
export function githubToken(env: NodeJS.ProcessEnv = process.env): string | undefined {
  if (!env.GITHUB_TOKEN_FILE) return undefined;
  const token = readFileSync(env.GITHUB_TOKEN_FILE, 'utf8').trim();
  if (!GITHUB_TOKEN.test(token)) throw new Error('GITHUB_TOKEN_FILE does not hold a GitHub token');
  return token;
}

type Metadata = { id:number; owner:{login:string}; name:string; private:boolean; visibility:string;
  archived:boolean; disabled:boolean; size:number; default_branch:string };
export interface GithubResult { checks: Check[]; facts: RepoFacts | null; licenseFile: Buffer | null }
export const GITHUB_CHECKS = ['github-metadata','github-license','github-commit'];
export class GithubClient {
  constructor(private readonly get: JsonRequest = jsonTransport(['api.github.com'],undefined,githubToken())) {}
  async headTree(spec: GithubSpec, headCommit: string): Promise<string> {
    if (!SHA40.test(headCommit)) throw new Error('Invalid head');
    const root = `https://api.github.com/repos/${spec.owner}/${spec.repo}`;
    const head = await this.get(`${root}/git/commits/${headCommit}`) as {sha:string;tree:{sha:string}};
    const compare = await this.get(`${root}/compare/${spec.baseCommit}...${headCommit}`) as {status:string;merge_base_commit:{sha:string}};
    if (head.sha !== headCommit || !SHA40.test(head.tree?.sha) || !['ahead','identical'].includes(compare.status) ||
      compare.merge_base_commit?.sha !== spec.baseCommit) throw new Error('Head commit/base ancestry');
    return head.tree.sha;
  }
  async inspect(spec: GithubSpec, expectedId?: number): Promise<GithubResult> {
    const checks: Check[] = [];
    try {
      let id = expectedId;
      if (id === undefined) {
        const named = await this.get(`https://api.github.com/repos/${spec.owner}/${spec.repo}`) as Metadata;
        id = named.id;
      }
      if (!Number.isSafeInteger(id) || id! <= 0) throw new Error();
      const meta = await this.get(`https://api.github.com/repositories/${id}`) as Metadata;
      if (meta.id !== id || meta.owner?.login?.toLowerCase() !== spec.owner.toLowerCase() ||
          meta.name?.toLowerCase() !== spec.repo.toLowerCase() || meta.private !== false || meta.visibility !== 'public' ||
          meta.archived !== false || meta.disabled !== false || !Number.isSafeInteger(meta.size) || meta.size < 0 ||
          meta.size > LIMITS.repoKiB || typeof meta.default_branch !== 'string' || !meta.default_branch) {
        return {checks:[check('github-metadata','reject','Repo identity/visibility/state/size')],facts:null,licenseFile:null};
      }
      checks.push(check('github-metadata','pass'));
      const root = `https://api.github.com/repos/${spec.owner}/${spec.repo}`;
      const lic = await this.get(`${root}/license?ref=${spec.baseCommit}`) as {license?:{spdx_id:string};content?:string;encoding?:string;path?:string;size?:number};
      const bytes = lic.encoding === 'base64' && typeof lic.content === 'string' ? Buffer.from(lic.content.replace(/\s/g,''),'base64') : null;
      const spdx = lic.license?.spdx_id;
      if (!bytes || bytes.length > LIMITS.fileBytes || !/^(?:LICENSE|LICENCE)(?:\.md|\.txt)?$/i.test(lic.path ?? '') ||
          !LICENSES.includes(spdx as typeof LICENSES[number]) || spdx !== spec.license || licenseFromFile(bytes) !== spdx) {
        return {checks:[...checks,check('github-license','reject','API/file SPDX mismatch or unsupported license')],facts:null,licenseFile:null};
      }
      checks.push(check('github-license','pass'));
      const commit = await this.get(`${root}/git/commits/${spec.baseCommit}`) as {sha:string;tree:{sha:string}};
      const branch = await this.get(`${root}/branches/${encodeURIComponent(meta.default_branch)}`) as {commit:{sha:string}};
      if (commit.sha !== spec.baseCommit || !SHA40.test(commit.tree?.sha) || !SHA40.test(branch.commit?.sha)) throw new Error();
      const compare = await this.get(`${root}/compare/${spec.baseCommit}...${branch.commit.sha}`) as {status:string;merge_base_commit:{sha:string}};
      if (!['ahead','identical'].includes(compare.status) || compare.merge_base_commit?.sha !== spec.baseCommit) {
        return {checks:[...checks,check('github-commit','reject','Base not reachable from default branch')],facts:null,licenseFile:null};
      }
      // Close named-route identity races: no owner transfer or repo substitution.
      const again = await this.get(`${root}`) as Metadata;
      if (again.id !== id || again.default_branch !== meta.default_branch) throw new Error();
      checks.push(check('github-commit','pass'));
      return { checks, licenseFile:bytes, facts:{id:id!,owner:spec.owner,name:spec.repo,licenseSpdx:spdx!,
        baseCommit:spec.baseCommit,treeSha:commit.tree.sha,defaultBranch:meta.default_branch,licenseFileSha256:hash(bytes)} };
    } catch {
      return {checks:[...checks,check(GITHUB_CHECKS[checks.length] ?? 'github-commit','hold',INFRA_HOLD.github)],facts:null,licenseFile:null};
    }
  }
}
