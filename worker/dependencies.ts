import { check, LIMITS, type Check, type TreeEntry } from './types.js';
export interface Dependency { name: string; version: string; ecosystem: 'npm' | 'PyPI' | 'crates.io' }
export interface LockScan { checks: Check[]; dependencies: Dependency[]; npmSupported: boolean }
export const LOCKFILES = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|requirements[^/]*\.txt|poetry\.lock|uv\.lock|Pipfile\.lock)$/;
export function parseLocks(entries: TreeEntry[]): LockScan {
  const locks = entries.filter(e=>LOCKFILES.test(e.path));
  const dependencies: Dependency[] = [], reasons: string[] = [];
  let npmSupported = false;
  if (!locks.length) return { checks: [check('lockfiles','hold','Lockfile missing')], dependencies, npmSupported };
  for (const entry of locks) {
    try {
      if (!/^(package-lock\.json|npm-shrinkwrap\.json)$/.test(entry.path)) {
        reasons.push('Unsupported or nested lockfile: '+entry.path); continue;
      }
      const p = JSON.parse(entry.data.toString('utf8'));
      if (![2,3].includes(p.lockfileVersion) || !p.packages || typeof p.packages !== 'object' || Array.isArray(p.packages)) throw new Error();
      npmSupported = true;
      for (const [path, raw] of Object.entries(p.packages)) {
        if (path === '') continue;
        const d = raw as Record<string,unknown>;
        const name = typeof d.name === 'string' ? d.name : path.split('node_modules/').at(-1)!;
        if (!/^(?:@[A-Za-z0-9_.-]+\/)?[A-Za-z0-9_.-]+$/.test(name) || typeof d.version !== 'string' ||
          !/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?$/.test(d.version)) throw new Error();
        if (d.link || typeof d.resolved !== 'string' || !d.resolved.startsWith('https://registry.npmjs.org/') ||
            !/^sha512-[A-Za-z0-9+/]{86}==$/.test(String(d.integrity))) reasons.push('Non-registry/link or missing SHA-512 integrity');
        if (d.hasInstallScript) reasons.push('Dependency install hook');
        dependencies.push({name,version:d.version,ecosystem:'npm'});
      }
    } catch { reasons.push('Malformed or unsupported lockfile: '+entry.path); }
  }
  if (locks.length > 1) reasons.push('Multiple lockfiles require review');
  if (dependencies.length > LIMITS.dependencies) reasons.push('Dependency quota exceeded');
  return { checks: [check('lockfiles', reasons.length ? 'hold' : 'pass',...new Set(reasons))],
    dependencies: dependencies.slice(0,LIMITS.dependencies), npmSupported: npmSupported && !reasons.length };
}
export type OsvQuery = (dependencies: Dependency[]) => Promise<unknown>;
export function parseOsv(response: unknown, expected: number): string[] {
  const r = response as { results?: Array<{ vulns?: Array<{id: string}>; next_page_token?: string }> };
  if (!r || !Array.isArray(r.results) || r.results.length !== expected) throw new Error('Incomplete OSV response');
  const ids: string[] = [];
  for (const row of r.results) {
    if (!row || row.next_page_token || (row.vulns !== undefined && !Array.isArray(row.vulns))) throw new Error('Incomplete OSV page');
    for (const v of row.vulns ?? []) {
      if (!v || typeof v.id !== 'string' || !/^[A-Za-z0-9_.-]{1,200}$/.test(v.id)) throw new Error('Invalid advisory');
      ids.push(v.id);
    }
  }
  return [...new Set(ids)];
}
export async function checkOsv(deps: Dependency[], query: OsvQuery): Promise<Check> {
  try {
    const ids: string[] = [];
    for (let i=0;i<deps.length;i+=100) ids.push(...parseOsv(await query(deps.slice(i,i+100)),Math.min(100,deps.length-i)));
    return check('osv',ids.length ? 'hold' : 'pass',...ids);
  } catch { return check('osv','hold','OSV unavailable, malformed or paginated'); }
}
export function newDependencies(before: Dependency[], after: Dependency[]): Dependency[] {
  const existing = new Set(before.map(d=>`${d.ecosystem}:${d.name}@${d.version}`));
  return after.filter(d=>!existing.has(`${d.ecosystem}:${d.name}@${d.version}`));
}
