import { posix } from 'node:path';
import { check, inAllowed, LIMITS, safePath, type Check, type GithubSpec, type TreeEntry } from './types.js';
import { curlPipe, executableBlob, injection, INSTALL_SCRIPTS, isInstruction, secret } from './rules.js';

export const TREE_CHECKS = ['tree-bounds','paths','install-hooks','blobs','workflows','secrets','allowed-paths','test-runner','agent-instructions'];
export interface TreeScan { checks: Check[]; instructionFiles: string[] }
export function testArgv(command: string): string[] {
  // No shell interpolation, redirects, environment assignments or arbitrary
  // package-manager flags. The script itself remains untrusted container code.
  if (!/^npm (?:test|run [A-Za-z0-9:_-]+)$/.test(command)) throw new Error('Unsupported test command');
  return command.split(' ');
}
export function scanTree(entries: TreeEntry[], spec: GithubSpec): TreeScan {
  const checks: Check[] = [];
  const reasons: Record<string, string[]> = Object.fromEntries(TREE_CHECKS.map(k => [k, []]));
  const total = entries.reduce((n,e)=>n+e.data.length,0);
  if (entries.length > LIMITS.entries || total > LIMITS.treeBytes) reasons['tree-bounds'].push('Tree quota exceeded');
  const names = new Set<string>(), folded = new Set<string>();
  const instructionFiles: string[] = [];
  for (const e of entries) {
    const path = e.path, rawText = e.data.toString('utf8');
    const text = rawText.normalize('NFKC').replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g,'').replace(/\\\r?\n/g,' ');
    if (!safePath(path) || names.has(path)) reasons.paths.push('Unsafe or duplicate path');
    names.add(path);
    // Include directory prefixes, not just leaf names (Src/a vs src/b).
    const parts = path.split('/');
    for (let i=1;i<=parts.length;i++) {
      const prefix = parts.slice(0,i).join('/');
      const lower = prefix.normalize('NFKC').toLowerCase();
      if (folded.has(lower) && !names.has('prefix:' + prefix)) reasons.paths.push('Case/normalization collision');
      folded.add(lower); names.add('prefix:' + prefix);
    }
    if (e.mode === '120000') {
      const target = posix.normalize(posix.join(posix.dirname(path), text));
      reasons.paths.push(text.startsWith('/') || target === '..' || target.startsWith('../') || text.includes('\\') ? 'Escaping symlink' : 'Symlink requires review');
    } else if (!['100644','100755'].includes(e.mode)) reasons.paths.push('Submodule or unsupported tree mode');
    if (inAllowed(path,spec.allowedPaths) && /[^\x20-\x7e]/.test(path)) reasons.paths.push('Non-ASCII/confusable filename in allowed paths');
    if (/(^|\/)package\.json$/.test(path)) {
      try {
        const p = JSON.parse(rawText);
        if (INSTALL_SCRIPTS.some(k=>Object.hasOwn(p.scripts ?? {},k))) reasons['install-hooks'].push('npm lifecycle hook');
      } catch { reasons['install-hooks'].push('Malformed package.json'); }
    }
    if (/(^|\/)setup\.py$/.test(path) && /cmdclass\s*=/.test(text)) reasons['install-hooks'].push('setup.py cmdclass');
    if (/(^|\/)build\.rs$/.test(path) || /(^|\/)\.husky(\/|$)/.test(path)) reasons['install-hooks'].push('Native build or husky hooks');
    if (/(^|\/)Makefile$/i.test(path) && curlPipe.test(text)) reasons['install-hooks'].push('Makefile network shell pipe');
    if (/(^|\/)(\.npmrc|\.yarnrc(?:\.yml)?|pip\.conf)$/.test(path) && /registry|index[-_]url|extra[-_]index|trusted[-_]host|npmRegistryServer|yarnPath|plugins|script-shell|ignore-scripts\s*=\s*false/i.test(text)) reasons['install-hooks'].push('Package manager registry/config override');
    if (executableBlob(e) || e.data.length > LIMITS.fileBytes || /\.(?:zip|tar|gz|xz|bz2|7z|rar|tgz|so(?:\.[\d.]+)?|dll|dylib|a|o|node|wasm)$/i.test(path) ||
      /^(?:504b0304|1f8b|377abcaf|fd377a58)/.test(e.data.subarray(0,6).toString('hex')) || e.data.subarray(0,4096).includes(0)) reasons.blobs.push('Binary, archive, native library or large blob');
    if (/^\.github\/workflows\/.*\.ya?ml$/i.test(path)) {
      // Conservative text checks are intentionally fail-closed for YAML aliases,
      // expressions and unusual syntax; this does not execute a YAML parser.
      if (/pull_request_target|self-hosted/i.test(text) || curlPipe.test(text) || /(?:^|\s)[&*][A-Za-z]|\$\{\{|!!|\\|["'](?:uses|permissions|runs-on|on)["']\s*:/.test(text)) reasons.workflows.push('Privileged trigger/runner, network shell or ambiguous workflow');
      const uses = [...text.matchAll(/\buses\s*:\s*["']?([^\s"'#]+)/g)].map(m=>m[1]);
      if (uses.some(u=>!u.startsWith('./') && !/@[0-9a-f]{40}$/i.test(u))) reasons.workflows.push(/write-all|:\s*write\b/i.test(text) ? 'Unpinned action with write permissions' : 'Unpinned action');
    }
    if (secret.test(text)) reasons.secrets.push('Potential secret (value redacted)');
    if (isInstruction(path)) {
      instructionFiles.push(path);
      if (injection.test(text)) reasons['agent-instructions'].push('Agent instruction injection');
    }
  }
  if (spec.allowedPaths.some(p=>!entries.some(e=>e.path === p || e.path.startsWith(p+'/')))) reasons['allowed-paths'].push('Allowed path missing');
  try {
    const argv = testArgv(spec.testCommand);
    const pkg = entries.find(e=>e.path === 'package.json' && e.mode !== '120000');
    const scripts = pkg ? JSON.parse(pkg.data.toString('utf8')).scripts : undefined;
    const script = argv[1] === 'test' ? 'test' : argv[2];
    if (!scripts || typeof scripts[script] !== 'string' || !scripts[script]) reasons['test-runner'].push('Declared npm script missing');
  } catch { reasons['test-runner'].push('Unsupported or malformed test runner'); }
  for (const id of TREE_CHECKS) {
    const fatal = id === 'tree-bounds' || id === 'allowed-paths' || id === 'secrets' ||
      (id === 'paths' && reasons.paths.some(r=>r !== 'Symlink requires review')) ||
      (id === 'agent-instructions' && reasons[id].length > 0);
    checks.push(check(id,reasons[id].length ? fatal ? 'reject' : 'hold' : 'pass',...new Set(reasons[id])));
  }
  return { checks, instructionFiles };
}
