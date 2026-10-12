import { expect, it } from 'vitest';
import { parseArtifact, scanPatch } from '../worker/artifact.js';
import { hash } from '../worker/types.js';
import { ARTIFACT_BYTES, FACTS, MANIFEST, PATCH, SPEC } from './worker-fixtures.js';
const scan=(patch:Buffer,manifest={...MANIFEST,patchSha256:hash(patch)},spec=SPEC)=>scanPatch({manifest,patch},spec,FACTS);
it('verifies exact artifact bytes and patch digest',()=>{
  expect(parseArtifact(ARTIFACT_BYTES,hash(ARTIFACT_BYTES))).toEqual({manifest:MANIFEST,patch:PATCH});
  expect(()=>parseArtifact(ARTIFACT_BYTES,'0'.repeat(64))).toThrow();
  const corrupt=Buffer.from(JSON.stringify({manifest:MANIFEST,patchBase64:Buffer.from('bad').toString('base64')}));
  expect(()=>parseArtifact(corrupt,hash(corrupt))).toThrow();
  const invalid=Buffer.from(JSON.stringify({manifest:MANIFEST,patchBase64:'@!'}));
  expect(()=>parseArtifact(invalid,hash(invalid))).toThrow();
});
it('passes allowed text patches and rejects base/repo manifest substitution',()=>{
  expect(scan(PATCH).checks.every(c=>c.verdict==='pass')).toBe(true);
  for(const manifest of [{...MANIFEST,baseCommit:'0'.repeat(40)}, {...MANIFEST,repo:{...MANIFEST.repo,id:999}},
    {...MANIFEST,repo:{...MANIFEST.repo,owner:'attacker'}}]) expect(scan(PATCH,manifest).checks.find(c=>c.id==='manifest')!.verdict).toBe('reject');
});
it('enforces patch byte limit at the exact boundary',()=>{
  expect(scan(PATCH,MANIFEST,{...SPEC,maxDiffBytes:PATCH.length}).checks.find(c=>c.id==='diff-size')!.verdict).toBe('pass');
  expect(scan(PATCH,MANIFEST,{...SPEC,maxDiffBytes:PATCH.length-1}).checks.find(c=>c.id==='diff-size')!.verdict).toBe('reject');
});
it.each(['outside/file.ts','src/../escape','/tmp/escape','src/.git/config','src\\escape'])('rejects touched path %s',path=>{
  const patch=Buffer.from(PATCH.toString().replaceAll('src/main.ts',path));
  expect(scan(patch).checks.find(c=>c.id==='diff-paths')!.verdict).toBe('reject');
});
it.each(['GIT binary patch','Binary files a/src/main.ts and b/src/main.ts differ','new file mode 120000','old mode 120000','new file mode 160000'])('rejects binary/symlink/submodule %s',line=>{
  const patch=Buffer.from(PATCH.toString().replace('index 1234567..7654321 100644',line));
  expect(scan(patch).checks.find(c=>c.id==='diff-binary')!.verdict).toBe('reject');
});
it.each(['AGENTS.md','CLAUDE.md','.cursorrules','.claude/settings.json','.github/workflows/ci.yml','.gitconfig','.gitattributes','.gitmodules','.npmrc','build.rs','setup.py','.husky/pre-commit'])('holds sensitive change %s',path=>{
  const patch=Buffer.from(PATCH.toString().replaceAll('src/main.ts',path));
  expect(scan(patch,undefined,{...SPEC,allowedPaths:[path]}).checks.find(c=>c.id==='diff-sensitive')!.verdict).toBe('hold');
});
it('holds changed lifecycle scripts and lock registry URLs',()=>{
  for(const [path,line] of [['package.json','+"postinstall": "node payload"'],['package-lock.json','+"resolved":"https://evil.example"']]) {
    const patch=Buffer.from(PATCH.toString().replaceAll('src/main.ts',path).replace('+export const answer = 2;',line));
    expect(scan(patch,undefined,{...SPEC,allowedPaths:[path]}).checks.find(c=>c.id==='diff-sensitive')!.verdict).toBe('hold');
  }
});
it('rejects secrets, malformed patch framing, quoted paths and rename/copy tricks',()=>{
  const secret=Buffer.from(PATCH.toString().replace('+export const answer = 2;','+const token="'+'A'.repeat(40)+'";'));
  expect(scan(secret).checks.find(c=>c.id==='diff-secrets')!.verdict).toBe('reject');
  for(const patch of [Buffer.from('not a patch'),Buffer.from(PATCH.toString()+'\nrename from outside\nrename to src/main.ts\n'),
    Buffer.from(PATCH.toString().replace('diff --git a/src/main.ts b/src/main.ts','diff --git "a/src/main.ts" "b/src/main.ts"'))])
    expect(scan(patch).checks.find(c=>c.id==='diff-paths')!.verdict).toBe('reject');
});
