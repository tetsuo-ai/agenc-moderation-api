import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { githubToken } from '../worker/github.js';

const dir = mkdtempSync(join(tmpdir(),'github-token-'));
afterEach(()=>rmSync(join(dir,'token'),{force:true}));
const file = (text:string) => { writeFileSync(join(dir,'token'),text); return {GITHUB_TOKEN_FILE:join(dir,'token')}; };

it('reads a GitHub token from GITHUB_TOKEN_FILE and calls anonymously without one',()=>{
 expect(githubToken({})).toBeUndefined();
 expect(githubToken(file('github_pat_'+'A1_'.repeat(20)+'\n'))).toBe('github_pat_'+'A1_'.repeat(20));
 expect(githubToken(file('ghp_'+'a'.repeat(36)))).toBe('ghp_'+'a'.repeat(36));
});
it('refuses a file that does not hold a GitHub token',()=>{
 for(const text of ['','token','github_pat_short','ghp_'+'a'.repeat(36)+' extra','Bearer ghp_'+'a'.repeat(36)]) expect(()=>githubToken(file(text))).toThrow(/GitHub token/);
});
