import { readFileSync } from 'node:fs';
import { GithubClient } from '../worker/github.js';
import { hash, type GithubSpec, type Job, type RepoFacts, type TreeEntry } from '../worker/types.js';
export const BASE = 'a'.repeat(40), TREE = 'b'.repeat(40), HEAD = 'c'.repeat(40), RESULT_TREE = 'd'.repeat(40), DIGEST = 'sha256:'+'e'.repeat(64);
export const TASK = '1'.repeat(32), SUBMISSION = '2'.repeat(32);
export const fixture = (name:string) => readFileSync(new URL('./worker-fixtures/'+name,import.meta.url));
export const LICENSE = fixture('license.txt');
export const SPEC:GithubSpec = {owner:'example',repo:'public-repo',license:'MIT',baseCommit:BASE,
  workType:'bugfix',allowedPaths:['src'],maxDiffBytes:100_000,testCommand:'npm test',needsNetworkForInstall:true};
export const JOB:Job = {kind:'repo-intake',taskPda:TASK,jobSpecHash:'0'.repeat(64),github:SPEC};
export const FACTS:RepoFacts = {id:123,owner:SPEC.owner,name:SPEC.repo,licenseSpdx:'MIT',baseCommit:BASE,
  treeSha:TREE,defaultBranch:'main',licenseFileSha256:hash(LICENSE)};
export function entry(path:string,data:string|Buffer,mode='100644'):TreeEntry { return {path,mode,data:Buffer.from(data)}; }
export function cleanTree():TreeEntry[] { return [entry('LICENSE',LICENSE),entry('src/main.ts','export const answer = 1;\n'),
  entry('package.json',JSON.stringify({scripts:{test:'node --test'}})),entry('package-lock.json',fixture('package-lock.json'))]; }
export const PATCH = Buffer.from('diff --git a/src/main.ts b/src/main.ts\nindex 1234567..7654321 100644\n--- a/src/main.ts\n+++ b/src/main.ts\n@@ -1 +1 @@\n-export const answer = 1;\n+export const answer = 2;\n');
export const MANIFEST = {repo:{id:123,owner:SPEC.owner,name:SPEC.repo},baseCommit:BASE,headCommit:HEAD,patchSha256:hash(PATCH)};
export const ARTIFACT_BYTES = Buffer.from(JSON.stringify({manifest:MANIFEST,patchBase64:PATCH.toString('base64')}));
export const META = {id:123,owner:{login:SPEC.owner},name:SPEC.repo,private:false,visibility:'public',archived:false,disabled:false,size:100,default_branch:'main'};
export function githubReply(uri:string):unknown {
  if (uri.includes('/license?')) return {license:{spdx_id:'MIT'},encoding:'base64',path:'LICENSE',content:LICENSE.toString('base64')};
  if (uri.includes('/git/commits/')) return {sha:uri.split('/').at(-1),tree:{sha:uri.endsWith(HEAD) ? RESULT_TREE:TREE}};
  if (uri.includes('/branches/')) return {commit:{sha:HEAD}};
  if (uri.includes('/compare/')) return {status:'ahead',merge_base_commit:{sha:BASE}};
  return META;
}
export function github(override?:(url:string)=>unknown):GithubClient {
  return new GithubClient(async url=>override?.(url) ?? githubReply(url));
}
