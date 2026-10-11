import { expect, it, vi } from 'vitest';
import { GithubClient } from '../worker/github.js';
import { FACTS, github, githubReply, LICENSE, META, SPEC, TREE } from './worker-fixtures.js';
it('reads immutable repo identity by numeric ID and records tree SHA',async()=>{
  const get=vi.fn(async(url:string)=>githubReply(url));
  const result=await new GithubClient(get).inspect(SPEC);
  expect(result.facts).toEqual(FACTS);expect(result.checks.every(c=>c.verdict==='pass')).toBe(true);
  expect(get.mock.calls[1][0]).toBe('https://api.github.com/repositories/123');
});
it.each([{private:true},{visibility:'private'},{archived:true},{disabled:true},{size:100001},{default_branch:''},
  {id:999},{owner:{login:'attacker'}},{name:'other'}])('rejects numeric metadata %j',change=>{
  return github(url=>url.includes('/repositories/') ? {...META,...change}:undefined).inspect(SPEC).then(r=>expect(r.checks.some(c=>c.verdict==='reject')).toBe(true));
});
it.each([{license:{spdx_id:'GPL-3.0'}},{license:{spdx_id:'NOASSERTION'}}, {content:Buffer.from('SPDX-License-Identifier: MIT').toString('base64')},
  {path:'src/license'},{encoding:'raw'}])('rejects API/file license mismatches %j',change=>{
  return github(url=>url.includes('/license?') ? {...githubReply(url) as object,...change}:undefined).inspect(SPEC).then(r=>expect(r.checks.find(c=>c.id==='github-license')!.verdict).toBe('reject'));
});
it('rejects a declared SPDX mismatch even when API and file agree',async()=>expect((await github().inspect({...SPEC,license:'ISC'})).checks.find(c=>c.id==='github-license')!.verdict).toBe('reject'));
it.each(['behind','diverged'])('rejects base not ancestral to default branch (%s)',async status=>{
  expect((await github(url=>url.includes('/compare/') ? {status,merge_base_commit:{sha:SPEC.baseCommit}}:undefined).inspect(SPEC)).checks.find(c=>c.id==='github-commit')!.verdict).toBe('reject');
});
it('holds missing commits, outages, malformed trees and repository identity races',async()=>{
  for(const client of [new GithubClient(async()=>{throw Error('offline');}),
    github(url=>url.includes('/git/commits/') ? {sha:'0'.repeat(40),tree:{sha:TREE}}:undefined),
    github(url=>url.endsWith('/public-repo') ? {...META,id:999}:undefined)]) {
    const r=await client.inspect(SPEC,123);expect(r.facts).toBeNull();expect(r.checks.some(c=>c.verdict==='hold')).toBe(true);
  }
});
