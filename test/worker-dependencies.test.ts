import { expect, it, vi } from 'vitest';
import { checkOsv, newDependencies, parseLocks, parseOsv, type Dependency } from '../worker/dependencies.js';
import { entry, fixture } from './worker-fixtures.js';
const lock=()=>JSON.parse(fixture('package-lock.json').toString());
it('parses recorded npm v2/v3 lockfiles and version changes',()=>{
  for(const lockfileVersion of [2,3]) {
    const parsed=parseLocks([entry('package-lock.json',JSON.stringify({...lock(),lockfileVersion}))]);
    expect(parsed.npmSupported).toBe(true); expect(parsed.checks[0].verdict).toBe('pass');
    expect(parsed.dependencies).toEqual([{name:'example',version:'1.0.0',ecosystem:'npm'}]);
    expect(newDependencies(parsed.dependencies,[{name:'example',version:'2.0.0',ecosystem:'npm'}])).toHaveLength(1);
    expect(newDependencies(parsed.dependencies,parsed.dependencies)).toEqual([]);
  }
});
it.each(['yarn.lock','pnpm-lock.yaml','Cargo.lock','requirements.txt','poetry.lock','uv.lock','Pipfile.lock'])('holds unsupported lock %s',path=>{
  expect(parseLocks([entry(path,'recorded unsupported fixture')]).checks[0].verdict).toBe('hold');
});
it('holds missing, malformed, nested and ambiguous lockfiles',()=>{
  for(const entries of [[],[entry('package-lock.json','{')],[entry('other/package-lock.json',fixture('package-lock.json'))],
    [entry('package-lock.json',fixture('package-lock.json')),entry('yarn.lock','')]]) expect(parseLocks(entries).checks[0].verdict).toBe('hold');
});
it.each([{resolved:'https://evil.example/pkg.tgz'},{resolved:'git+https://github.com/pkg'}, {integrity:''},{link:true},{hasInstallScript:true},{version:'github:user/repo'}])('holds nonstandard sources/install metadata %j',change=>{
  const p=lock();Object.assign(p.packages['node_modules/example'],change);
  expect(parseLocks([entry('package-lock.json',JSON.stringify(p))]).checks[0].verdict).toBe('hold');
});
it('parses recorded OSV clean, advisory and pagination responses',async()=>{
  const deps=[{name:'example',version:'1.0.0',ecosystem:'npm' as const}];
  expect((await checkOsv(deps,async()=>JSON.parse(fixture('osv-clean.json').toString()))).verdict).toBe('pass');
  const vuln=await checkOsv(deps,async()=>JSON.parse(fixture('osv-vulnerable.json').toString()));
  expect(vuln.verdict).toBe('hold');expect(vuln.reasons).toContain('GHSA-vqj2-4v8m-8vrq');
  expect((await checkOsv(deps,async()=>JSON.parse(fixture('osv-paginated.json').toString()))).verdict).toBe('hold');
});
it.each([null,{}, {results:[]},{results:[{vulns:'bad'}]},{results:[{vulns:[{}]}]}])('fails closed on incomplete OSV %j',response=>expect(()=>parseOsv(response,1)).toThrow());
it('holds OSV outages and batches at 100 queries without querying empty lists',async()=>{
  const deps=Array.from({length:101},(_,i)=>({name:'pkg'+i,version:'1.0.0',ecosystem:'npm' as const}));
  const query=vi.fn(async(d:Dependency[])=>({results:d.map(()=>({}))}));
  expect((await checkOsv(deps,query)).verdict).toBe('pass');expect(query.mock.calls.map(c=>c[0].length)).toEqual([100,1]);
  expect((await checkOsv([],query)).verdict).toBe('pass');expect(query).toHaveBeenCalledTimes(2);
  expect((await checkOsv(deps,async()=>{throw Error('offline');})).verdict).toBe('hold');
});
