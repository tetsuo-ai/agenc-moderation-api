import { expect, it, vi } from 'vitest';
import { ContainerSandbox, containerArgv, type CommandResult, type Executor } from '../worker/container.js';
import { DIGEST, MANIFEST, PATCH, RESULT_TREE, SPEC, TREE, cleanTree } from './worker-fixtures.js';
const CONFIG={cli:'podman' as const,image:'ghcr.io/example/scanner@'+DIGEST,restrictedNetwork:'agenc-fetch'};
const NAME='agenc-scan-'+'0'.repeat(32), ID='f'.repeat(64);
function mockExecutor(options:{rootless?:boolean;networks?:unknown;applyFail?:boolean;timeoutTest?:boolean;binaryDelta?:boolean;escapeDelta?:boolean}={}) {
  let applied=false;
  const run=vi.fn<Executor>(async(_binary,args)=>{
    const r:CommandResult={code:0,stdout:Buffer.alloc(0),stderr:Buffer.alloc(0),timedOut:false};
    if(args[0]==='info')r.stdout=Buffer.from(options.rootless===false?'false':'true');
    if(args[0]==='create')r.stdout=Buffer.from(ID);
    if(args[0]==='inspect')r.stdout=Buffer.from(JSON.stringify(options.networks??{}));
    if(args[0]==='exec'&&args.includes('git')&&args.includes('apply')) {
      if(options.applyFail)r.code=1; else if(!args.includes('--check'))applied=true;
    }
    if(args.includes('--numstat'))r.stdout=Buffer.from(options.binaryDelta?'-\t-\tsrc/main.ts\0':options.escapeDelta?'1\t1\tescape/file\0':'1\t1\tsrc/main.ts\0');
    if(args[0]==='exec'&&args.some(a=>a.includes("const index=git(['ls-files'")))r.stdout=Buffer.from(JSON.stringify({treeSha:applied?RESULT_TREE:TREE,
      entries:cleanTree().map(e=>({...e,data:e.data.toString('base64')}))}));
    if(args.at(-1)==='test'){r.timedOut=options.timeoutTest??false;r.code=r.timedOut?-1:0;r.stdout=Buffer.from('test output');}
    return r;
  });
  return run;
}
it('hardens argv with pinned image, rootless user, quotas and no mounts/host env/socket',()=>{
  const args=containerArgv(CONFIG,NAME);
  for(const flag of ['--network','--read-only','--tmpfs','--cap-drop','--security-opt','--user','--pids-limit','--memory','--memory-swap','--cpus','--pull'])expect(args).toContain(flag);
  expect(args[args.indexOf('--network')+1]).toBe('none');expect(args).toContain('no-new-privileges');expect(args).toContain('ALL');expect(args).toContain('65534:65534');
  expect(args).not.toContain('--privileged');expect(args.join(' ')).not.toMatch(/docker\.sock|--mount|--volume|\/Users\/|\/home\//);
  expect(args).toContain(CONFIG.image);
});
it.each([{image:'node:latest'},{restrictedNetwork:'host'},{restrictedNetwork:'bridge'},{restrictedNetwork:'none'},{image:'--privileged@'+DIGEST}])('rejects sandbox config %j',change=>{
  expect(()=>containerArgv({...CONFIG,...change},NAME)).toThrow();
});
it('clones/fetches exact SHA with no hooks/submodules/LFS then disconnects before checkout/test',async()=>{
  const run=mockExecutor(),sandbox=new ContainerSandbox(CONFIG,run);
  expect((await sandbox.clone(SPEC)).treeSha).toBe(TREE);
  expect((await sandbox.apply({manifest:MANIFEST,patch:PATCH},SPEC)).snapshot!.treeSha).toBe(RESULT_TREE);
  expect((await sandbox.test(SPEC)).exitCode).toBe(0);await sandbox.close();
  const calls=run.mock.calls.map(c=>c[1]);
  const init=calls.find(a=>a.some(s=>s.includes("run(['fetch'")))!.join(' ');
  for(const s of ['--depth','--no-recurse-submodules','core.hooksPath','/dev/null','GIT_LFS_SKIP_SMUDGE'])expect(calls.flat().join(' ')).toContain(s);
  expect(init).toContain(SPEC.baseCommit);expect(init).toContain('protocol.file.allow=never');
  const initCall=calls.find(a=>a.some(s=>s.includes("run(['fetch'")))!;
  expect(initCall[initCall.indexOf('--workdir')+1]).toBe('/work');
  expect(calls.find(a=>a.includes('checkout'))).toEqual(expect.arrayContaining(['-f','--detach',SPEC.baseCommit]));
  const npm=calls.find(a=>a.includes('ci'))!;expect(npm).toContain('--ignore-scripts');expect(npm).toContain('--registry=https://registry.npmjs.org');
  const test=calls.findIndex(a=>a.at(-1)==='test');
  expect(calls[test-2].slice(0,2)).toEqual(['network','disconnect']);expect(calls[test-1][0]).toBe('inspect');
  expect(calls.at(-1)).toEqual(['rm','--force',ID]);
  expect(run.mock.calls.every(c=>c[0]==='/usr/bin/podman')).toBe(true);
});
it('keeps offline dependency installs offline and reports test timeout',async()=>{
  const run=mockExecutor({timeoutTest:true}),sandbox=new ContainerSandbox(CONFIG,run);
  await sandbox.clone(SPEC);await sandbox.apply({manifest:MANIFEST,patch:PATCH},SPEC);
  expect((await sandbox.test({...SPEC,needsNetworkForInstall:false})).timedOut).toBe(true);await sandbox.close();
  expect(run.mock.calls.some(c=>c[1].includes('--offline'))).toBe(true);expect(run.mock.calls.some(c=>c[1].slice(0,2).join(' ')==='network connect')).toBe(false);
});
it.each([{applyFail:true},{binaryDelta:true},{escapeDelta:true}])('rejects actual apply/delta %j',async options=>{
  const sandbox=new ContainerSandbox(CONFIG,mockExecutor(options));await sandbox.clone(SPEC);
  expect((await sandbox.apply({manifest:MANIFEST,patch:PATCH},SPEC)).checks[0].verdict).toBe('reject');await sandbox.close();
});
it('refuses rootful engines and network-disconnect failures',async()=>{
  await expect(new ContainerSandbox(CONFIG,mockExecutor({rootless:false})).clone(SPEC)).rejects.toThrow(/Rootless/);
  const sandbox=new ContainerSandbox(CONFIG,mockExecutor({networks:{'agenc-fetch':{}}}));
  await expect(sandbox.clone(SPEC)).rejects.toThrow(/Network/);await sandbox.close();
});
