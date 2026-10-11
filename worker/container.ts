import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { check, hash, inAllowed, LIMITS, safePath, validateJob, type Artifact, type Check, type GithubSpec, type TreeEntry } from './types.js';
import { testArgv } from './tree.js';

export interface CommandResult { code: number; stdout: Buffer; stderr: Buffer; timedOut: boolean }
export type Executor = (binary: string, args: string[], stdin?: Buffer, timeoutMs?: number) => Promise<CommandResult>;
/** No shell, no host environment, bounded output and wall clock. */
export const execute: Executor = (binary,args,stdin,timeoutMs = LIMITS.phaseMs) => new Promise((resolve,reject)=>{
  const child = spawn(binary,args,{stdio:['pipe','pipe','pipe'],env:{PATH:'/usr/bin:/bin',HOME:'/var/lib/agenc-worker',
    XDG_RUNTIME_DIR:`/run/user/${process.getuid?.() ?? 65534}`}});
  let outBytes = 0, errBytes = 0, timedOut = false;
  const out: Buffer[] = [], err: Buffer[] = [];
  const cap = LIMITS.treeBytes*2;
  const timer = setTimeout(()=>{timedOut=true;child.kill('SIGKILL');},timeoutMs);
  child.stdout.on('data',(b:Buffer)=>{outBytes+=b.length;if(outBytes > cap) {timedOut=true;child.kill('SIGKILL');} else out.push(b);});
  child.stderr.on('data',(b:Buffer)=>{errBytes+=b.length;if(errBytes > 1024*1024) {timedOut=true;child.kill('SIGKILL');} else err.push(b);});
  child.on('error',e=>{clearTimeout(timer);reject(e);});
  child.on('close',code=>{clearTimeout(timer);resolve({code:code ?? -1,stdout:Buffer.concat(out),stderr:Buffer.concat(err),timedOut});});
  child.stdin.on('error',()=>{}); child.stdin.end(stdin);
});
export interface ContainerConfig { cli: 'podman'|'docker'; image: string; restrictedNetwork: string }
export function containerArgv(config: ContainerConfig, name: string, network = 'none'): string[] {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9./:_-]*@sha256:[0-9a-f]{64}$/.test(config.image) ||
      !['podman','docker'].includes(config.cli) || !/^[a-zA-Z0-9_-]{1,64}$/.test(config.restrictedNetwork) || ['host','bridge','default','none'].includes(config.restrictedNetwork) ||
      ![config.restrictedNetwork,'none'].includes(network) ||
      !/^agenc-scan-[0-9a-f]{32}$/.test(name)) throw new Error('Invalid sandbox configuration');
  return ['create','--name',name,'--pull','never','--network',network,'--read-only',
    '--tmpfs',`/work:rw,nosuid,nodev,size=${LIMITS.tmpfsBytes},uid=65534,gid=65534,mode=0700`,
    '--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777',
    '--cap-drop','ALL','--security-opt','no-new-privileges','--user','65534:65534',
    '--pids-limit',String(LIMITS.pids),'--memory',String(LIMITS.memoryBytes),'--memory-swap',String(LIMITS.memoryBytes),
    '--cpus',String(LIMITS.cpus),'--ulimit','nofile=1024:1024','--workdir','/work',
    '--env','HOME=/work','--env','GIT_CONFIG_NOSYSTEM=1','--env','GIT_CONFIG_GLOBAL=/dev/null',
    '--env','GIT_TERMINAL_PROMPT=0','--env','GIT_LFS_SKIP_SMUDGE=1',
    '--env','npm_config_cache=/work/npm-cache','--entrypoint','node',config.image,
    '-e','setInterval(()=>{},1000)'];
}
const GIT_FLAGS = ['-c','core.hooksPath=/dev/null','-c','protocol.file.allow=never','-c','protocol.ext.allow=never',
  '-c','submodule.recurse=false','-c','filter.lfs.required=false','-c','filter.lfs.smudge=',
  '-c','filter.lfs.process=','-c','http.followRedirects=false'];
const SNAPSHOT = `const fs=require('node:fs'),cp=require('node:child_process');
const git=a=>cp.execFileSync('git',${JSON.stringify(GIT_FLAGS)}.concat(a),{maxBuffer:${LIMITS.treeBytes},cwd:'/work/repo'});
const index=git(['ls-files','--stage','-z']).toString('utf8').split('\\0').filter(Boolean);
if(index.length>${LIMITS.entries})throw Error('entry quota');let total=0;
const entries=index.map(row=>{const m=/^(\\d+) ([0-9a-f]{40}) 0\\t([\\s\\S]+)$/.exec(row);if(!m)throw Error('index');
const size=Number(git(['cat-file','-s',m[2]]).toString());total+=size;
if(size>${LIMITS.fileBytes}||total>${LIMITS.treeBytes})throw Error('blob quota');
return {path:m[3],mode:m[1],data:git(['cat-file','blob',m[2]]).toString('base64')};});
process.stdout.write(JSON.stringify({treeSha:git(['write-tree']).toString().trim(),entries}));`;
export interface Snapshot { treeSha:string; entries:TreeEntry[] }
export interface TestResult { exitCode:number|null; timedOut:boolean; outputSha256:string }
export interface Sandbox {
  clone(spec:GithubSpec):Promise<Snapshot>;
  apply(artifact:Artifact,spec:GithubSpec):Promise<{checks:Check[];snapshot:Snapshot|null}>;
  test(spec:GithubSpec):Promise<TestResult>;
  close():Promise<void>;
}
export class ContainerSandbox implements Sandbox {
  private id: string | null = null;
  private offline = false;
  private readonly name = 'agenc-scan-'+randomBytes(16).toString('hex');
  private readonly deadline = Date.now()+LIMITS.jobMs;
  constructor(private readonly config:ContainerConfig, private readonly run:Executor = execute) { containerArgv(config,this.name); }
  get imageDigest():string { return this.config.image.split('@')[1]; }
  private async command(args:string[],stdin?:Buffer):Promise<CommandResult> {
    const remaining = this.deadline-Date.now();
    if (remaining <= 0) throw new Error('Sandbox job deadline');
    const r = await this.run(`/usr/bin/${this.config.cli}`,args,stdin,Math.min(LIMITS.phaseMs,remaining));
    return r;
  }
  private async checked(args:string[],stdin?:Buffer):Promise<CommandResult> {
    const r = await this.command(args,stdin);
    if (r.code !== 0 || r.timedOut) throw new Error('Sandbox phase failed');
    return r;
  }
  private async exec(args:string[],stdin?:Buffer) {
    if (!this.id) throw new Error('Sandbox unavailable');
    return this.checked(['exec','--interactive','--workdir','/work/repo',this.id,...args],stdin);
  }
  private async disconnect() {
    if (!this.id) throw new Error('Sandbox unavailable');
    await this.checked(['network','disconnect',this.config.restrictedNetwork,this.id]);
    const state = await this.checked(['inspect','--format','{{json .NetworkSettings.Networks}}',this.id]);
    const networks = JSON.parse(state.stdout.toString('utf8'));
    if (!networks || Object.keys(networks).length !== 0) throw new Error('Network still connected');
    this.offline = true;
  }
  private async snapshot():Promise<Snapshot> {
    const r = await this.exec(['node','-e',SNAPSHOT]);
    const obj = JSON.parse(r.stdout.toString('utf8')) as {treeSha:string;entries:Array<{path:string;mode:string;data:string}>};
    if (!/^[0-9a-f]{40}$/.test(obj.treeSha) || !Array.isArray(obj.entries) || obj.entries.length > LIMITS.entries) throw new Error('Incomplete tree');
    const entries = obj.entries.map(e=>({...e,data:Buffer.from(e.data,'base64')}));
    if (entries.reduce((n,e)=>n+e.data.length,0)>LIMITS.treeBytes) throw new Error('Tree quota');
    return {treeSha:obj.treeSha,entries};
  }
  async clone(spec:GithubSpec):Promise<Snapshot> {
    // Validate even direct callers of the exported adapter.
    validateJob({kind:'repo-intake',taskPda:'1'.repeat(32),jobSpecHash:'0'.repeat(64),github:spec});
    const info = await this.checked(['info','--format',this.config.cli === 'podman' ? '{{.Host.Security.Rootless}}':'{{json .SecurityOptions}}']);
    if (this.config.cli === 'podman' ? info.stdout.toString().trim() !== 'true' :
        !JSON.parse(info.stdout.toString()).some((s:string)=>s === 'name=rootless')) throw new Error('Rootless engine required');
    const created = await this.checked(containerArgv(this.config,this.name,this.config.restrictedNetwork));
    const id = created.stdout.toString().trim();
    if (!/^[0-9a-f]{12,64}$/.test(id)) throw new Error('Invalid container id');
    this.id = id;
    await this.checked(['start',id]);
    const init = `const cp=require('node:child_process'),fs=require('node:fs');fs.mkdirSync('/work/repo');
      const run=a=>cp.execFileSync('git',${JSON.stringify(GIT_FLAGS)}.concat(a),{cwd:'/work/repo',stdio:'pipe',timeout:${LIMITS.phaseMs}});
      run(['init']);run(['config','core.hooksPath','/dev/null']);
      run(['remote','add','origin',${JSON.stringify(`https://github.com/${spec.owner}/${spec.repo}.git`)}]);
      run(['fetch','--depth','1','--no-tags','--no-recurse-submodules','origin',${JSON.stringify(spec.baseCommit)}]);
      if(run(['rev-parse','FETCH_HEAD']).toString().trim()!==${JSON.stringify(spec.baseCommit)})throw Error('Wrong commit');`;
    await this.exec(['node','-e',init]);
    await this.disconnect();
    // No checkout or hooks while networking is attached. Index reads never
    // recurse into submodules and cannot invoke repository filters.
    await this.exec(['git',...GIT_FLAGS,'read-tree',spec.baseCommit]);
    return this.snapshot();
  }
  async apply(artifact:Artifact,spec:GithubSpec):Promise<{checks:Check[];snapshot:Snapshot|null}> {
    if (!this.offline) throw new Error('Apply must be offline');
    try {
      await this.exec(['git',...GIT_FLAGS,'checkout','--detach',spec.baseCommit]);
      await this.exec(['git',...GIT_FLAGS,'apply','--check','--index','--whitespace=error-all','-'],artifact.patch);
      await this.exec(['git',...GIT_FLAGS,'apply','--index','--whitespace=error-all','-'],artifact.patch);
      const delta = await this.exec(['git',...GIT_FLAGS,'diff','--cached','--no-renames','--numstat','-z',spec.baseCommit]);
      const paths = delta.stdout.toString('utf8').split('\0').filter(Boolean).map(row=>{
        const m=/^(\d+)\t(\d+)\t([\s\S]+)$/.exec(row);if(!m)throw new Error('Binary or unsupported delta');return m[3];
      });
      if (!paths.length || paths.some(p=>!safePath(p)||!inAllowed(p,spec.allowedPaths))) throw new Error('Actual delta escapes allowedPaths');
      const snapshot = await this.snapshot();
      if (snapshot.entries.some(e=>!['100644','100755'].includes(e.mode))) throw new Error('Symlink/submodule');
      // Verify the claimed head against GitHub's immutable Git commit object
      // outside the sandbox (consumer); this tree is the exact staged result.
      return {checks:[check('patch-apply','pass')],snapshot};
    } catch { return {checks:[check('patch-apply','reject','Patch fails clean apply or actual delta rules')],snapshot:null}; }
  }
  async test(spec:GithubSpec):Promise<TestResult> {
    if (!this.offline || !this.id) throw new Error('Test must start offline');
    // We support only reviewed npm lockfiles. Ignore both project and dependency
    // lifecycle scripts. Never execute tests when a security check held/rejected.
    if (spec.needsNetworkForInstall) {
      await this.checked(['network','connect',this.config.restrictedNetwork,this.id]);
      this.offline = false;
    }
    try {
      await this.exec(['npm','ci','--ignore-scripts','--no-audit','--no-fund',
        '--registry=https://registry.npmjs.org',...(spec.needsNetworkForInstall ? []:['--offline'])]);
    } finally { if (!this.offline) await this.disconnect(); }
    const r = await this.command(['exec','--interactive','--workdir','/work/repo',
      '--env','npm_config_offline=true','--env','npm_config_ignore_scripts=true',this.id,...testArgv(spec.testCommand)]);
    return {exitCode:r.code,timedOut:r.timedOut,outputSha256:hash(Buffer.concat([r.stdout,r.stderr]))};
  }
  async close():Promise<void> {
    // A separate bounded cleanup deadline still runs if the job timed out.
    if (this.id) {
      const id = this.id;
      const r = await this.run(`/usr/bin/${this.config.cli}`,['rm','--force',id],undefined,10_000);
      if (r.code !== 0 || r.timedOut) throw new Error('Sandbox cleanup failed');
      this.id = null;
    }
  }
}
