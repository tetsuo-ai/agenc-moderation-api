import { EventEmitter } from 'node:events';
import { afterEach, expect, it, vi } from 'vitest';
const state=vi.hoisted(()=>({addresses:[{address:'8.8.8.8',family:4}],status:200,chunks:['{"ok":true}'],stall:false,lookupOptions:undefined as unknown}));
vi.mock('node:dns/promises',()=>({lookup:vi.fn(async()=>state.addresses)}));
vi.mock('node:https',()=>({request:vi.fn((_url,options,callback)=>{
  state.lookupOptions=options;
  const req=new EventEmitter() as EventEmitter & {destroy:()=>void;end:()=>void};
  req.destroy=()=>{};
  req.end=()=>{
    if(state.stall)return;
    queueMicrotask(()=>{
      const res=new EventEmitter() as EventEmitter & {statusCode:number;headers:object;destroy:()=>void};
      res.statusCode=state.status;res.headers={};res.destroy=()=>{};callback(res);
      for(const chunk of state.chunks)res.emit('data',Buffer.from(chunk));res.emit('end');
    });
  };
  return req;
})}));
import { jsonTransport } from '../worker/http.js';
afterEach(()=>{state.addresses=[{address:'8.8.8.8',family:4}];state.status=200;state.chunks=['{"ok":true}'];state.stall=false;vi.useRealTimers();});
it('uses pinned DNS with no credentials and only read-only OSV POST queries',async()=>{
  const get=jsonTransport(['api.github.com','api.osv.dev']);
  expect(await get('https://api.github.com/repositories/123')).toEqual({ok:true});
  const options=state.lookupOptions as {method:string;headers:Record<string,string>;lookup:Function};
  expect(options.method).toBe('GET');expect(options.headers.authorization).toBeUndefined();
  const callback=vi.fn();options.lookup('api.github.com',{},callback);expect(callback).toHaveBeenCalledWith(null,'8.8.8.8',4);
  options.lookup('api.github.com',{all:true},callback);expect(callback).toHaveBeenLastCalledWith(null,state.addresses);
  await get('https://api.osv.dev/v1/querybatch',{queries:[]});expect((state.lookupOptions as {method:string}).method).toBe('POST');
  await expect(get('https://api.github.com/repos/example/repo',{write:true})).rejects.toThrow();
});
it.each(['http://api.github.com/repositories/1','https://evil.example/data','https://user:password@api.github.com/data',
  'https://api.github.com:8443/data','https://api.github.com/data#fragment'])('rejects URI %s without a connection',async uri=>{
  await expect(jsonTransport(['api.github.com'])(uri)).rejects.toThrow();
});
it('rejects private/mixed DNS results, redirects, large bodies and malformed JSON',async()=>{
  const get=jsonTransport(['api.github.com'],20);
  state.addresses=[{address:'8.8.8.8',family:4},{address:'169.254.169.254',family:4}];
  await expect(get('https://api.github.com/data')).rejects.toThrow(/Nonpublic/);
  state.addresses=[{address:'8.8.8.8',family:4}];state.status=302;
  await expect(get('https://api.github.com/data')).rejects.toThrow(/status/);
  state.status=200;state.chunks=['a'.repeat(21)];await expect(get('https://api.github.com/data')).rejects.toThrow(/size/);
  state.chunks=['{bad'];await expect(get('https://api.github.com/data')).rejects.toThrow(/JSON/);
});
it('enforces a total response deadline',async()=>{
  vi.useFakeTimers();state.stall=true;
  const response=jsonTransport(['api.github.com'])('https://api.github.com/data');
  const assertion=expect(response).rejects.toThrow(/timeout/);
  await vi.advanceTimersByTimeAsync(10_001);await assertion;
});
