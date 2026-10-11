import { lookup } from 'node:dns/promises';
import { request } from 'node:https';
import { isPublicAddress } from '../src/ssrf-fetch.js';

export type JsonRequest = (url: string, body?: unknown) => Promise<unknown>;
/** Read-only queries only; fixed host allowlist, vetted/pinned DNS, no redirects,
 * no ambient credentials, total deadline and bounded streaming response. */
export function jsonTransport(hosts: string[], maxBytes = 4 * 1024 * 1024): JsonRequest {
  return async (uri, body) => {
    const url = new URL(uri);
    if (url.protocol !== 'https:' || url.port && url.port !== '443' || url.username || url.password ||
        !hosts.includes(url.hostname) || url.hash || (body !== undefined && uri !== 'https://api.osv.dev/v1/querybatch')) throw new Error('Disallowed query');
    const addresses = await lookup(url.hostname,{all:true});
    if (!addresses.length || addresses.some(a=>!isPublicAddress(a.address,a.family))) throw new Error('Nonpublic DNS');
    const pinned = addresses[0];
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    if (payload && payload.length > 256*1024) throw new Error('Query size');
    return new Promise((resolve,reject)=>{
      let settled = false, bytes = 0;
      const chunks: Buffer[] = [];
      const finish = (error?: Error, value?: unknown) => {
        if (settled) return;
        settled = true; clearTimeout(timer);
        if (error) reject(error); else resolve(value);
      };
      const req = request(url,{method:payload ? 'POST':'GET',
        lookup: (_host, options, callback) => {
          if (options && (options as {all?:boolean}).all) {
            (callback as unknown as (error:null, records: Array<{address:string;family:number}>)=>void)(null,[pinned]);
          } else callback(null,pinned.address,pinned.family);
        }, headers:{accept:'application/vnd.github+json','user-agent':'agenc-repo-worker/1',
          ...(payload ? {'content-type':'application/json','content-length':String(payload.length)} : {})}},res=>{
        if (res.statusCode !== 200 || Number(res.headers['content-length'] ?? 0) > maxBytes) {
          res.destroy(); finish(new Error('Query status/size')); return;
        }
        res.on('data',(chunk:Buffer)=>{
          bytes += chunk.length;
          if (bytes > maxBytes) { res.destroy(); req.destroy(); finish(new Error('Query size')); }
          else chunks.push(chunk);
        });
        res.on('end',()=>{
          try { finish(undefined,JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
          catch { finish(new Error('Invalid query JSON')); }
        });
        res.on('error',()=>finish(new Error('Query response failed')));
      });
      const timer = setTimeout(()=>{req.destroy();finish(new Error('Query timeout'));},10_000);
      req.on('error',()=>finish(new Error('Query failed')));
      req.end(payload);
    });
  };
}
