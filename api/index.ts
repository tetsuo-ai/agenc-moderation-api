/** Legacy serverless entry disabled: phase 1 requires durable droplet storage. */
import type { IncomingMessage, ServerResponse } from 'node:http';
export default async function legacyHandler(_req: IncomingMessage, res: ServerResponse): Promise<void> {
  res.statusCode = 410;
  res.setHeader('content-type','application/json; charset=utf-8');
  res.end(JSON.stringify({ok:false,moderator:null,error:'Service unavailable on this entry point.'}));
}
