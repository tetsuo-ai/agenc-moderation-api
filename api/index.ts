/**
 * Vercel function entry (@vercel/node). Every path is routed here (vercel.json);
 * the router dispatches on the real pathname. Uses the Node req/res signature
 * (via the shared node-adapter) for unambiguous @vercel/node compatibility.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { createModerationApi } from "../src/router.js";
import { nodeRequestToWeb, writeWebResponse } from "../src/node-adapter.js";

const handler = createModerationApi();

export default async function vercelHandler(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  try {
    const response = await handler(nodeRequestToWeb(req));
    await writeWebResponse(res, response);
  } catch {
    res.statusCode = 500;
    res.setHeader("content-type", "application/json; charset=utf-8");
    res.end('{"ok":false,"error":"internal error"}');
  }
}
