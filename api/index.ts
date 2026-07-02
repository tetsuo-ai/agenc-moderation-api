/**
 * Vercel entrypoint. Every path is rewritten here (vercel.json); the router
 * dispatches on the real pathname. Uses the Web-standard handler signature
 * supported by Vercel's Node.js runtime.
 */
import { createModerationApi } from "../src/router.js";

const handler = createModerationApi();

export default function vercelHandler(request: Request): Promise<Response> {
  return handler(request);
}
