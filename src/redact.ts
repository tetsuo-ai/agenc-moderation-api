/**
 * Keeps credentials out of anything this service prints or sends back.
 *
 * The RPC URL may carry a provider key in its query string (for example
 * `?api-key=...`), and some transport errors echo the URL they failed on.
 * Every error message that reaches a caller, and every startup log line that
 * names a URL, goes through these helpers first.
 */

const KEYED_QUERY = /([?&](?:api[-_]?key|apikey|key|token|access[-_]?token|auth|secret)=)[^&\s"'<>]+/gi;
const URL_USERINFO = /(\b[a-z][a-z0-9+.-]*:\/\/)[^\s/@"'<>]+@/gi;

/** The text with key-like query values and URL user:password parts replaced by `<redacted>`. */
export function redactSecrets(text: string): string {
  return text.replace(KEYED_QUERY, "$1<redacted>").replace(URL_USERINFO, "$1<redacted>@");
}

/** Only the scheme, host and port of a URL, for logs. */
export function urlOrigin(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return "<invalid url>";
  }
}
