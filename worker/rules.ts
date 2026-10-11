import { readFileSync, readdirSync } from 'node:fs';
import { canonicalJson } from '../src/verdict.js';
import { IMAGE, LIMITS, LICENSES, hash, type TreeEntry } from './types.js';

// Commit to executable rules, parsers, transport, sandbox and signer rechecks,
// not a version label. Ship these source files with the compiled release.
export const RULE_FILES = ['worker/types.ts','worker/protocol.ts','worker/rules.ts','worker/tree.ts',
  'worker/dependencies.ts','worker/github.ts','worker/http.ts','worker/artifact.ts',
  'worker/container.ts','worker/consumer.ts','worker/bin.ts','src/repo-review.ts','src/verdict.ts',
  'src/base58.ts','src/ssrf-fetch.ts','src/json-depth.ts','src/policy.ts','src/scan.ts','package-lock.json',
  'tsup.config.ts','tsconfig.json'];
export function scannerHash(imageDigest: string, root = new URL('../', import.meta.url)): string {
  if (!IMAGE.test(imageDigest)) throw new Error('Pinned image digest required');
  const files = RULE_FILES.map(path => ({ path, sha256: hash(readFileSync(new URL(path, root))) }));
  // Built releases additionally commit to the exact executable JS chunks.
  // This prevents an old binary paired with updated sources advertising the
  // new source rule hash. Both hosts must ship the identical complete dist/.
  const runtimeBundle = import.meta.url.endsWith('.js') ? readdirSync(new URL('dist/',root))
    .filter(p=>p.endsWith('.js')).sort().map(p=>({path:'dist/'+p,sha256:hash(readFileSync(new URL('dist/'+p,root)))})) : [];
  return hash(canonicalJson({ files, runtimeBundle, imageDigest, limits: LIMITS, licenses: LICENSES }));
}
export const isInstruction = (path: string) => /(^|\/)(CLAUDE\.md|AGENTS\.md|\.cursorrules)$/i.test(path) || /(^|\/)\.claude(\/|$)/i.test(path);
export const INSTALL_SCRIPTS = ['preinstall','install','postinstall','prepare'];
export const injection = /ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions|(?:exfiltrat|steal|upload).{0,80}(?:secret|token|key)|(?:disable|bypass).{0,40}(?:safety|sandbox|security)|(?:system|assistant)\s*:\s*(?:override|ignore)|(?:curl|wget).{0,120}\|\s*(?:ba)?sh/is;
export const secret = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[0-9A-Z]{16}|sk_live_[A-Za-z0-9]{20,})\b|(?:api[_-]?key|secret|password|token)\s*[:=]\s*["'](?!(?:example|placeholder|test|dummy|\$))[A-Za-z0-9/+_-]{20,}["']/i;
export const curlPipe = /(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/i;
export function licenseFromFile(data: Buffer): string | null {
  const text = data.toString('utf8');
  // An SPDX label alone is not evidence of a license grant.
  const matches = [
    ['MIT', /permission is hereby granted, free of charge/i, /the software is provided "as is"/i, /the above copyright notice and this permission notice/i],
    ['Apache-2.0', /Apache License/i, /Version 2\.0, January 2004/i, /TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION/i],
    ['BSD-3-Clause', /redistribution and use in source and binary forms/i, /neither the name/i, /this software is provided.*as is/is],
    ['BSD-2-Clause', /redistribution and use in source and binary forms/i, /this software is provided.*as is/is],
    ['ISC', /permission to use, copy, modify, and\/or distribute this software/i, /the software is provided "as is"/i],
  ] as const;
  return matches.find(([, ...patterns]) => patterns.every(p=>p.test(text)))?.[0] ?? null;
}
export function executableBlob(entry: TreeEntry): boolean {
  const magic = entry.data.subarray(0,4).toString('hex');
  return magic.startsWith('7f454c46') || magic.startsWith('4d5a') ||
    ['feedface','cefaedfe','feedfacf','cffaedfe','cafebabe','bebafeca','cafebabf','bfbafeca'].includes(magic);
}
