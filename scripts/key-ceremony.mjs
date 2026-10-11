#!/usr/bin/env node
// Offline key ceremony for the AgenC Desktop attestor.
//
// Run on an offline machine. The root private key never goes to the server.
//
//   node scripts/key-ceremony.mjs init-root --out root.key
//     Generates the root Ed25519 key, encrypted with a passphrase you type,
//     and prints the root public key (ROOT_PUBLIC_KEY for the server and the
//     key Desktop pins).
//
//   node scripts/key-ceremony.mjs sign-manifest --root root.key \
//       --verdict <V public key> [--days 90] [--key-id v1] --out keys.json
//     Signs the key manifest that authorizes the server's verdict key V.
//     Copy keys.json to /etc/agenc-attestor/keys.json on the server.
//
//   node scripts/key-ceremony.mjs verify --root-public <key> --manifest keys.json
//     Checks a manifest signature and validity window.
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createInterface } from 'node:readline';

const MANIFEST_DOMAIN = Buffer.concat([Buffer.from([0xff]), Buffer.from('agenc-desktop-keys/v1'), Buffer.from([0])]);
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

// Must match canonicalJson in src/verdict.ts byte for byte.
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    const s = JSON.stringify(value);
    if (s === undefined) throw new Error('Non JSON value');
    return s;
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

function base58(bytes) {
  let n = BigInt('0x' + Buffer.from(bytes).toString('hex')), s = '';
  while (n > 0n) { s = ALPHABET[Number(n % 58n)] + s; n /= 58n; }
  for (const b of bytes) { if (b === 0) s = '1' + s; else break; }
  return s;
}

function base58Decode(text) {
  let n = 0n;
  for (const ch of text) {
    const i = ALPHABET.indexOf(ch);
    if (i < 0) throw new Error('Invalid base58');
    n = n * 58n + BigInt(i);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const body = n === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex');
  const zeros = [...text].findIndex(ch => ch !== '1');
  return Buffer.concat([Buffer.alloc(zeros < 0 ? text.length : zeros), body]);
}

function publicKeyFromAddress(address) {
  const bytes = base58Decode(address);
  if (bytes.length !== 32) throw new Error('Invalid public key');
  return createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), bytes]), format: 'der', type: 'spki' });
}

function address(key) {
  const pub = key.type === 'public' ? key : createPublicKey(key);
  return base58(pub.export({ format: 'der', type: 'spki' }).subarray(-32));
}

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  if (i >= 0 && process.argv[i + 1]) return process.argv[i + 1];
  if (fallback !== undefined) return fallback;
  throw new Error(`Missing --${name}`);
}

async function passphrase(prompt) {
  if (process.env.CEREMONY_PASSPHRASE) return process.env.CEREMONY_PASSPHRASE;
  const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
  rl._writeToOutput = () => {};
  process.stderr.write(prompt);
  const value = await new Promise(resolve => rl.question('', resolve));
  rl.close();
  process.stderr.write('\n');
  if (value.length < 12) throw new Error('Use a passphrase of at least 12 characters.');
  return value;
}

async function initRoot() {
  const out = arg('out');
  if (existsSync(out)) throw new Error(`${out} already exists; refusing to overwrite.`);
  const pass = await passphrase('Root key passphrase: ');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pem = privateKey.export({ format: 'pem', type: 'pkcs8', cipher: 'aes-256-cbc', passphrase: pass });
  writeFileSync(out, pem, { mode: 0o600 });
  console.log(JSON.stringify({ rootPublicKey: address(publicKey), file: out }));
}

async function signManifest() {
  const rootFile = arg('root');
  const verdictKey = arg('verdict');
  publicKeyFromAddress(verdictKey);
  const days = Number(arg('days', '90'));
  if (!Number.isInteger(days) || days < 1 || days > 365) throw new Error('--days must be 1 to 365');
  const keyId = arg('key-id', 'v1');
  const out = arg('out');
  const root = createPrivateKey({ key: readFileSync(rootFile), passphrase: await passphrase('Root key passphrase: ') });
  const now = new Date();
  const expires = new Date(now.getTime() + days * 86_400_000);
  const body = {
    v: 1,
    issuedAt: now.toISOString(),
    expiresAt: expires.toISOString(),
    keys: [{ keyId, publicKey: verdictKey, purpose: 'verdict', notBefore: now.toISOString(), notAfter: expires.toISOString() }],
  };
  const signature = sign(null, Buffer.concat([MANIFEST_DOMAIN, Buffer.from(canonicalJson(body))]), root).toString('hex');
  writeFileSync(out, JSON.stringify({ body, signature }, null, 2) + '\n', { mode: 0o644 });
  console.log(JSON.stringify({ rootPublicKey: address(root), verdictKey, keyId, expiresAt: body.expiresAt, file: out }));
}

function verifyManifest() {
  const root = arg('root-public');
  const doc = JSON.parse(readFileSync(arg('manifest'), 'utf8'));
  const ok = /^[0-9a-f]{128}$/.test(doc.signature) &&
    verify(null, Buffer.concat([MANIFEST_DOMAIN, Buffer.from(canonicalJson(doc.body))]), publicKeyFromAddress(root), Buffer.from(doc.signature, 'hex'));
  const now = Date.now();
  const valid = ok && Date.parse(doc.body.issuedAt) <= now && Date.parse(doc.body.expiresAt) > now;
  console.log(JSON.stringify({ signatureValid: ok, inWindow: valid, keys: doc.body.keys?.map(k => ({ keyId: k.keyId, publicKey: k.publicKey, notAfter: k.notAfter })) }));
  if (!valid) process.exit(1);
}

const command = process.argv[2];
const run = { 'init-root': initRoot, 'sign-manifest': signManifest, verify: verifyManifest }[command];
if (!run) {
  console.error('Usage: key-ceremony.mjs init-root --out root.key | sign-manifest --root root.key --verdict <V> --out keys.json | verify --root-public <key> --manifest keys.json');
  process.exit(2);
}
Promise.resolve(run()).catch(error => { console.error(error.message); process.exit(1); });
