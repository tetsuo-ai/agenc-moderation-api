import { createPrivateKey, createPublicKey, sign, verify, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { base58Decode, base58Encode } from './base58.js';
export function canonicalJson(value: unknown): string {
    if (value === null || typeof value !== 'object') {
        const s = JSON.stringify(value);
        if (s === undefined)
            throw new Error('Non JSON value');
        return s;
    }
    if (Array.isArray(value))
        return `[${value.map(canonicalJson).join(',')}]`;
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonicalJson((value as Record<string, unknown>)[k])}`).join(',')}}`;
}
export const VERDICT_DOMAIN = Buffer.concat([Buffer.from([0xff]), Buffer.from('agenc-desktop-attestation/v1'), Buffer.from([0])]);
export const MANIFEST_DOMAIN = Buffer.concat([Buffer.from([0xff]), Buffer.from('agenc-desktop-keys/v1'), Buffer.from([0])]);
export interface SignedDocument<T = Record<string, unknown>> {
    body: T;
    signature: string;
}
export function documentBytes(body: unknown, domain = VERDICT_DOMAIN): Buffer { return Buffer.concat([domain, Buffer.from(canonicalJson(body))]); }
export function signDocument<T>(body: T, key: KeyObject): SignedDocument<T> { return { body, signature: sign(null, documentBytes(body), key).toString('hex') }; }
export function publicKeyFromAddress(address: string): KeyObject {
    const bytes = base58Decode(address);
    if (bytes.length !== 32)
        throw new Error('Invalid public key');
    return createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), bytes]), format: 'der', type: 'spki' });
}
export function keyAddress(key: KeyObject): string { return base58Encode(createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32)); }
export function loadVerdictKey(): KeyObject {
    if (process.env.NODE_ENV === 'production' && process.env.VERDICT_KEY_SECRET)
        throw new Error('Environment secrets forbidden');
    const path = process.env.VERDICT_KEY_FILE;
    if (!path)
        throw new Error('Verdict key file required');
    const key = createPrivateKey(readFileSync(path));
    if (key.asymmetricKeyType !== 'ed25519')
        throw new Error('Ed25519 required');
    return key;
}
/** Manifest is provisioned offline; root private key is never loaded here. */
export function verifyKeyManifest(doc: SignedDocument, root: string, now = Date.now()): SignedDocument {
    if (!/^[0-9a-f]{128}$/.test(doc.signature) || !verify(null, documentBytes(doc.body, MANIFEST_DOMAIN), publicKeyFromAddress(root), Buffer.from(doc.signature, 'hex')))
        throw new Error('Invalid manifest signature');
    const issued = Date.parse(String(doc.body.issuedAt));
    const expires = Date.parse(String(doc.body.expiresAt));
    if (doc.body.v !== 1 || !Array.isArray(doc.body.keys)) throw new Error('Invalid manifest schema');
    if (!Number.isFinite(issued) || issued > now || !(expires > now) || expires <= issued)
        throw new Error('Manifest expired');
    return doc;
}
export function loadKeyManifest(): SignedDocument {
    if (!process.env.KEY_MANIFEST_FILE || !process.env.ROOT_PUBLIC_KEY)
        throw new Error('Key manifest required');
    return verifyKeyManifest(JSON.parse(readFileSync(process.env.KEY_MANIFEST_FILE, 'utf8')), process.env.ROOT_PUBLIC_KEY);
}
export function authorizedVerdictKey(moderator: string | null): {
    key: KeyObject;
    keyId: string;
} {
    const key = loadVerdictKey();
    const pub = keyAddress(key);
    if (pub === moderator)
        throw new Error('Separate verdict key required');
    const manifest = loadKeyManifest();
    const keys = manifest.body.keys;
    const entry = Array.isArray(keys) ? keys.find(k => k.publicKey === pub && k.purpose === 'verdict' && !k.revoked && Date.parse(k.notBefore) <= Date.now() && Date.parse(k.notAfter) > Date.now()) : undefined;
    if (!entry || typeof entry.keyId !== 'string')
        throw new Error('Verdict key not authorized');
    return { key, keyId: entry.keyId };
}
