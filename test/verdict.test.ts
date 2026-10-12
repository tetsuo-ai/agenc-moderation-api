import { it, expect, afterEach } from 'vitest';
import { generateKeyPairSync, verify, sign } from 'node:crypto';
import { canonicalJson, documentBytes, signDocument, VERDICT_DOMAIN, MANIFEST_DOMAIN, verifyKeyManifest, keyAddress, authorizedVerdictKey } from '../src/verdict.js';
import { installVerdictFixture } from './fixtures.js';
let fixture: ReturnType<typeof installVerdictFixture> | undefined;
afterEach(()=>{fixture?.cleanup();fixture=undefined;});
it('signs exact 0xff domain NUL canonical bytes and refuses a different domain',()=>{
 const key=generateKeyPairSync('ed25519');const body={z:2,a:{b:1,a:3}};const doc=signDocument(body,key.privateKey);
 expect(canonicalJson(body)).toBe('{"a":{"a":3,"b":1},"z":2}');
 expect(VERDICT_DOMAIN.toString('hex')).toBe(Buffer.concat([Buffer.from([255]),Buffer.from('agenc-desktop-attestation/v1'),Buffer.from([0])]).toString('hex'));
 expect(verify(null,documentBytes(body),key.publicKey,Buffer.from(doc.signature,'hex'))).toBe(true);
 expect(verify(null,documentBytes(body,MANIFEST_DOMAIN),key.publicKey,Buffer.from(doc.signature,'hex'))).toBe(false);
 expect(verify(null,documentBytes({...body,z:3}),key.publicKey,Buffer.from(doc.signature,'hex'))).toBe(false);
});
it('verifies the offline root manifest and rejects tampering or wrong root',()=>{
 fixture=installVerdictFixture();const root=keyAddress(fixture.root.privateKey);
 expect(verifyKeyManifest(fixture.manifest,root)).toEqual(fixture.manifest);
 expect(()=>verifyKeyManifest({...fixture!.manifest,body:{...fixture!.manifest.body,v:2}},root)).toThrow();
 expect(()=>verifyKeyManifest(fixture!.manifest,keyAddress(generateKeyPairSync('ed25519').privateKey))).toThrow();
});
it('rejects a validly signed expired manifest',()=>{
 fixture=installVerdictFixture();const body={...fixture.manifest.body,expiresAt:new Date(Date.now()-1000).toISOString()};const doc={body,signature:sign(null,documentBytes(body,MANIFEST_DOMAIN),fixture.root.privateKey).toString('hex')};
 expect(()=>verifyKeyManifest(doc,keyAddress(fixture!.root.privateKey))).toThrow(/expired/);
});
it('refuses V equal to roster payer R',()=>{
 fixture=installVerdictFixture();expect(()=>authorizedVerdictKey(keyAddress(fixture!.verdict.privateKey))).toThrow(/Separate/);
});
it('refuses a signed manifest with invalid issuance time',()=>{
 fixture=installVerdictFixture();const body={...fixture.manifest.body,issuedAt:'invalid'};const doc={body,signature:sign(null,documentBytes(body,MANIFEST_DOMAIN),fixture.root.privateKey).toString('hex')};
 expect(()=>verifyKeyManifest(doc,keyAddress(fixture!.root.privateKey))).toThrow();
});
