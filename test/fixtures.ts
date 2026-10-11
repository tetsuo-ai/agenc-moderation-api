import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { base58Encode } from '../src/base58.js';
import { keyAddress, documentBytes, MANIFEST_DOMAIN } from '../src/verdict.js';
export function installVerdictFixture() {
  const directory = mkdtempSync(join(tmpdir(),'attestor-test-'));
  const verdict = generateKeyPairSync('ed25519'); const root = generateKeyPairSync('ed25519');
  const body = {v:1,issuedAt:new Date(Date.now()-1000).toISOString(),expiresAt:new Date(Date.now()+86400000).toISOString(),keys:[{keyId:'V1',publicKey:keyAddress(verdict.privateKey),purpose:'verdict',notBefore:new Date(Date.now()-1000).toISOString(),notAfter:new Date(Date.now()+86400000).toISOString()}]};
  const manifest = {body,signature:sign(null,documentBytes(body,MANIFEST_DOMAIN),root.privateKey).toString('hex')};
  writeFileSync(join(directory,'verdict.pem'),verdict.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});
  writeFileSync(join(directory,'keys.json'),JSON.stringify(manifest));
  process.env.VERDICT_KEY_FILE=join(directory,'verdict.pem'); process.env.KEY_MANIFEST_FILE=join(directory,'keys.json'); process.env.ROOT_PUBLIC_KEY=keyAddress(root.privateKey);
  process.env.ATTESTATION_DB_PATH=join(directory,'store.sqlite');
  return {directory,verdict,root,manifest,cleanup:()=>{for(const key of ['VERDICT_KEY_FILE','KEY_MANIFEST_FILE','ROOT_PUBLIC_KEY','ATTESTATION_DB_PATH']) delete process.env[key];rmSync(directory,{recursive:true,force:true});}};
}
export function installPayerFixture() {
  const key = generateKeyPairSync('ed25519');
  const seed = key.privateKey.export({format:'der',type:'pkcs8'}).subarray(-32);
  const pub = key.publicKey.export({format:'der',type:'spki'}).subarray(-32);
  process.env.MODERATION_SIGNER_SECRET=JSON.stringify([...seed,...pub]);
  return { ...key, address:base58Encode(pub) };
}
