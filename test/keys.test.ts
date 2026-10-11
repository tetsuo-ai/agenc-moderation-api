import { it,expect } from 'vitest';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadModeratorSigner } from '../src/signer.js';
import { loadVerdictKey } from '../src/verdict.js';
import { installPayerFixture, installVerdictFixture } from './fixtures.js';
it('loads payer credentials from a file and refuses environment secrets in production',async()=>{
 const fixture=installVerdictFixture();const payer=installPayerFixture();const secret=process.env.MODERATION_SIGNER_SECRET!;const oldMode=process.env.NODE_ENV;
 const path=join(fixture.directory,'payer.json');writeFileSync(path,secret,{mode:0o600});process.env.MODERATION_SIGNER_SECRET_FILE=path;process.env.NODE_ENV='production';
 try {
  await expect(loadModeratorSigner()).rejects.toThrow(/Environment secrets/);
  delete process.env.MODERATION_SIGNER_SECRET;expect((await loadModeratorSigner()).address).toBe(payer.address);
  process.env.MODERATION_AUTHORITY_SECRET=secret;await expect(loadModeratorSigner()).rejects.toThrow(/Environment secrets/);
 } finally {delete process.env.MODERATION_SIGNER_SECRET;delete process.env.MODERATION_SIGNER_SECRET_FILE;delete process.env.MODERATION_AUTHORITY_SECRET;if(oldMode===undefined) delete process.env.NODE_ENV;else process.env.NODE_ENV=oldMode;fixture.cleanup();}
});
it('refuses verdict environment secrets in production',()=>{
 const fixture=installVerdictFixture();const oldMode=process.env.NODE_ENV;process.env.NODE_ENV='production';process.env.VERDICT_KEY_SECRET='forbidden';
 try {expect(()=>loadVerdictKey()).toThrow(/Environment secrets/);} finally {delete process.env.VERDICT_KEY_SECRET;if(oldMode===undefined) delete process.env.NODE_ENV;else process.env.NODE_ENV=oldMode;fixture.cleanup();}
});
