import { afterEach, expect, it, vi } from 'vitest';
import { loadConfig } from '../src/config.js';
afterEach(()=>vi.unstubAllEnvs());
it('defaults to no service fee and five outstanding creator transactions',()=>{
 vi.stubEnv('ATTESTATION_SERVICE_FEE_LAMPORTS',undefined);vi.stubEnv('CREATOR_OUTSTANDING_TRANSACTIONS',undefined);
 expect(loadConfig()).toMatchObject({attestationServiceFeeLamports:0,spendLimits:{outstandingTransactions:5}});
});
it('accepts exact lamport fees and zero outstanding capacity',()=>{
 vi.stubEnv('ATTESTATION_SERVICE_FEE_LAMPORTS','12345');vi.stubEnv('CREATOR_OUTSTANDING_TRANSACTIONS','0');
 expect(loadConfig()).toMatchObject({attestationServiceFeeLamports:12345,spendLimits:{outstandingTransactions:0}});
});
it.each(['-1','0.1','42junk','9007199254740992'])('rejects unsafe payment configuration %s',value=>{
 for(const name of ['ATTESTATION_SERVICE_FEE_LAMPORTS','CREATOR_OUTSTANDING_TRANSACTIONS']) {
  vi.stubEnv(name,value);expect(()=>loadConfig()).toThrow(`Invalid ${name}`);vi.stubEnv(name,undefined);
 }
});
