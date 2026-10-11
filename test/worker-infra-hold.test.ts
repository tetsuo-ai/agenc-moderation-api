import { expect, it } from 'vitest';
import { check, infrastructureHold, INFRA_HOLD } from '../worker/types.js';

it('retries only holds whose every open reason is an infrastructure failure',()=>{
 const pass=check('github-metadata','pass');
 expect(infrastructureHold([pass,check('worker-error','hold',INFRA_HOLD.worker)])).toBe(true);
 expect(infrastructureHold([check('github-commit','hold',INFRA_HOLD.github),check('signer-github-commit','hold',INFRA_HOLD.github)])).toBe(true);
 expect(infrastructureHold([pass])).toBe(false);
 expect(infrastructureHold([check('osv','hold','GHSA-aaaa-bbbb-cccc')])).toBe(false);
 expect(infrastructureHold([check('osv','hold',INFRA_HOLD.osv),check('payload-policy','hold','PROMPT_INJECTION_OVERRIDE')])).toBe(false);
 expect(infrastructureHold([check('worker-error','hold',INFRA_HOLD.worker),check('secrets','reject','Secret in tree')])).toBe(false);
 expect(infrastructureHold([check('paths','hold')])).toBe(false);
});
