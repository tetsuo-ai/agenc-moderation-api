#!/usr/bin/env node
// Register the attestor's roster key R on the AgenC moderation roster.
//
// R pays the refundable registration bond and the roster entry rent from its
// own balance. Simulates by default; sends only with --yes. The key is read
// from stdin so it never touches disk, for example on the signer host:
//
//   systemd-creds decrypt --name=moderation.key \
//     /etc/credstore.encrypted/agenc-moderation.key - \
//     | node /opt/agenc-attestor/scripts/register-roster.mjs [--yes]
import {
  appendTransactionMessageInstructions, compileTransaction, createKeyPairSignerFromBytes, createSolanaRpc,
  createTransactionMessage, getBase64EncodedWireTransaction, getSignatureFromTransaction, pipe,
  setTransactionMessageFeePayerSigner, setTransactionMessageLifetimeUsingBlockhash, signTransactionMessageWithSigners,
} from '@solana/kit';
import { facade, fetchMaybeModerationAttestor, findModerationAttestorPda } from '@tetsuo-ai/marketplace-sdk';

const RPC_URL = process.env.RPC_URL ?? 'https://api.mainnet-beta.solana.com';
const send = process.argv.includes('--yes');
const out = value => JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2);

async function readStdin() {
  let data = '';
  for await (const chunk of process.stdin) data += chunk;
  return data.trim();
}

const raw = await readStdin();
if (!raw.startsWith('[')) throw new Error('Expected a Solana keypair JSON array on stdin.');
const signer = await createKeyPairSignerFromBytes(Uint8Array.from(JSON.parse(raw)));
const rpc = createSolanaRpc(RPC_URL);

const [rosterPda] = await findModerationAttestorPda({ attestor: signer.address });
const existing = await fetchMaybeModerationAttestor(rpc, rosterPda);
if (existing.exists) {
  console.log(out({ attestor: signer.address, roster: rosterPda, status: 'already registered' }));
  process.exit(0);
}

const balance = (await rpc.getBalance(signer.address).send()).value;
const instruction = await facade.registerModerationAttestor({ attestor: signer });
const { value: lifetime } = await rpc.getLatestBlockhash({ commitment: 'confirmed' }).send();
const message = pipe(
  createTransactionMessage({ version: 0 }),
  m => setTransactionMessageFeePayerSigner(signer, m),
  m => setTransactionMessageLifetimeUsingBlockhash(lifetime, m),
  m => appendTransactionMessageInstructions([instruction], m),
);
const signed = await signTransactionMessageWithSigners(message);
const wire = getBase64EncodedWireTransaction(signed);

const simulation = await rpc.simulateTransaction(wire, {
  encoding: 'base64', sigVerify: true, commitment: 'confirmed',
  accounts: { encoding: 'base64', addresses: [signer.address] },
}).send();
const after = simulation.value.accounts?.[0]?.lamports ?? null;
const report = {
  attestor: signer.address,
  roster: rosterPda,
  balanceLamports: String(balance),
  simulated: simulation.value.err === null ? 'ok' : simulation.value.err,
  costLamports: after === null ? null : String(balance - after),
  logs: simulation.value.err === null ? undefined : simulation.value.logs?.slice(-6),
};
if (!send || simulation.value.err !== null) {
  console.log(out({ ...report, sent: false, note: send ? 'simulation failed; nothing sent' : 'dry run; add --yes to send' }));
  process.exit(simulation.value.err === null ? 0 : 1);
}

const signature = getSignatureFromTransaction(signed);
await rpc.sendTransaction(wire, { encoding: 'base64', skipPreflight: false, preflightCommitment: 'confirmed', maxRetries: 0n }).send();
for (let i = 0; i < 60; i++) {
  const { value } = await rpc.getSignatureStatuses([signature]).send();
  const status = value[0];
  if (status?.err) { console.log(out({ ...report, sent: true, signature, error: status.err })); process.exit(1); }
  if (status?.confirmationStatus === 'confirmed' || status?.confirmationStatus === 'finalized') {
    console.log(out({ ...report, sent: true, signature, status: status.confirmationStatus }));
    process.exit(0);
  }
  await new Promise(r => setTimeout(r, 2000));
}
console.log(out({ ...report, sent: true, signature, status: 'unconfirmed after 120 s; check the signature' }));
process.exit(1);
