import { verify } from 'node:crypto';
import { publicKeyFromAddress } from './verdict.js';
import { ModerationRejectError } from './errors.js';
import type { AttestationStore } from './store.js';
export interface CreatorAuthorization {
    issuedAt: string;
    nonce: string;
    signature: string;
}
export function creatorRequestBytes(creator: string, task: string, hash: string, auth: Pick<CreatorAuthorization, 'issuedAt' | 'nonce'>): Buffer {
    return Buffer.from(`AgenC attestation request v1\ncreator=${creator}\ntask=${task}\njobSpecHash=${hash}\nissuedAt=${auth.issuedAt}\nnonce=${auth.nonce}`);
}
export function verifyCreatorAuthorization(creator: string, task: string, hash: string, auth: CreatorAuthorization | undefined, now = Date.now()): boolean {
    if (!auth || typeof auth.issuedAt !== 'string' || !/^[0-9a-f]{32,128}$/.test(auth.nonce) || !/^[0-9a-f]{128}$/.test(auth.signature))
        return false;
    const at = Date.parse(auth.issuedAt);
    if (!Number.isFinite(at) || new Date(at).toISOString() !== auth.issuedAt || at > now + 30000 || at < now - 5 * 60000)
        return false;
    try {
        return verify(null, creatorRequestBytes(creator, task, hash, auth), publicKeyFromAddress(creator), Buffer.from(auth.signature, 'hex'));
    }
    catch {
        return false;
    }
}
export function bindRequester(taskData: {
    creator: string;
    status: number;
    currentWorkers: number;
    completions: number;
    description: ArrayLike<number>;
}, task: string, hash: string, auth: CreatorAuthorization | undefined, store: AttestationStore, preflight = false): boolean {
    if (taskData.status !== 0 || taskData.currentWorkers !== 0 || taskData.completions !== 0)
        throw new ModerationRejectError(409, 'Task is not open and unclaimed.');
    const authenticated = verifyCreatorAuthorization(taskData.creator, task, hash, auth);
    const commitment = Buffer.from(taskData.description).subarray(0, 32).toString('hex') === hash;
    if (!commitment && !authenticated)
        throw new ModerationRejectError(403, 'Creator binding required.');
    if (auth && !authenticated)
        throw new ModerationRejectError(403, 'Invalid creator authorization.');
    if (authenticated && !preflight)
        store.consumeNonce(taskData.creator, auth!.nonce);
    return authenticated;
}
