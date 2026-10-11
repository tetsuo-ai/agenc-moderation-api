import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, chmodSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import type { Job } from '../worker/types.js';
import type { CreatorAuthorization } from './binding.js';
import type { SignedDocument } from './verdict.js';
export interface QueueContext { payload: Record<string,unknown>; creator: string; specUri?: string; authenticatedCreator: boolean; creatorAuthorization?: CreatorAuthorization }
export interface StoredJob { id: string; binding: string; task: string; hash: string; kind: string; job: string; context: string; state: string; worker: string|null; lease: string|null; leaseUntil: number; reviewed: string|null; report: string|null; result: string|null; expires: number }

import { ModerationRejectError } from './errors.js';
export interface StoredIntake {
    task: string;
    hash: string;
    creator: string;
    state: string;
    signature: string | null;
    expires: number;
    result: string | null;
}
export interface SpendLimits {
    hourlyLamports: number;
    dailyLamports: number;
    dailyIntakes: number;
    hourlyTasks: number;
    walletFloor: number;
}
export const DEFAULT_SPEND_LIMITS: SpendLimits = { hourlyLamports: 30000000, dailyLamports: 150000000, dailyIntakes: 20, hourlyTasks: 5, walletFloor: 100000000 };
/** Single-host durable journal. Reservations survive crashes and are never automatically resent. */
export class AttestationStore {
    readonly db: DatabaseSync;
    constructor(path: string) {
        if (path !== ':memory:')
            mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
        this.db = new DatabaseSync(path);
        if (path !== ':memory:')
            chmodSync(path, 0o600);
        this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS intakes(task TEXT PRIMARY KEY, hash TEXT NOT NULL, creator TEXT NOT NULL, state TEXT NOT NULL, signature TEXT, expires INTEGER NOT NULL, result TEXT);
      CREATE TABLE IF NOT EXISTS spend(id INTEGER PRIMARY KEY, task TEXT, creator TEXT, at INTEGER, lamports INTEGER);
      CREATE TABLE IF NOT EXISTS nonces(creator TEXT, nonce TEXT, at INTEGER, PRIMARY KEY(creator,nonce));
      CREATE TABLE IF NOT EXISTS admissions(id INTEGER PRIMARY KEY, task TEXT, hash TEXT, creator TEXT, at INTEGER);
      CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, binding TEXT UNIQUE NOT NULL, task TEXT NOT NULL, hash TEXT NOT NULL, kind TEXT NOT NULL, job TEXT NOT NULL, context TEXT NOT NULL, state TEXT NOT NULL, worker TEXT, lease TEXT, leaseUntil INTEGER NOT NULL DEFAULT 0, reviewed TEXT, report TEXT, result TEXT, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at INTEGER, event TEXT, detail TEXT);`);
    }
    get(task: string): StoredIntake | undefined { return this.db.prepare('SELECT * FROM intakes WHERE task=?').get(task) as unknown as StoredIntake | undefined; }
    audit(event: string, detail: unknown): void { this.db.prepare('INSERT INTO audit(at,event,detail) VALUES(?,?,?)').run(Date.now(), event, JSON.stringify(detail)); }
    consumeNonce(creator: string, nonce: string): void {
        try {
            this.db.prepare('INSERT INTO nonces VALUES(?,?,?)').run(creator, nonce, Date.now());
        }
        catch {
            throw new ModerationRejectError(409, 'Nonce already used.');
        }
    }
    private admitInside(task: string, hash: string, creator: string, limits: SpendLimits, now: number): void {
        const prior = this.db.prepare('SELECT at FROM admissions WHERE task=? AND hash=? ORDER BY at DESC LIMIT 1').get(task, hash) as {
            at: number;
        } | undefined;
        if (prior && prior.at > now - 72 * 3600000)
            return;
        const counts = this.db.prepare('SELECT COUNT(*) AS dayCount, COUNT(DISTINCT CASE WHEN at>? THEN task END) AS hourCount FROM admissions WHERE creator=? AND at>?').get(now - 3600000, creator, now - 86400000) as {
            dayCount: number;
            hourCount: number;
        };
        const hourlyTask = this.db.prepare('SELECT 1 FROM admissions WHERE creator=? AND task=? AND at>?').get(creator, task, now - 3600000);
        if (counts.dayCount >= limits.dailyIntakes || (!hourlyTask && counts.hourCount >= limits.hourlyTasks))
            throw new ModerationRejectError(429, 'Creator quota exceeded.');
        this.db.prepare('INSERT INTO admissions(task,hash,creator,at) VALUES(?,?,?,?)').run(task, hash, creator, now);
    }
    admit(task: string, hash: string, creator: string, limits: SpendLimits, now = Date.now()): void {
        this.db.exec('BEGIN IMMEDIATE');
        try {
            this.admitInside(task, hash, creator, limits, now);
            this.db.exec('COMMIT');
        }
        catch (e) {
            this.db.exec('ROLLBACK');
            throw e;
        }
    }
    reserve(task: string, hash: string, creator: string, cost: number, balance: number, limits: SpendLimits, now = Date.now(), queued?: {job: Job; context: QueueContext}): void {
        this.db.exec('BEGIN IMMEDIATE');
        try {
            const prior = this.get(task);
            if (prior?.state === 'queued' && (queued || prior.hash !== hash)) throw new ModerationRejectError(409, 'Task already queued.');
            if (prior && (prior.state === 'pending' || prior.state === 'reserved' || (prior.state !== 'queued' && prior.expires > now)))
                throw new ModerationRejectError(409, 'Task already reserved.');
            this.admitInside(task, hash, creator, limits, now);
            if (prior?.state === 'queued') this.db.prepare('DELETE FROM spend WHERE id=(SELECT MAX(id) FROM spend WHERE task=?)').run(task);
            const spend = this.db.prepare('SELECT COALESCE(SUM(lamports),0) AS day, COALESCE(SUM(CASE WHEN at>? THEN lamports ELSE 0 END),0) AS hour FROM spend WHERE at>?').get(now - 3600000, now - 86400000) as {
                day: number;
                hour: number;
            };
            if (spend.day + cost > limits.dailyLamports || spend.hour + cost > limits.hourlyLamports)
                throw new ModerationRejectError(429, 'Spend cap exceeded.');
            // Concurrent reserved transactions may not yet be reflected in RPC balance.
            const outstanding = this.db.prepare("SELECT COALESCE(SUM(lamports),0) AS n FROM spend WHERE task<>? AND id IN (SELECT MAX(id) FROM spend GROUP BY task) AND task IN (SELECT task FROM intakes WHERE state IN ('queued','reserved','pending'))").get(task) as {
                n: number;
            };
            if (balance - cost - outstanding.n < limits.walletFloor)
                throw new ModerationRejectError(503, 'Wallet floor reached.');
            this.db.prepare("INSERT OR REPLACE INTO intakes VALUES(?,?,?,?,NULL,?,NULL)").run(task, hash, creator, queued ? 'queued':'reserved', now + 72 * 3600000);
            if (queued) this.insertJob(queued.job, queued.context, now);
            this.db.prepare('INSERT INTO spend(task,creator,at,lamports) VALUES(?,?,?,?)').run(task, creator, now, cost);
            this.audit('reserved', { task, hash, creator, cost });
            this.db.exec('COMMIT');
        }
        catch (e) {
            this.db.exec('ROLLBACK');
            throw e;
        }
    }
    submitted(task: string, signature: string): void { this.db.prepare("UPDATE intakes SET state='pending',signature=? WHERE task=?").run(signature, task); this.audit('submitted', { task, signature }); }
    finish(task: string, result: unknown, expires: number): void { this.db.prepare("UPDATE intakes SET state='confirmed',result=?,expires=? WHERE task=?").run(JSON.stringify(result), expires, task); this.audit('confirmed', { task }); }
    saveVerdict(task: string, hash: string, creator: string, result: unknown, expires: number): void {
        const attestation = (result as {
            attestation?: {
                signature: string;
            } | null;
        }).attestation;
        const state = attestation ? 'confirmed' : 'held';
        const saved = this.db.prepare(`INSERT INTO intakes VALUES(?,?,?,?,?,?,?) ON CONFLICT(task) DO UPDATE SET hash=excluded.hash,creator=excluded.creator,state=excluded.state,signature=excluded.signature,expires=excluded.expires,result=excluded.result WHERE (intakes.hash=excluded.hash OR intakes.expires<=?) AND intakes.state NOT IN ('reserved','pending')`).run(task, hash, creator, state, attestation?.signature || null, expires, JSON.stringify(result), Date.now());
        if (saved.changes === 0) throw new ModerationRejectError(409, 'One live hash per task.');
        this.audit('verdict', { task, hash, creator });
    }
    private insertJob(job: Job, context: QueueContext, now: number): StoredJob {
        const id = randomUUID(), binding = JSON.stringify([job.kind,job.taskPda,job.jobSpecHash,job.artifact ?? null]);
        this.db.prepare("INSERT INTO jobs(id,binding,task,hash,kind,job,context,state,expires) VALUES(?,?,?,?,?,?,?,'queued',?)").run(id,binding,job.taskPda,job.jobSpecHash,job.kind,JSON.stringify(job),JSON.stringify(context),now+72*3600000);
        return this.job(id)!;
    }
    job(id: string): StoredJob|undefined { return this.db.prepare('SELECT * FROM jobs WHERE id=?').get(id) as unknown as StoredJob|undefined; }
    intakeJob(task: string, hash: string): StoredJob|undefined { return this.db.prepare("SELECT * FROM jobs WHERE task=? AND hash=? AND kind='repo-intake' ORDER BY rowid DESC LIMIT 1").get(task,hash) as unknown as StoredJob|undefined; }
    deliverableJob(task: string, submission: string, artifact: string): StoredJob|undefined {
        return this.db.prepare('SELECT * FROM jobs WHERE binding=?').get(JSON.stringify(['deliverable',task,this.get(task)?.hash,{sha256:artifact,submissionPda:submission}])) as unknown as StoredJob|undefined;
    }
    enqueueDeliverable(job: Job, context: QueueContext, limits: SpendLimits): StoredJob {
        this.db.exec('BEGIN IMMEDIATE');
        try {
            // Artifact-specific admissions bound scanner work, including failed reviews.
            this.admitInside(job.taskPda,'deliverable:'+job.artifact!.submissionPda+':'+job.artifact!.sha256,context.creator,limits,Date.now());
            const result=this.insertJob(job,context,Date.now()); this.db.exec('COMMIT'); return result;
        } catch(e) { this.db.exec('ROLLBACK'); throw e; }
    }
    leaseJob(worker: string, now=Date.now()): StoredJob|undefined {
        this.db.exec('BEGIN IMMEDIATE');
        try {
            const next=this.db.prepare("SELECT id FROM jobs WHERE (state='queued' OR (state='leased' AND leaseUntil<=?)) AND expires>? ORDER BY rowid LIMIT 1").get(now,now) as {id:string}|undefined;
            if(next) this.db.prepare("UPDATE jobs SET state='leased',worker=?,lease=?,leaseUntil=? WHERE id=?").run(worker,randomBytes(24).toString('hex'),now+15*60000,next.id);
            this.db.exec('COMMIT'); return next ? this.job(next.id):undefined;
        } catch(e) { this.db.exec('ROLLBACK'); throw e; }
    }
    saveReview(id: string, reviewed: SignedDocument, report: unknown): void {
        this.db.prepare("UPDATE jobs SET state='reviewed',reviewed=?,report=? WHERE id=?").run(JSON.stringify(reviewed),JSON.stringify(report),id);
    }
    finishJob(id: string, result: unknown, expires: number): void {
        this.db.prepare("UPDATE jobs SET state='done',result=?,expires=? WHERE id=?").run(JSON.stringify(result),expires,id);
    }
    releaseQueuedSpend(task: string): void {
        if(this.get(task)?.state === 'queued') this.db.prepare('DELETE FROM spend WHERE id=(SELECT MAX(id) FROM spend WHERE task=?)').run(task);
    }
    close(): void { this.db.close(); }
}
const stores = new Map<string, AttestationStore>();
export function getStore(path = process.env.ATTESTATION_DB_PATH ?? './data/attestations.sqlite'): AttestationStore {
    let store = stores.get(path);
    if (!store) {
        store = new AttestationStore(path);
        stores.set(path, store);
    }
    return store;
}
