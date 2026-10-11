import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, chmodSync } from 'node:fs';
import { dirname } from 'node:path';
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
    reserve(task: string, hash: string, creator: string, cost: number, balance: number, limits: SpendLimits, now = Date.now()): void {
        this.db.exec('BEGIN IMMEDIATE');
        try {
            const prior = this.get(task);
            if (prior && (prior.state === 'pending' || prior.state === 'reserved' || prior.expires > now))
                throw new ModerationRejectError(409, 'Task already reserved.');
            this.admitInside(task, hash, creator, limits, now);
            const spend = this.db.prepare('SELECT COALESCE(SUM(lamports),0) AS day, COALESCE(SUM(CASE WHEN at>? THEN lamports ELSE 0 END),0) AS hour FROM spend WHERE at>?').get(now - 3600000, now - 86400000) as {
                day: number;
                hour: number;
            };
            if (spend.day + cost > limits.dailyLamports || spend.hour + cost > limits.hourlyLamports)
                throw new ModerationRejectError(429, 'Spend cap exceeded.');
            // Concurrent reserved transactions may not yet be reflected in RPC balance.
            const outstanding = this.db.prepare("SELECT COALESCE(SUM(lamports),0) AS n FROM spend WHERE task IN (SELECT task FROM intakes WHERE state IN ('reserved','pending'))").get() as {
                n: number;
            };
            if (balance - cost - outstanding.n < limits.walletFloor)
                throw new ModerationRejectError(503, 'Wallet floor reached.');
            this.db.prepare("INSERT OR REPLACE INTO intakes VALUES(?,?,?,'reserved',NULL,?,NULL)").run(task, hash, creator, now + 72 * 3600000);
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
