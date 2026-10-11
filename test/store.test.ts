import { describe, it, expect } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { AttestationStore, DEFAULT_SPEND_LIMITS } from '../src/store.js';
describe('durable spend and identity bounds',()=>{
 it.each(['hour','day'])('bounds per-creator %s quota despite changing IPs',kind=>{
  const store=new AttestationStore(':memory:');const limits={...DEFAULT_SPEND_LIMITS,dailyIntakes:kind==='day'?1:20,hourlyTasks:kind==='hour'?1:5};
  try {store.reserve('t1','h','creator',10,1e9,limits);expect(()=>store.reserve('t2','h','creator',10,1e9,limits)).toThrow(/quota/);expect(()=>store.reserve('t2','h','other',10,1e9,limits)).not.toThrow();} finally {store.close();}
 });
 it.each(['hour','day'])('accounts cumulative %s spend and rolls failed reservations back',kind=>{
  const store=new AttestationStore(':memory:');const limits={...DEFAULT_SPEND_LIMITS,hourlyLamports:kind==='hour'?15:100,dailyLamports:kind==='day'?15:100};
  try {store.reserve('t1','h','c1',10,1e9,limits);expect(()=>store.reserve('t2','h','c2',10,1e9,limits)).toThrow(/Spend cap/);expect(store.get('t2')).toBeUndefined();} finally {store.close();}
 });
 it('reserves balance for concurrent outstanding sends',()=>{
  const store=new AttestationStore(':memory:');const limits={...DEFAULT_SPEND_LIMITS,walletFloor:100};
  try {store.reserve('t1','h','c1',60,200,limits);expect(()=>store.reserve('t2','h','c2',60,200,limits)).toThrow(/Wallet floor/);} finally {store.close();}
 });
 it('retains pending signature, spend, audit and used nonce across process restart',()=>{
  const directory=mkdtempSync(join(tmpdir(),'attestor-store-'));const path=join(directory,'db');
  const first=new AttestationStore(path);first.reserve('t','h','c',10,1e9,DEFAULT_SPEND_LIMITS);first.consumeNonce('c','n');first.submitted('t','sig');first.close();
  const next=new AttestationStore(path);
  try {expect(next.get('t')).toMatchObject({state:'pending',signature:'sig'});expect(()=>next.consumeNonce('c','n')).toThrow();expect(()=>next.reserve('t','different','c',10,1e9,DEFAULT_SPEND_LIMITS)).toThrow();expect(next.db.prepare('SELECT COUNT(*) AS n FROM audit').get()).toMatchObject({n:2});} finally {next.close();rmSync(directory,{recursive:true,force:true});}
 });
 it('serializes reservations between two database connections',()=>{
  const directory=mkdtempSync(join(tmpdir(),'attestor-concurrency-'));const path=join(directory,'db');const a=new AttestationStore(path);const b=new AttestationStore(path);
  try {a.reserve('t','h','c',10,1e9,DEFAULT_SPEND_LIMITS);expect(()=>b.reserve('t','h2','c',10,1e9,DEFAULT_SPEND_LIMITS)).toThrow();} finally {a.close();b.close();rmSync(directory,{recursive:true,force:true});}
 });
});
it('replaces expired held results with the new live hash',()=>{
 const store=new AttestationStore(':memory:');
 try {store.saveVerdict('task','old','c',{attestation:null},Date.now()-1);store.saveVerdict('task','new','c',{attestation:null},Date.now()+1000);expect(store.get('task')?.hash).toBe('new');} finally {store.close();}
});
it('atomically refuses competing live verdict hashes',()=>{
 const store=new AttestationStore(':memory:');
 try {store.saveVerdict('task','first','c',{attestation:null},Date.now()+1000);expect(()=>store.saveVerdict('task','second','c',{attestation:null},Date.now()+1000)).toThrow(/One live hash/);expect(store.get('task')?.hash).toBe('first');} finally {store.close();}
});
