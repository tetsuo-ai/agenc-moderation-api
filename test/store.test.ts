import { describe, it, expect } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { AttestationStore, DEFAULT_SPEND_LIMITS } from '../src/store.js';
describe('durable creator payment and identity bounds',()=>{
 it.each(['hour','day'])('bounds per-creator %s quota despite changing IPs',kind=>{
  const store=new AttestationStore(':memory:');const limits={...DEFAULT_SPEND_LIMITS,dailyIntakes:kind==='day'?1:20,hourlyTasks:kind==='hour'?1:5};
  try {store.saveOffer('t1','h','creator',{transaction:'wire'},Date.now()+10000,limits);expect(()=>store.saveOffer('t2','h','creator',{transaction:'wire'},Date.now()+10000,limits)).toThrow(/quota/);expect(()=>store.saveOffer('t2','h','other',{transaction:'wire'},Date.now()+10000,limits)).not.toThrow();} finally {store.close();}
 });
 it.each(['hour','day'])('ignores legacy %s spend caps and never writes a spend ledger',kind=>{
  const store=new AttestationStore(':memory:');const limits={...DEFAULT_SPEND_LIMITS,hourlyLamports:kind==='hour'?0:100,dailyLamports:kind==='day'?0:100,walletFloor:Number.MAX_SAFE_INTEGER};
  try {store.saveOffer('t1','h','c1',{transaction:'wire'},Date.now()+10000,limits);store.saveOffer('t2','h','c2',{transaction:'wire'},Date.now()+10000,limits);expect(store.db.prepare('SELECT COUNT(*) AS n FROM spend').get()).toEqual({n:0});} finally {store.close();}
 });
 it('caps outstanding offers and releases capacity on confirmation',()=>{
  const store=new AttestationStore(':memory:');const limits={...DEFAULT_SPEND_LIMITS,outstandingTransactions:1};
  try {
   store.saveOffer('t1','h','c',{transaction:'wire'},Date.now()+10000,limits);expect(()=>store.saveOffer('t2','h','c',{transaction:'wire'},Date.now()+10000,limits)).toThrow(/Outstanding/);
   store.saveVerdict('t1','h','c',{attestation:{signature:'sig'}},Date.now()+10000);expect(()=>store.saveOffer('t2','h','c',{transaction:'wire'},Date.now()+10000,limits)).not.toThrow();
  } finally {store.close();}
 });
 it('retains payment offer, audit and used nonce across process restart',()=>{
  const directory=mkdtempSync(join(tmpdir(),'attestor-store-'));const path=join(directory,'db');
  const first=new AttestationStore(path);first.saveOffer('t','h','c',{transaction:'wire'},Date.now()+10000,DEFAULT_SPEND_LIMITS);first.consumeNonce('c','n');first.close();
  const next=new AttestationStore(path);
  try {expect(next.get('t')).toMatchObject({state:'awaiting-payment',result:JSON.stringify({transaction:'wire'})});expect(()=>next.consumeNonce('c','n')).toThrow();expect(()=>next.saveOffer('t','different','c',{transaction:'wire'},Date.now()+10000,DEFAULT_SPEND_LIMITS)).toThrow();expect(next.db.prepare('SELECT COUNT(*) AS n FROM audit').get()).toMatchObject({n:1});} finally {next.close();rmSync(directory,{recursive:true,force:true});}
 });
 it('serializes offers and creator caps between two database connections',()=>{
  const directory=mkdtempSync(join(tmpdir(),'attestor-concurrency-'));const path=join(directory,'db');const a=new AttestationStore(path);const b=new AttestationStore(path);const limits={...DEFAULT_SPEND_LIMITS,outstandingTransactions:1};
  try {
   a.saveOffer('t','h','c',{transaction:'wire'},Date.now()+10000,limits);
   expect(()=>b.saveOffer('t','h2','c',{transaction:'wire'},Date.now()+10000,limits)).toThrow();expect(()=>b.saveOffer('other','h','c',{transaction:'wire'},Date.now()+10000,limits)).toThrow(/Outstanding/);
   const first=a.get('t')!.result!;a.saveOffer('t','h','c',{transaction:'fresh'},Date.now()+10000,limits,first);
   expect(b.saveOffer('t','h','c',{transaction:'competing'},Date.now()+10000,limits,first)).toEqual({transaction:'fresh'});
  } finally {a.close();b.close();rmSync(directory,{recursive:true,force:true});}
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
