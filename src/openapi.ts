import { SERVICE_NAME, SERVICE_VERSION } from './version.js';
const hash = {type:'string',pattern:'^[0-9a-f]{64}$'};
const pda = {type:'string',pattern:'^[1-9A-HJ-NP-Za-km-z]{32,44}$'};
const signature = {type:'string',pattern:'^[0-9a-f]{128}$'};
const signedDocument = {type:'object',required:['body','signature'],properties:{body:{type:'object'},signature}};
const lamports={type:'integer',minimum:0,maximum:Number.MAX_SAFE_INTEGER};
const paymentBinding={type:'object',additionalProperties:false,required:['recordPda','priceLamports','payer'],properties:{recordPda:pda,priceLamports:lamports,payer:pda}};
const paymentOffer={type:'object',required:['transaction','lastValidBlockHeight','priceLamports','rentLamports','serviceFeeLamports','recordPda','moderator'],properties:{
 transaction:{type:'string',contentEncoding:'base64',description:'Version-0 Solana wire transaction signed by R only; creator adds its signature and submits. Exactly creator-to-R SystemProgram transfer, then record_task_moderation; no compute-budget instructions.'},
 lastValidBlockHeight:{type:'integer',minimum:0,maximum:Number.MAX_SAFE_INTEGER},priceLamports:lamports,rentLamports:lamports,serviceFeeLamports:lamports,recordPda:pda,moderator:pda,
}};
const intakeDocument={...signedDocument,properties:{...signedDocument.properties,body:{type:'object',required:['payment','record'],properties:{
 payment:{oneOf:[paymentBinding,{type:'null'}]},record:{type:'object',required:['moderator','pda','txSignature'],properties:{moderator:{type:['string','null']},pda:{type:['string','null']},txSignature:{type:['string','null']}}},
}}}};
const creatorAuthorization = {type:'object',required:['issuedAt','nonce','signature'],properties:{issuedAt:{type:'string',format:'date-time'},nonce:{type:'string',pattern:'^[0-9a-f]{32,128}$'},signature}};
const request = {type:'object',required:['task'],properties:{task:pda,taskPda:pda,jobSpecHash:hash,spec:{type:'object'},specUri:{type:'string',format:'uri'},preflightOnly:{type:'boolean'},creatorAuthorization}};
const compatRequest = {...request,required:['jobSpecHash'],properties:{...request.properties,jobSpec:{type:'object'},jobSpecUri:{type:'string'},text:{type:'string'},jobSpecCanonicalJson:{type:'string'}}};
const pending = {type:'object',required:['ok','moderator','pending','jobId','retryAfterSeconds'],properties:{ok:{const:true},moderator:{type:['string','null']},pending:{const:true},jobId:{type:'string',format:'uuid'},retryAfterSeconds:{type:'integer',const:5},attested:{const:false},attestation:{type:['object','null']}}};
const result = {type:'object',dependentRequired:{transaction:paymentOffer.required.filter(k=>k!=='transaction')},required:['moderator'],properties:{...paymentOffer.properties,ok:{const:true},moderator:{type:['string','null']},attested:{type:'boolean'},verdict:{type:'string',enum:['clean','suspicious','blocked']},riskScore:{type:'number'},specHash:hash,policyHash:hash,signedVerdict:intakeDocument,attestation:{type:['object','null'],properties:{signature:{type:'string'},recordedAt:{type:'string',format:'date-time'},expiresAt:{type:['string','null'],format:'date-time'}}},pending:{type:'boolean'},jobId:{type:'string',format:'uuid'},retryAfterSeconds:{type:'integer'},preflightOnly:{type:'boolean'},wouldAttest:{type:'boolean'},moderation:{type:'object'},txSignature:{type:['string','null']}}};
const deliverableResult = {type:'object',required:['ok','moderator','attested','verdict','attestation','signedVerdict'],properties:{ok:{const:true},moderator:{type:['string','null']},attested:{const:false},attestation:{type:'null'},verdict:result.properties.verdict,signedVerdict:signedDocument}};
const error = {type:'object',required:['ok','moderator','error','logId'],properties:{ok:{const:false},moderator:{type:'null'},error:{const:'Request could not be completed.'},logId:{type:'string',format:'uuid'},retryAfterSeconds:{type:'integer'},retryable:{type:'boolean'},code:{type:'string'}}};
const content=(schema:unknown)=>({'application/json':{schema}});
const response=(description:string,schema:unknown=result)=>({description,content:content(schema)});
const errors={
 '400':response('Malformed request or JSON depth limit',error),'401':response('Configured Desktop bearer API key required',error),
 '403':response('Creator binding or worker authentication refused',error),'404':response('Task/submission missing or stored result unavailable',error),
 '409':response('Task/hash/submission/lease conflict, expired review, changed policy or spec not retrievable',error),
 '413':response('Body exceeds 512 KiB',error),'422':response('Spec hash mismatch or invalid repository spec',error),
 '429':response('IP/creator quota or outstanding creator payment cap exceeded',error),
 '502':response('Upstream read, independent worker recheck or chain failure; retryable after reconciliation',error),
 '503':response('R/V/worker configuration, keys, roster or payment configuration unavailable',error),
};
const intake={summary:'Creator-bound task intake; custom.github enqueues repository screening',requestBody:{required:true,content:content(request)},responses:{
 '200':response('V-signed clean/hold/reject verdict, or unsigned preflight. CLEAN returns a creator-paid R-partially-signed payment offer. Creator co-signs and submits. If already paid, record.txSignature is present and transaction is absent. Repeat POST reissues only after blockhash expiry with the same signed verdict and price.'),
 '202':response('Repository scan pending: pending:true, jobId, retryAfterSeconds:5. Repeat POST after the worker report is accepted to obtain the verdict and payment offer.',{oneOf:[pending,result]}),...errors}};
const queueEnvelope={type:'object',required:['body','signature'],properties:{signature,body:{type:'object',required:['workerId','path','issuedAt','nonce','payload'],properties:{workerId:{type:'string'},path:{type:'string',enum:['/internal/worker/pull','/internal/worker/reports']},issuedAt:{type:'string',format:'date-time'},nonce:{type:'string',pattern:'^[0-9a-f]{32}$'},payload:{type:'object'}}}}};
const params=(names:string[])=>names.map(name=>({in:'path',name,required:true,schema:name==='hash'||name==='artifact'?hash:pda}));
export function openApiDocument() {
 return {openapi:'3.1.0',info:{title:SERVICE_NAME,version:SERVICE_VERSION},components:{schemas:{PaymentBinding:paymentBinding,PaymentOffer:paymentOffer,IntakeVerdict:intakeDocument,PendingJob:pending,IntakeResult:result,DeliverableResult:deliverableResult,Error:error,WorkerEnvelope:queueEnvelope}},paths:{
  '/v1/moderation/tasks':{post:intake},
  '/api/task-moderation/attest':{post:{...intake,requestBody:{required:true,content:content(compatRequest)}}},
  '/v1/moderation/deliverables':{post:{summary:'Review a submitted artifact; proofHash must equal artifactSha256',requestBody:{required:true,content:content({type:'object',required:['task','submissionPda','artifactSha256'],properties:{task:pda,submissionPda:pda,artifactSha256:hash}})},responses:{'200':response('Stored V-signed deliverable-review verdict; no chain transaction',deliverableResult),'202':response('Queued review',pending),...errors}}},
  '/v1/attestations/{task}/{hash}':{get:{parameters:params(['task','hash']),responses:{'200':response('Stored unexpired intake verdict; reconciles confirmed payment via RPC history and returns signed record.txSignature without a transaction. Unpaid offers may be returned but GET never reissues. Includes hold/reject reasons'),'404':response('Pending, unavailable or expired',error)}}},
  '/v1/deliverable-reviews/{task}/{submission}/{artifact}':{get:{parameters:params(['task','submission','artifact']),responses:{'200':response('Stored unexpired deliverable verdict',deliverableResult),'404':response('Pending, unavailable or expired',error)}}},
  '/internal/worker/pull':{post:{summary:'Worker-only signed queue request; restrict ingress to scanner droplet',description:'Sign the entire body with the report credential and agenc-worker-queue/v1 domain. Fresh 60-second request, durable nonce. payload:{}; path:/internal/worker/pull. Does not use Desktop bearer keys.',requestBody:{required:true,content:content(queueEnvelope)},responses:{'200':response('15-minute lease',{type:'object',required:['moderator','jobId','leaseToken','leaseExpiresAt','job'],properties:{moderator:{type:'null'},jobId:{type:'string',format:'uuid'},leaseToken:{type:'string',pattern:'^[0-9a-f]{48}$'},leaseExpiresAt:{type:'string',format:'date-time'},job:{type:'object'}}}),'204':{description:'No available jobs; empty body'},'403':errors['403'],'409':response('Request nonce replay',error),'503':errors['503']}}},
  '/internal/worker/reports':{post:{summary:'Worker-only report acknowledgement after durable signer recheck',description:'Queue envelope payload:{jobId,leaseToken,report:{body,signature}}. Report uses agenc-worker-report/v1. Retry exact report under a fresh transport nonce. Clean intake finalization failures remain durable and resume through Desktop POST.',requestBody:{required:true,content:content(queueEnvelope)},responses:{'200':response('Report durably accepted',{type:'object',required:['moderator','accepted','jobId'],properties:{moderator:{type:'null'},accepted:{const:true},jobId:{type:'string',format:'uuid'}}}),...errors}}},
  '/v1/keys':{get:{responses:{'200':response('Offline-root signed key manifest',{type:'object',required:['ok','moderator','manifest'],properties:{ok:{const:true},moderator:{type:'null'},manifest:signedDocument}}),'502':errors['502']}}},
  '/v1/policy':{get:{responses:{'200':{description:'Exact policy bytes',content:{'text/markdown':{schema:{type:'string'}}}}}}},
  '/v1/info':{get:{responses:{'200':response('Public configuration; repository.scannerHash commits to worker bundle/image')}}},
  '/v1/health':{get:{responses:{'200':response('Liveness')}}},
 }};
}
