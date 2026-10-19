// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
import { createHash, createPublicKey, verify as verifyBytes, type KeyObject } from 'node:crypto'
import { isDeepStrictEqual } from 'node:util'
import { verifyPreparedNode, type NodeTrust } from './agentgate_node_trust.ts'
import {
  AgentGateError, enrolledAuthoritySigner, prepareIsolatedAgent, unixAuthorityClient, validatePreparedAuditHeader, validateManifest, agentManifestDigest,
  type AgentKind, type AgentManifest, type AgentTerminal, type GateAuthorization,
  type GateBinding, type GatewayJob, type NodeRequest, type PreparedAgentRun, type PreparedJob,
} from './agentgate_gateway_policy.ts'

const hash=(value:string|Uint8Array)=>createHash('sha256').update(value).digest('hex')
const identifier=(value:unknown):value is string=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value)
const digest=(value:unknown):value is string=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value)
const decimal=(value:unknown):value is string=>typeof value==='string'&&/^[1-9][0-9]{0,19}$/.test(value)&&BigInt(value)<=18446744073709551615n
const goJSON=(value:unknown)=>JSON.stringify(value).replace(/[<>&\u2028\u2029]/g,char=>`\\u${char.charCodeAt(0).toString(16).padStart(4,'0')}`)
const sameSet=(left:unknown,right:unknown)=>Array.isArray(left)&&Array.isArray(right)&&left.every(value=>typeof value==='string')&&right.every(value=>typeof value==='string')&&new Set(left).size===left.length&&new Set(right).size===right.length&&isDeepStrictEqual([...left].sort(),[...right].sort())

export type IssueGrantRequest={protocol:'agentgate.full-job-issue.v1';manifest:AgentManifest;prepared:PreparedJob;document:unknown}
export type IssueGrantResponse={protocol:'agentgate.full-job-issued.v1';authorization:GateAuthorization}
export type AuthorityIssuer=(request:IssueGrantRequest)=>Promise<GateAuthorization>
export type AuthorityClientOptions={
 socketPath:string;authorityUID:number;authorityID:string;authorityEpoch:string
 agentID:string;agentKey:string;privateKey:KeyObject
 publicKeys:Record<string,string>;timeoutMS:number;nodeTrust:NodeTrust
 now?:()=>{wallSeconds:number;monotonicNS:bigint}
}
function authorityKeys(values:Record<string,string>):Map<string,KeyObject>{
 const keys=new Map<string,KeyObject>()
 if(!values||Object.keys(values).length===0||Object.keys(values).length>32)throw new AgentGateError('agentgate-authority-trust-missing')
 for(const [id,value]of Object.entries(values)){
  if(!identifier(id)||typeof value!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(value))throw new AgentGateError('agentgate-authority-key-invalid')
  const bytes=Buffer.from(value,'base64url')
  if(bytes.length!==32||bytes.toString('base64url')!==value)throw new AgentGateError('agentgate-authority-key-invalid')
  keys.set(id,createPublicKey({format:'der',type:'spki',key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),bytes])}))
 }
 return keys
}
function verifyIssued(authorization:GateAuthorization,input:IssueGrantRequest,options:AuthorityClientOptions,keys:Map<string,KeyObject>):void{
 const binding=input.prepared.binding
 if(!authorization||!isDeepStrictEqual(authorization.binding,binding)||!sameSet(authorization.required_capabilities,(input.document as any)?.required_capabilities)||!isDeepStrictEqual(authorization.document,input.document)||typeof authorization.grant!=='string'||authorization.grant.length>32768)throw new AgentGateError('agentgate-authority-binding-differs')
 let grant:any
 try{grant=JSON.parse(authorization.grant)}catch{throw new AgentGateError('agentgate-authority-grant-invalid')}
 const claims=grant?.claims;const publicKey=keys.get(grant?.key_id)
 if(!publicKey||grant.protocol!=='agentgate.full-job-grant.v1'||grant.authority_id!==options.authorityID||goJSON(grant)!==authorization.grant||!claims||Object.keys(grant).some(key=>!['protocol','authority_id','key_id','claims','signature'].includes(key))||Object.keys(claims).some(key=>!['binding','document_digest','required_capabilities','qualification_digest','audit_header_digest','issued_at','not_before','expires_at','issued_mono_ns','deadline_ns'].includes(key)))throw new AgentGateError('agentgate-authority-grant-invalid')
 const signature=typeof grant.signature==='string'?Buffer.from(grant.signature,'base64url'):Buffer.alloc(0)
 const unsigned={...grant,signature:''}
 if(signature.length!==64||signature.toString('base64url')!==grant.signature||!verifyBytes(null,Buffer.from('AGENTGATE_FULL_JOB_GRANT_V1\n'+goJSON(unsigned)),publicKey,signature))throw new AgentGateError('agentgate-authority-signature-invalid')
 const header=JSON.parse(Buffer.from(input.prepared.audit_header,'base64').toString('utf8'))
 if(!isDeepStrictEqual(claims.binding,binding)||claims.document_digest!==binding.policy_digest||claims.deadline_ns!==binding.deadline_ns||claims.issued_mono_ns!==input.prepared.prepared_mono_ns||claims.audit_header_digest!==input.prepared.audit_header_digest||claims.qualification_digest!==header.qualification_digest||!sameSet(claims.required_capabilities,authorization.required_capabilities)||hash(goJSON(input.document))!==binding.policy_digest)throw new AgentGateError('agentgate-authority-binding-differs')
 const time=options.now?.()??{wallSeconds:Math.floor(Date.now()/1000),monotonicNS:process.hrtime.bigint()}
 const duration=(input.document as any)?.lifecycle?.duration_seconds
 if(!Number.isSafeInteger(time.wallSeconds)||!Number.isSafeInteger(duration)||duration<1||duration>86400||![claims.issued_at,claims.not_before,claims.expires_at].every(Number.isSafeInteger)||claims.issued_at<0||claims.not_before<claims.issued_at||claims.expires_at<=claims.not_before||claims.expires_at-claims.issued_at>duration||claims.expires_at>input.prepared.prepared_at_unix+Number((BigInt(binding.deadline_ns)-BigInt(input.prepared.prepared_mono_ns))/1000000000n)||time.wallSeconds<claims.not_before||time.wallSeconds>=claims.expires_at||!decimal(claims.issued_mono_ns)||!decimal(claims.deadline_ns)||BigInt(claims.issued_mono_ns)>time.monotonicNS||time.monotonicNS>=BigInt(claims.deadline_ns)||BigInt(claims.deadline_ns)<=BigInt(claims.issued_mono_ns)||BigInt(claims.deadline_ns)-BigInt(claims.issued_mono_ns)>BigInt(duration)*1000000000n||BigInt(claims.issued_mono_ns)<BigInt(header.created_mono_ns))throw new AgentGateError('agentgate-authority-grant-expired')
}
// The issuer carries the agent request key. It never receives an authority signer key.
export function createAuthorityIssuer(options:AuthorityClientOptions,request?:NodeRequest):AuthorityIssuer{
 const keys=authorityKeys(options.publicKeys)
 const client=request??unixAuthorityClient({socketPath:options.socketPath,nodeUID:options.authorityUID,timeoutMS:options.timeoutMS,sign:enrolledAuthoritySigner(options)})
 return async input=>{
  const body=structuredClone(input)
  if(body.protocol!=='agentgate.full-job-issue.v1'||body.manifest.agent_kind===undefined||body.prepared.protocol!=='agentgate.job.prepared.v1'||body.prepared.binding.agent_id!==options.agentID||body.prepared.binding.agent_key!==options.agentKey||!digest(body.prepared.audit_header_digest)||(body.document as any)?.profile!=='kernel-policy.v2')throw new AgentGateError('agentgate-authority-request-invalid')
  validateManifest(body.manifest)
  if(agentManifestDigest(body.manifest)!==body.prepared.binding.job_digest)throw new AgentGateError('agentgate-authority-request-invalid')
  validatePreparedAuditHeader(body.prepared,(body.document as any).required_capabilities)
  try{verifyPreparedNode(body.prepared,body.prepared.binding,options.nodeTrust)}catch{throw new AgentGateError('agentgate-node-preparation-untrusted')}
  const response=await client('POST','/v1/grants/issue',body) as IssueGrantResponse
  if(response?.protocol!=='agentgate.full-job-issued.v1')throw new AgentGateError('agentgate-authority-response-invalid')
  verifyIssued(response.authorization,body,options,keys)
  return structuredClone(response.authorization)
 }
}

export type ManagedJobRequest={schema:string;job_id:string;input:{type:'text';text:string}[];agentgate:{policy_digest:string};reply_to?:string;thread_key?:string;stream_topic?:string|null}
export type ManagedJobContext={from:string;correlationID:string}
export type ManagedJobPlan={job:GatewayJob;document:unknown}
export type GatewayLedger={
 reserve(jobID:string):Promise<boolean>
 start(jobID:string):Promise<boolean>
 reject(jobID:string,delivered:boolean):Promise<void>
 finish(jobID:string,state:'completed'|'failed'|'cancelled',delivered:boolean):Promise<void>
 fail(reason:string):Promise<void>
}
export type ManagedGatewayOptions={
 kind:AgentKind;agentID:string;policyDigest:string;allowedRequesters:readonly string[]
 node:NodeRequest;issue:AuthorityIssuer;ledger:GatewayLedger;nodeTrust:NodeTrust
 plan:(request:ManagedJobRequest,context:ManagedJobContext)=>Promise<ManagedJobPlan>
 send:(to:string,body:Record<string,unknown>,correlationID:string)=>Promise<boolean>
}
export function isManagedJob(value:unknown):boolean{
 const body=value as any
 return !!body&&typeof body==='object'&&(Object.hasOwn(body,'agentgate')||body.execution_mode==='managed'||typeof body.schema==='string'&&body.schema.startsWith('agentgate.'))
}
export const UNMANAGED_EXECUTION={execution_mode:'unmanaged',agentgate_qualified:false} as const
export function unmanagedGatewayReply(body:any):any {return body&&typeof body==='object'&&typeof body.schema==='string'&&/^(codex|claude)\.job\./.test(body.schema)?{...body,...UNMANAGED_EXECUTION}:body}
function checkRequest(body:ManagedJobRequest,context:ManagedJobContext,options:ManagedGatewayOptions):void{
 if(!body||body.schema!==`${options.kind}.job.request.v1`||!identifier(body.job_id)||!body.agentgate||Object.keys(body.agentgate).some(key=>key!=='policy_digest')||body.agentgate.policy_digest!==options.policyDigest||!Array.isArray(body.input)||body.input.length===0||body.input.some(item=>!item||item.type!=='text'||typeof item.text!=='string'||Object.keys(item).some(key=>!['type','text'].includes(key)))||Buffer.byteLength(body.input.map(item=>item.text).join('\n'))>1<<20)throw new AgentGateError('agentgate-managed-request-invalid')
 if(!options.allowedRequesters.includes(context.from)||body.reply_to!==undefined&&body.reply_to!==context.from&&!options.allowedRequesters.includes(body.reply_to))throw new AgentGateError('agentgate-requester-denied')
 if(body.thread_key!==undefined||body.stream_topic!==undefined&&body.stream_topic!==null||Object.keys(body).some(key=>!['schema','job_id','input','agentgate','reply_to','stream_topic'].includes(key)))throw new AgentGateError('agentgate-feature-unsupported')
}
function decodeOutput(kind:AgentKind,terminal:AgentTerminal):string{
 if(!terminal.output)throw new AgentGateError('agentgate-agent-output-missing')
 const raw=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.from(terminal.output,'base64'))
 let result='';let ended=false
 for(const line of raw.split('\n').filter(line=>line.trim())){
  let event:any;try{event=JSON.parse(line)}catch{throw new AgentGateError('agentgate-agent-output-invalid')}
  if(kind==='codex'){
   if(event.type==='item.completed'&&event.item?.type==='agent_message'&&typeof event.item.text==='string')result+=event.item.text
   if(event.type==='turn.completed')ended=true
   if(event.type==='turn.failed'||event.type==='error')throw new AgentGateError('agentgate-agent-turn-failed')
  }else if(kind==='claude'){
   if(event.type==='result'){if(event.subtype!=='success'||event.is_error!==false||typeof event.result!=='string')throw new AgentGateError('agentgate-agent-turn-failed');result=event.result;ended=true}
  }else if(event.type==='message_end'&&event.message?.role==='assistant'){
   if(event.message.stopReason==='error'||event.message.stopReason==='aborted')throw new AgentGateError('agentgate-agent-turn-failed')
   const text=event.message.content?.filter((item:any)=>item.type==='text').map((item:any)=>item.text)
   if(!Array.isArray(text)||text.some(value=>typeof value!=='string'))throw new AgentGateError('agentgate-agent-output-invalid')
   result=text.join('');ended=true
  }
 }
 if(!ended)throw new AgentGateError('agentgate-agent-output-incomplete')
 return result
}
// This router owns no local process API. Every managed turn uses a fresh node run.
export class ManagedGateway {
 private readonly options:ManagedGatewayOptions
 private readonly active=new Map<string,{owner:string;prepared?:PreparedAgentRun;preparing?:Promise<PreparedAgentRun>;cancelled:boolean}>()
 private readonly pending=new Set<Promise<void>>()
 private closing=false
 constructor(options:ManagedGatewayOptions){
  if(!['codex','claude','pi'].includes(options.kind)||!identifier(options.agentID)||!digest(options.policyDigest)||!Array.isArray(options.allowedRequesters)||options.allowedRequesters.length===0||options.allowedRequesters.length>64||options.allowedRequesters.some(id=>!identifier(id)))throw new AgentGateError('agentgate-managed-config-invalid')
  this.options={...options,allowedRequesters:[...options.allowedRequesters]}
 }
 handle(body:ManagedJobRequest,context:ManagedJobContext):Promise<void>{
  const operation=this.perform(body,context)
  this.pending.add(operation)
  void operation.finally(()=>this.pending.delete(operation)).catch(()=>{})
  return operation
 }
 private async send(to:string,body:Record<string,unknown>,correlationID:string):Promise<boolean>{try{return await this.options.send(to,body,correlationID)}catch{return false}}
 private async perform(body:ManagedJobRequest,context:ManagedJobContext):Promise<void>{
  const o=this.options;const jobID=typeof body?.job_id==='string'?body.job_id:'';const recipient=body?.reply_to??context.from
  let reserved=false;let prepared:PreparedAgentRun|undefined;let accepted=false
  const slot:{owner:string;prepared?:PreparedAgentRun;preparing?:Promise<PreparedAgentRun>;cancelled:boolean}={owner:context.from,cancelled:false}
  try{
   if(this.closing)throw new AgentGateError('agentgate-gateway-closed')
   checkRequest(body,context,o)
   if(this.active.has(jobID))throw new AgentGateError('agentgate-job-replay')
   if(!await o.ledger.reserve(jobID))throw new AgentGateError('agentgate-capacity-unavailable')
   reserved=true;this.active.set(jobID,slot)
   const plan=await o.plan(structuredClone(body),{...context})
   if(this.closing||slot.cancelled)throw new AgentGateError('agentgate-job-cancelled')
   if(plan.job.manifest.agent_kind!==o.kind||plan.job.binding.agent_id!==o.agentID||plan.job.binding.policy_digest!==o.policyDigest||hash(plan.job.input)!==hash(body.input.map(item=>item.text).join('\n')))throw new AgentGateError('agentgate-managed-plan-differs')
   slot.preparing=prepareIsolatedAgent(plan.job,o.node,prepared=>o.issue({protocol:'agentgate.full-job-issue.v1',manifest:plan.job.manifest,prepared,document:plan.document}),o.nodeTrust)
   prepared=await slot.preparing;slot.prepared=prepared
   if(this.closing||slot.cancelled)throw new AgentGateError('agentgate-job-cancelled')
   accepted=await this.send(recipient,{schema:`${o.kind}.job.accepted.v1`,job_id:jobID,execution_mode:'managed',agentgate:{run_id:prepared.binding.run_id,policy_digest:o.policyDigest,audit_header_digest:prepared.auditHeaderDigest}},context.correlationID)
   if(!accepted){await prepared.stop('gateway-acceptance-failed');await o.ledger.reject(jobID,false);return}
   if(!await o.ledger.start(jobID))throw new AgentGateError('agentgate-lifecycle-start-failed')
   const terminal=await prepared.run()
   const completed=terminal.state==='completed'&&terminal.exit_code===0
   const cancelled=terminal.state==='cancelled'||terminal.state==='revoked'
   const schema=`${o.kind}.job.${completed?'completed':cancelled?'cancelled':'failed'}.v1`
   const text=completed?decodeOutput(o.kind,terminal):''
   const delivered=await this.send(recipient,{schema,job_id:jobID,execution_mode:'managed',...(completed?{output:[{type:'text',text}]}:{error:`agentgate-${terminal.state}`}),agentgate:{binding:terminal.binding,evidence_digest:terminal.evidence_digest,evidence_verdict:terminal.evidence_verdict,domain_empty:terminal.domain_empty,rights_removed:terminal.rights_removed}},context.correlationID)
   await o.ledger.finish(jobID,completed?'completed':cancelled?'cancelled':'failed',delivered)
  }catch(error){
   let cleanup=!(error instanceof AgentGateError&&error.cleanupConfirmed===false)
   if(!cleanup){this.closing=true;await o.ledger.fail('agentgate-cleanup-unconfirmed')}
   try{await prepared?.stop('gateway-route-failed')}catch{cleanup=false;this.closing=true;await o.ledger.fail('agentgate-cleanup-unconfirmed')}
   const code=error instanceof AgentGateError?error.code:'agentgate-managed-node-unavailable'
   const delivered=await this.send(context.from,{schema:`${o.kind}.job.${accepted?(slot.cancelled?'cancelled':'failed'):'rejected'}.v1`,job_id:jobID||null,execution_mode:'managed',reason:code,cleanup_confirmed:cleanup},context.correlationID)
   if(reserved){if(accepted)await o.ledger.finish(jobID,slot.cancelled?'cancelled':'failed',delivered);else await o.ledger.reject(jobID,delivered)}
  }finally{if(this.active.get(jobID)===slot)this.active.delete(jobID)}
 }
 async cancel(jobID:string,from:string):Promise<boolean>{
  const run=this.active.get(jobID)
  if(!run||run.owner!==from)return false
  run.cancelled=true
  if(!run.preparing)return true
  try{const prepared=await run.preparing;await prepared.stop('gateway-job-cancelled');return true}catch{return false}
 }
 async shutdown():Promise<void>{
  this.closing=true
  let timer:ReturnType<typeof setTimeout>|undefined
  const work=async()=>{
   const stops=await Promise.allSettled([...this.active.values()].map(run=>run.prepared?.stop('gateway-shutdown')))
   await Promise.allSettled([...this.pending])
   if(stops.some(result=>result.status==='rejected'))throw new AgentGateError('agentgate-shutdown-unconfirmed')
  }
  try{
   await Promise.race([work(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new AgentGateError('agentgate-shutdown-unconfirmed')),1000)})])
  }catch{await this.options.ledger.fail('agentgate-shutdown-unconfirmed');throw new AgentGateError('agentgate-shutdown-unconfirmed')}
  finally{if(timer)clearTimeout(timer)}

 }
}
