// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
import { constants } from 'node:fs'
import { lstat, open, readFile, realpath } from 'node:fs/promises'
import { dirname, isAbsolute, normalize } from 'node:path'
import { createHash, createPrivateKey, createPublicKey, randomUUID } from 'node:crypto'
import { AgentGateError, agentManifestDigest, enrolledNodeSigner, unixNodeClient, validateManifest, type AgentKind, type AgentManifest, type GateBinding, type NodeRequest } from './agentgate_gateway_policy.ts'
import { createAuthorityIssuer, ManagedGateway, type ManagedJobRequest, type ManagedJobPlan, type AuthorityIssuer } from './agentgate_gateway_runtime.ts'
import { verifyNodeInventory, type NodeInventory, type NodeTrust } from './agentgate_node_trust.ts'

export type ManagedGatewayConfig = {
 protocol:'agentgate.gateway.config.v1';kind:AgentKind;agent_id:string
 node_id:string;node_socket:string;node_uid:number;node_public_keys:Record<string,string>
 authority_id:string;authority_epoch:string;authority_socket:string;authority_uid:number;authority_public_keys:Record<string,string>
 agent_private_key_file:string;approved_document_file:string;policy_digest:string;schema_digest:string
 compiler_digest:string;artifact_digests:Record<string,string>;allowed_requesters:string[]
 runtime:Omit<AgentManifest,'protocol'|'agent_kind'|'input_digest'>
 ssh_identity?:{user:string;uid:number;gid:number}
}
export type ManagedChannel = {
 readonly signingEnabled:boolean
 start():Promise<void>;isStarted():boolean;markWorkerReady():Promise<void>;stop():Promise<void>
 queueWorkerJob(id:string):Promise<{ok:true}|{ok:false;reason:string}>
 startWorkerJob(id:string):Promise<boolean>;rejectWorkerJob(id:string,delivered:boolean):Promise<void>
 finishWorkerJob(id:string,state:'completed'|'failed'|'cancelled',delivered:boolean):Promise<void>
 failWorker(reason:string):Promise<void>;drainWorker(reason:'shutdown'):Promise<void>
 sendTerminalReply(args:{to:string;body:string;corr:string}):Promise<any>
}
type ChannelFactory=(receive:(content:string,attrs:any)=>Promise<void>,options:{enabled:true;agentId:string;workerMaxActive:number;workerMaxQueue:number})=>ManagedChannel
export type ManagedBootstrapDependencies={
 load?:(path:string)=>Promise<{config:ManagedGatewayConfig;document:any;privateKey:ReturnType<typeof createPrivateKey>}>
 bootID?:()=>Promise<string>;node?:(config:ManagedGatewayConfig,boot:string,agentKey:string,privateKey:ReturnType<typeof createPrivateKey>)=>NodeRequest
 issue?:AuthorityIssuer;nowWall?:()=>number;runID?:()=>string
}
const hash=(value:string|Uint8Array)=>createHash('sha256').update(value).digest('hex')
const id=(value:unknown):value is string=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value)
const digest=(value:unknown):value is string=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value)
const pathOK=(path:unknown):path is string=>typeof path==='string'&&isAbsolute(path)&&normalize(path)===path&&path!=='/'&&path!=='/tmp'&&!path.startsWith('/tmp/')
const goJSON=(value:unknown)=>JSON.stringify(value).replace(/[<>&\u2028\u2029]/g,char=>`\\u${char.charCodeAt(0).toString(16).padStart(4,'0')}`)
function configError():never {throw new AgentGateError('agentgate-managed-config-invalid')}
async function protectedBytes(path:string,limit:number):Promise<Buffer>{
 if(!pathOK(path))configError()
 let parent=dirname(path)
 while(true){
  const stat=await lstat(parent)
  if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==0||stat.mode&0o022||await realpath(parent)!==parent)configError()
  if(parent==='/')break
  parent=dirname(parent)
 }
 const file=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW)
 try{
  const stat=await file.stat()
  if(!stat.isFile()||stat.uid!==0||stat.nlink!==1||stat.mode&0o027||stat.size<1||stat.size>limit)configError()
  const bytes=await file.readFile()
  const after=await file.stat()
  if(bytes.length!==stat.size||after.size!==stat.size||after.mtimeMs!==stat.mtimeMs||after.ctimeMs!==stat.ctimeMs)configError()
  return bytes
 }finally{await file.close()}
}
function validateConfig(c:ManagedGatewayConfig):void{
 const keys=['protocol','kind','agent_id','node_id','node_socket','node_uid','node_public_keys','authority_id','authority_epoch','authority_socket','authority_uid','authority_public_keys','agent_private_key_file','approved_document_file','policy_digest','schema_digest','compiler_digest','artifact_digests','allowed_requesters','runtime','ssh_identity']
 if(!c||Object.keys(c).some(key=>!keys.includes(key))||c.protocol!=='agentgate.gateway.config.v1'||!['codex','claude','pi','ssh'].includes(c.kind)||![c.agent_id,c.node_id,c.authority_id,c.authority_epoch].every(id)||![c.node_socket,c.authority_socket,c.agent_private_key_file,c.approved_document_file].every(pathOK)||![c.node_uid,c.authority_uid].every(n=>Number.isSafeInteger(n)&&n>=0)||![c.policy_digest,c.schema_digest,c.compiler_digest].every(digest)||!c.artifact_digests||Object.keys(c.artifact_digests).length===0||Object.keys(c.artifact_digests).length>64||!Object.entries(c.artifact_digests).every(([key,value])=>id(key)&&digest(value))||!Array.isArray(c.allowed_requesters)||c.allowed_requesters.length>64||c.allowed_requesters.some(value=>!id(value))||(c.kind!=='ssh'&&c.allowed_requesters.length===0))configError()
 if(c.kind==='ssh'){
  const identity=c.ssh_identity
  if(!identity||Object.keys(identity).some(key=>!['user','uid','gid'].includes(key))||!id(identity.user)||!Number.isSafeInteger(identity.uid)||identity.uid<1||!Number.isSafeInteger(identity.gid)||identity.gid<1||!Array.isArray(c.runtime?.arguments)||c.runtime.arguments.length!==2||c.runtime.arguments[0]!=='-c'||c.runtime.arguments[1]!==':')configError()
 }else if(c.ssh_identity!==undefined)configError()
 validateManifest({...c.runtime,protocol:'agentgate.job.manifest.v1',agent_kind:c.kind,input_digest:c.kind==='ssh'?hash(new Uint8Array()):'0'.repeat(64)})
 // Provider secrets belong to the node's sealed credential descriptors.
 if(Object.keys(c.runtime.environment).some(name=>/(?:^|_)(?:API_KEY|TOKEN|PASSWORD|SECRET|PRIVATE_KEY)$/.test(name)))configError()
}
export async function loadManagedGatewayConfig(path:string):Promise<{config:ManagedGatewayConfig;document:any;privateKey:ReturnType<typeof createPrivateKey>}>{
 const text=(await protectedBytes(path,131072)).toString('utf8')
 const config=JSON.parse(text) as ManagedGatewayConfig
 // This also rejects duplicate and case-aliased fields before any transport effect.
 if(JSON.stringify(config)!==text.trim())configError()
 validateConfig(config)
 const raw=(await protectedBytes(config.approved_document_file,1<<20)).toString('utf8').trim()
 const document=JSON.parse(raw)
 if(goJSON(document)!==raw||hash(raw)!==config.policy_digest||document.profile!=='kernel-policy.v2'||!Array.isArray(document.required_capabilities)||document.required_capabilities.length===0||document.required_capabilities.length>64||!Number.isSafeInteger(document.lifecycle?.duration_seconds)||document.lifecycle.duration_seconds<1||document.lifecycle.duration_seconds>86400)configError()
 const privateKey=createPrivateKey(await protectedBytes(config.agent_private_key_file,16384))
 if(privateKey.asymmetricKeyType!=='ed25519')configError()
 return {config,document,privateKey}
}
function verifyInventory(i:NodeInventory,c:ManagedGatewayConfig,boot:string,document:any,trust:NodeTrust):void{
 try{verifyNodeInventory(i,{nodeID:c.node_id,bootID:boot,schemaDigest:c.schema_digest},trust)}catch{throw new AgentGateError('agentgate-node-inventory-untrusted')}
 if(i.compiler_digest!==c.compiler_digest||Object.entries(c.artifact_digests).some(([key,value])=>i.artifact_digests[key]!==value))throw new AgentGateError('agentgate-node-artifacts-differ')
 for(const cap of document.required_capabilities){const result=i.target_report.capabilities?.[cap];if(result?.state!=='enforced'||!digest(result.receipt_sha256)||!Array.isArray(result.mechanisms)||result.mechanisms.length===0)throw new AgentGateError('agentgate-capability-unqualified')}
}
export type ManagedAdmission={config:ManagedGatewayConfig;node:NodeRequest;issue:AuthorityIssuer;nodeTrust:NodeTrust;plan(request:ManagedJobRequest):Promise<ManagedJobPlan>;planSSHCommand(command:string):Promise<ManagedJobPlan>}
// This controller opens only authenticated transports. The node owns agent execution.
export async function openManagedGatewayAdmission(kind:AgentKind,env:Record<string,string|undefined>,deps:ManagedBootstrapDependencies={}):Promise<ManagedAdmission>{
 if(!env.AGENTGATE_MANAGED_CONFIG)throw new AgentGateError('agentgate-managed-config-missing')
 const {config:c,document,privateKey}=await(deps.load??loadManagedGatewayConfig)(env.AGENTGATE_MANAGED_CONFIG)
 validateConfig(c)
 if(c.kind!==kind||env.A2A_AGENT_ID&&env.A2A_AGENT_ID!==c.agent_id)configError()
 const boot=(await(deps.bootID??(()=>readFile('/proc/sys/kernel/random/boot_id','utf8')))()).trim()
 if(!id(boot))throw new AgentGateError('agentgate-local-boot-unavailable')
 const agentKey=createPublicKey(privateKey).export({format:'jwk'}).x!
 const nodeTrust:NodeTrust={publicKeys:c.node_public_keys,maxAgeSeconds:30,nowWall:deps.nowWall}
 const node=deps.node?.(c,boot,agentKey,privateKey)??unixNodeClient({socketPath:c.node_socket,nodeUID:c.node_uid,timeoutMS:Math.min(document.lifecycle.duration_seconds*1000+10000,86400000),sign:enrolledNodeSigner({agentID:c.agent_id,agentKey,privateKey,nodeID:c.node_id,bootID:boot})})
 const inventory=async()=>{const value=await node('GET','/v1/node/inventory') as NodeInventory;verifyInventory(value,c,boot,document,nodeTrust);return value}
 await inventory()
 const issue=deps.issue??createAuthorityIssuer({socketPath:c.authority_socket,authorityUID:c.authority_uid,authorityID:c.authority_id,authorityEpoch:c.authority_epoch,agentID:c.agent_id,agentKey,privateKey,publicKeys:c.authority_public_keys,timeoutMS:10000,nodeTrust})
 const buildPlan=async(input:Buffer,command?:string):Promise<ManagedJobPlan>=>{
   const i=await inventory()
   const floor=await node('GET',`/v1/agents/${encodeURIComponent(c.agent_id)}/generation`) as any
   if(floor?.protocol!=='agentgate.agent-generation.v1'||floor.agent_id!==c.agent_id||floor.node_id!==c.node_id||floor.boot_id!==boot||typeof floor.generation!=='string'||!/^(0|[1-9][0-9]*)$/.test(floor.generation)||BigInt(floor.generation)>=9223372036854775807n)throw new AgentGateError('agentgate-generation-unavailable')
   const manifest:AgentManifest={...structuredClone(c.runtime),protocol:'agentgate.job.manifest.v1',agent_kind:kind,input_digest:hash(input)}
   if(command!==undefined)manifest.arguments=['-c',command]
   const runID=deps.runID?.()??randomUUID()
   const binding:GateBinding={agent_id:c.agent_id,agent_key:agentKey,job_digest:agentManifestDigest(manifest),grant_id:randomUUID(),run_id:runID,node_id:c.node_id,boot_id:boot,policy_digest:c.policy_digest,schema_digest:c.schema_digest,compiler_digest:i.compiler_digest,artifact_digests:{...i.artifact_digests},cgroup_id:'0',generation:(BigInt(floor.generation)+1n).toString(),deadline_ns:(BigInt(i.mono_ns)+BigInt(document.lifecycle.duration_seconds)*1000000000n).toString()}
   return{job:{manifest,binding,input,requiredCapabilities:[...document.required_capabilities]},document:structuredClone(document)}
 }
 return{config:c,node,issue,nodeTrust,
  plan:async request=>{if(kind==='ssh')configError();return buildPlan(Buffer.from(request.input.map(item=>item.text).join('\n')))},
  planSSHCommand:async command=>{
   if(kind!=='ssh'||typeof command!=='string'||command.length===0||Buffer.byteLength(command)>16384||command.includes('\0'))throw new AgentGateError('agentgate-ssh-command-invalid')
   return buildPlan(Buffer.alloc(0),command)
  },
 }
}
export async function startManagedGateway(kind:AgentKind,env:Record<string,string|undefined>,factory:ChannelFactory,deps:ManagedBootstrapDependencies={}):Promise<{shutdown():Promise<void>}> {
 if(kind==='ssh')throw new AgentGateError('agentgate-ssh-transport-required')
 const admission=await openManagedGatewayAdmission(kind,env,deps)
 const {config:c,node,issue,nodeTrust}=admission
 let gateway:ManagedGateway
 let failed=false
 const channel=factory(async(content,attrs)=>{
  if(attrs?.feed!=='a2a'||attrs.kind!=='direct'||attrs.type!=='request'||!id(attrs.from)||!id(attrs.id))return
  let body:any;try{body=JSON.parse(content)}catch{body={}}
  if(body?.schema===`${kind}.job.cancel.v1`){
   const ok=await gateway.cancel(body.job_id,attrs.from)
   await channel.sendTerminalReply({to:attrs.from,corr:attrs.id,body:JSON.stringify({schema:`${kind}.job.cancel.${ok?'accepted':'rejected'}.v1`,job_id:body.job_id??null,execution_mode:'managed'})})
   return
  }
  // Each operation stays tracked by ManagedGateway. The inbox can receive cancellation.
  void gateway.handle(body as ManagedJobRequest,{from:attrs.from,correlationID:attrs.id}).catch(async()=>{failed=true;await channel.failWorker('agentgate-route-failed')})
 },{enabled:true,agentId:c.agent_id,workerMaxActive:1,workerMaxQueue:0})
 if(!channel.signingEnabled)throw new AgentGateError('agentgate-bus-signing-required')
 gateway=new ManagedGateway({kind,agentID:c.agent_id,policyDigest:c.policy_digest,allowedRequesters:c.allowed_requesters,node,issue,nodeTrust,
  ledger:{reserve:async id=>(await channel.queueWorkerJob(id)).ok,start:id=>channel.startWorkerJob(id),reject:(id,delivered)=>channel.rejectWorkerJob(id,delivered),finish:(id,state,delivered)=>channel.finishWorkerJob(id,state,delivered),fail:async reason=>{failed=true;await channel.failWorker(reason)}},
  send:async(to,body,corr)=>{const response=await channel.sendTerminalReply({to,body:JSON.stringify(body),corr});try{return JSON.parse(response?.content?.[0]?.text).ok===true}catch{return false}},
  plan:async request=>{
   if(failed)throw new AgentGateError('agentgate-gateway-closed')
   return admission.plan(request)
  },
 })
 try{
  await channel.start()
  if(!channel.isStarted())throw new AgentGateError('agentgate-bus-unavailable')
  await channel.markWorkerReady()
 }catch(error){await channel.stop();throw error}
 return {async shutdown(){await channel.drainWorker('shutdown');try{await gateway.shutdown()}finally{await channel.stop()}}}
}

// The node owns every child. Shutdown only drains the bus and requests domain stops.
export function installManagedShutdown(runtime:{shutdown():Promise<void>}):void {
 for(const signal of ['SIGTERM','SIGINT'] as const)process.once(signal,()=>{
  void runtime.shutdown().then(()=>process.exit(0),()=>process.exit(1))
 })
}
