// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Isolated job admission for Codex, Claude and pi. This module never spawns an agent.
import { createHash, createPublicKey, randomBytes, randomUUID, sign as signBytes, type KeyObject } from 'node:crypto'
import { request as httpRequest } from 'node:http'
import { lstat, realpath } from 'node:fs/promises'
import { dirname, isAbsolute, normalize } from 'node:path'
import { verifyPreparedNode, type NodeTrust } from './agentgate_node_trust.ts'

export type AgentKind = 'codex' | 'claude' | 'pi' | 'ssh'
export type AgentManifest = {
  protocol: 'agentgate.job.manifest.v1'
  agent_kind: AgentKind
  runtime_version: string
  executable: string
  executable_digest: string
  image_digest: string
  arguments: string[]
  workspace: string
  environment: Record<string, string>
  input_digest: string
}
export type GateBinding = {
  agent_id: string; agent_key: string; job_digest: string; grant_id: string; run_id: string
  node_id: string; boot_id: string; policy_digest: string; schema_digest: string
  compiler_digest: string; artifact_digests: Record<string, string>
  cgroup_id: string; generation: string; deadline_ns: string
}
export type GateAuthorization = {
  binding: GateBinding; grant: string; document: unknown; required_capabilities: string[]
}
export type GateEvidence = {
  binding: GateBinding; phase: string; quarantined: boolean; released: boolean; terminated: boolean
  readback_digest: string; mandatory_hooks: boolean; empty: boolean; rights_removed: boolean
  decisions: string; lost: string; digest: string; no_domain?:boolean; counters_available?:boolean
  capabilities: Record<string, { state: string; mechanisms: string[]; evidence_digest: string }>
  process?: {pid:number;start_time_ticks:string;barrier_id:string}
}
export type PreparedJob = {
  preparation_key_id: string; preparation_signature: string; prepared_at_unix: number; prepared_mono_ns: string
  protocol: 'agentgate.job.prepared.v1'; binding: GateBinding; manifest_digest: string
  preparation_deadline_ns: string; audit_header: string; audit_header_digest: string; evidence: GateEvidence
}
export type AgentTerminal = {
  protocol: 'agentgate.job.terminal.v1'; binding: GateBinding
  state: 'completed' | 'failed' | 'cancelled' | 'expired' | 'revoked' | 'aborted'
  exit_code: number; domain_empty: boolean; rights_removed: boolean
  evidence_digest: string; evidence_verdict: string; output?: string; output_digest?: string; stderr?: string; stderr_digest?: string
}
export type GatewayJob = {
  manifest: AgentManifest; binding: GateBinding; input: Uint8Array; requiredCapabilities: string[]
}
export type NodeProofInput = { method: string; path: string; body: Uint8Array; bodyDigest: string }
export type NodeRequest = (method: string, path: string, body?: unknown) => Promise<unknown>
export class AgentGateError extends Error {
  constructor(readonly code: string,readonly cleanupConfirmed?:boolean) { super(code); this.name = 'AgentGateError' }
}
const hash = (value: string | Uint8Array) => createHash('sha256').update(value).digest('hex')
const digest = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)
const identifier = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value)
function canonical(value: any): string {
  if (!value || typeof value !== 'object') return JSON.stringify(value) ?? 'undefined'
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']'
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}'
}
const same = (left: unknown, right: unknown) => canonical(left) === canonical(right)
function decimal(value: unknown, zero = false): value is string {
  return typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value)
    && BigInt(value) <= 18446744073709551615n && (zero || BigInt(value) > 0n)
}
function validText(value: unknown): value is string {
  if (typeof value !== 'string' || value.includes('\0')) return false
  for (let i = 0; i < value.length; i++) {
    const char = value.charCodeAt(i)
    if (char >= 0xd800 && char <= 0xdbff) { const next = value.charCodeAt(++i); if (!(next >= 0xdc00 && next <= 0xdfff)) return false }
    else if (char >= 0xdc00 && char <= 0xdfff) return false
  }
  return true
}
function safePath(value: string) {
  return validText(value) && isAbsolute(value) && normalize(value) === value && value !== '/' && value !== '/tmp' && !value.startsWith('/tmp/')
}
export function validateManifest(manifest: AgentManifest): void {
  if (!manifest || Object.keys(manifest).some(key => !['protocol','agent_kind','runtime_version','executable','executable_digest','image_digest','arguments','workspace','environment','input_digest'].includes(key)) || manifest.protocol !== 'agentgate.job.manifest.v1' || !['codex', 'claude', 'pi', 'ssh'].includes(manifest.agent_kind)
    || !validText(manifest.runtime_version) || !manifest.runtime_version || Buffer.byteLength(manifest.runtime_version) > 128 || /[\r\n]/.test(manifest.runtime_version)
    || !safePath(manifest.executable) || !safePath(manifest.workspace)
    || !digest(manifest.executable_digest) || !/^sha256:[a-f0-9]{64}$/.test(manifest.image_digest) || !digest(manifest.input_digest)
    || !Array.isArray(manifest.arguments) || manifest.arguments.length > 128 || manifest.arguments.some(arg => !validText(arg))
    || !manifest.environment || typeof manifest.environment !== 'object' || Array.isArray(manifest.environment)
    || Object.keys(manifest.environment).length > 64) throw new AgentGateError('agentgate-invalid-manifest')
  let bytes = manifest.arguments.reduce((total, arg) => total + Buffer.byteLength(arg), 0)
  for (const [key, value] of Object.entries(manifest.environment)) {
    if (!/^[A-Z_][A-Z0-9_]{0,127}$/.test(key) || !validText(value)) throw new AgentGateError('agentgate-invalid-environment')
    bytes += Buffer.byteLength(key) + Buffer.byteLength(value)
  }
  if (bytes > 65536) throw new AgentGateError('agentgate-manifest-too-large')
  if(manifest.agent_kind==='ssh'&&(manifest.arguments.length!==2||manifest.arguments[0]!=='-c'||!manifest.arguments[1]||manifest.arguments[1].includes('\uFFFD')||Buffer.byteLength(manifest.arguments[1])>16384||!sshEnvironmentMatches(manifest.workspace,manifest.environment)||manifest.input_digest!==hash(new Uint8Array())))throw new AgentGateError('agentgate-ssh-command-invalid')
}
export function sshEnvironmentMatches(workspace:string,environment:Record<string,string>):boolean{
 const allowed:Record<string,string>={PATH:'/usr/bin:/bin',HOME:workspace,LANG:'C.UTF-8',PYTHONDONTWRITEBYTECODE:'1'}
 return Object.entries(environment).every(([key,value])=>Object.hasOwn(allowed,key)&&allowed[key]===value)
}
// Match lifecycle.Manifest.Digest: fixed struct order, sorted map keys and Go JSON escaping.
export function agentManifestDigest(manifest: AgentManifest): string {
  validateManifest(manifest)
  const ordered: AgentManifest = {
    protocol: manifest.protocol, agent_kind: manifest.agent_kind, runtime_version: manifest.runtime_version,
    executable: manifest.executable, executable_digest: manifest.executable_digest, image_digest: manifest.image_digest,
    arguments: manifest.arguments, workspace: manifest.workspace,
    environment: Object.fromEntries(Object.entries(manifest.environment).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)),
    input_digest: manifest.input_digest,
  }
  const serialized=JSON.stringify(ordered)
  if(Buffer.byteLength(serialized)>65536)throw new AgentGateError('agentgate-manifest-too-large')
  return hash(serialized.replace(/[<>&\u2028\u2029]/g, char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`))
}
function validateBinding(binding: GateBinding, preparing = false): void {
  if (!binding || Object.keys(binding).some(key => !['agent_id','agent_key','job_digest','grant_id','run_id','node_id','boot_id','policy_digest','schema_digest','compiler_digest','artifact_digests','cgroup_id','generation','deadline_ns'].includes(key)) || [binding.agent_id, binding.grant_id, binding.run_id, binding.node_id, binding.boot_id].some(id => !identifier(id))
    || !/^[A-Za-z0-9_-]{43}$/.test(binding.agent_key) || Buffer.from(binding.agent_key, 'base64url').toString('base64url') !== binding.agent_key
    || [binding.job_digest, binding.policy_digest, binding.schema_digest, binding.compiler_digest].some(value => !digest(value))
    || !binding.artifact_digests || Object.keys(binding.artifact_digests).length === 0 || Object.keys(binding.artifact_digests).length > 64
    || Object.entries(binding.artifact_digests).some(([name, value]) => !identifier(name) || !digest(value))
    || !decimal(binding.cgroup_id, preparing) || !decimal(binding.generation) || BigInt(binding.generation) > 9223372036854775807n || !decimal(binding.deadline_ns)) throw new AgentGateError('agentgate-invalid-binding')
}
function validateCapabilities(required: string[]): void {
  if (!Array.isArray(required) || required.length === 0 || required.length > 64 || new Set(required).size !== required.length
    || required.some(id => !/^[a-z][a-z0-9_.-]+\.v[1-9][0-9]*$/.test(id))) throw new AgentGateError('agentgate-invalid-capabilities')
}
function requireQualified(evidence: GateEvidence, required: string[]) {
  if (!evidence.mandatory_hooks || evidence.lost !== '0' || !digest(evidence.digest) || !digest(evidence.readback_digest)) throw new AgentGateError('agentgate-enforcement-unavailable')
  for (const id of required) {
    const capability = evidence.capabilities?.[id]
    if (capability?.state !== 'qualified' || !Array.isArray(capability.mechanisms) || !capability.mechanisms.length || !digest(capability.evidence_digest)) throw new AgentGateError('agentgate-capability-unqualified')
  }
}
function validatePrepared(prepared: PreparedJob, job: GatewayJob): GateBinding {
  if (prepared?.protocol !== 'agentgate.job.prepared.v1') throw new AgentGateError('agentgate-prepare-response-invalid')
  validateBinding(prepared.binding)
  if (!same({ ...prepared.binding, cgroup_id: '0' }, job.binding) || prepared.manifest_digest !== job.binding.job_digest
    || !decimal(prepared.preparation_deadline_ns) || BigInt(prepared.preparation_deadline_ns) > BigInt(prepared.binding.deadline_ns)
    || !same(prepared.evidence?.binding, prepared.binding) || prepared.evidence?.phase !== 'quarantined'
    || !prepared.evidence.quarantined || prepared.evidence.released || !prepared.evidence.empty || prepared.evidence.rights_removed) throw new AgentGateError('agentgate-preparation-binding-differs')
  validatePreparedAuditHeader(prepared,job.requiredCapabilities)
  return structuredClone(prepared.binding)
}
export function validatePreparedAuditHeader(prepared: PreparedJob,requiredCapabilities:string[]):void {
 if (typeof prepared.audit_header !== 'string' || prepared.audit_header.length>65536 || !digest(prepared.audit_header_digest)) throw new AgentGateError('agentgate-audit-header-invalid')
 const raw=Buffer.from(prepared.audit_header,'base64')
 if(raw.toString('base64')!==prepared.audit_header || hash(Buffer.concat([Buffer.from('AGENTGATE_JOB_AUDIT_HEADER_V1\n'),raw]))!==prepared.audit_header_digest) throw new AgentGateError('agentgate-audit-header-invalid')
 let header:any
 try {header=JSON.parse(raw.toString('utf8'))} catch {throw new AgentGateError('agentgate-audit-header-invalid')}
 if (Object.keys(header||{}).some(key=>!['protocol','binding','document_digest','qualification_digest','required_capabilities','required_streams','created_mono_ns'].includes(key)) || JSON.stringify(header)!==raw.toString('utf8') || header.protocol!=='agentgate.full-job-audit.v1' || !same(header.binding,prepared.binding) || header.document_digest!==prepared.binding.policy_digest || !digest(header.qualification_digest) || !same(header.required_capabilities,requiredCapabilities) || !decimal(header.created_mono_ns) || BigInt(header.created_mono_ns)>=BigInt(prepared.preparation_deadline_ns) || !Array.isArray(header.required_streams) || header.required_streams.length!==7) throw new AgentGateError('agentgate-audit-header-invalid')
 const formats:Record<string,string>={files:'files216.v1',peers:'peers96.v2',sockets:'sockets112.v1',custody:'custody64.v1',process:'process80.v1'}
 const names=new Set<string>();const resources=new Set<string>();let syscallObservation=false;let nodeControl=false
 for(const stream of header.required_streams){
  if(!stream||Object.keys(stream).some(key=>!['name','kind','version','artifact_digest'].includes(key))||!identifier(stream.name)||names.has(stream.name)||!identifier(stream.version)||!['resource','observation','control'].includes(stream.kind)||!digest(stream.artifact_digest)||stream.artifact_digest!==prepared.binding.artifact_digests[stream.name])throw new AgentGateError('agentgate-audit-header-invalid')
  names.add(stream.name)
  if(stream.kind==='resource'){if(formats[stream.name]!==stream.version)throw new AgentGateError('agentgate-audit-header-invalid');resources.add(stream.name)}
  if(stream.kind==='observation'){if(stream.name!=='syscalls'||!['syscalls104.v1','syscalls128.v2'].includes(stream.version))throw new AgentGateError('agentgate-audit-header-invalid');syscallObservation=true}
  if(stream.kind==='control'){if(stream.name!=='node'||stream.version!=='nodecontrol.v1')throw new AgentGateError('agentgate-audit-header-invalid');nodeControl=true}
 }
 if(resources.size!==Object.keys(formats).length||!syscallObservation||!nodeControl)throw new AgentGateError('agentgate-audit-header-invalid')
}
export function validateTerminal(terminal: AgentTerminal, binding: GateBinding): void {
  if (terminal?.protocol !== 'agentgate.job.terminal.v1' || !same(terminal.binding, binding)
    || !['completed', 'failed', 'cancelled', 'expired', 'revoked', 'aborted'].includes(terminal.state)
    || !terminal.domain_empty || !terminal.rights_removed || !digest(terminal.evidence_digest)
    || !Number.isInteger(terminal.exit_code)) throw new AgentGateError('agentgate-terminal-binding-differs')
  if (terminal.evidence_verdict !== 'VALID_COMPLETE') throw new AgentGateError('agentgate-evidence-incomplete')
  if (terminal.state === 'completed' && terminal.exit_code !== 0) throw new AgentGateError('agentgate-terminal-state-differs')
  const output=terminal.output??''
  if (terminal.output===null || typeof output !== 'string' || Buffer.byteLength(output, 'base64') > 1 << 20 || !digest(terminal.output_digest)
    || Buffer.from(output,'base64').toString('base64')!==output || hash(Buffer.from(output, 'base64')) !== terminal.output_digest) throw new AgentGateError('agentgate-output-digest-differs')
  if (terminal.stderr !== undefined || terminal.stderr_digest !== undefined) {
    const stderr=terminal.stderr??''
    if (terminal.stderr===null || typeof stderr !== 'string' || Buffer.byteLength(stderr, 'base64') > 1 << 20 || !digest(terminal.stderr_digest)
      || Buffer.from(stderr,'base64').toString('base64')!==stderr || hash(Buffer.from(stderr, 'base64')) !== terminal.stderr_digest) throw new AgentGateError('agentgate-stderr-digest-differs')
  }
}
export type PreparedAgentRun = {
  readonly binding: GateBinding
  readonly auditHeaderDigest: string
  run(): Promise<AgentTerminal>
  stop(reason?: string): Promise<void>
}
async function confirmStop(request:NodeRequest,binding:GateBinding,reason:string):Promise<void>{
 try {
  const stopped=await request('POST',`/v1/jobs/${encodeURIComponent(binding.run_id)}/stop`,{protocol:'agentgate.job.stop.v1',binding,reason}) as {protocol:string;binding:GateBinding;evidence:GateEvidence}
  const expected=binding.cgroup_id==='0'?{...binding,cgroup_id:stopped.binding?.cgroup_id}:binding
  validateBinding(expected,expected.cgroup_id==='0')
  if(expected.cgroup_id==='0'&&stopped.evidence?.no_domain!==true)throw new AgentGateError('agentgate-cleanup-unconfirmed',false)
  if(stopped.protocol!=='agentgate.job.stopped.v1'||!same(stopped.binding,expected)||!same(stopped.evidence?.binding,expected)||stopped.evidence.phase!=='stopped'||!stopped.evidence.empty||!stopped.evidence.terminated||!stopped.evidence.rights_removed||!digest(stopped.evidence.digest))throw new AgentGateError('agentgate-cleanup-unconfirmed')
 } catch {throw new AgentGateError('agentgate-cleanup-unconfirmed',false)}
}
// Preparation completes node custody and authority signing before a gateway accepts a job.
export async function prepareIsolatedAgent(input:GatewayJob,request:NodeRequest,authorize:(prepared:PreparedJob)=>Promise<GateAuthorization>,nodeTrust:NodeTrust):Promise<PreparedAgentRun>{
 const job=structuredClone(input)
 validateManifest(job.manifest);validateBinding(job.binding,true);validateCapabilities(job.requiredCapabilities)
 if(job.binding.cgroup_id!=='0'||job.input.byteLength>1<<20||hash(job.input)!==job.manifest.input_digest||agentManifestDigest(job.manifest)!==job.binding.job_digest)throw new AgentGateError('agentgate-job-digest-differs')
 let owned:GateBinding|undefined
 let attempted=false
 try {
  attempted=true
  const prepared=await request('POST','/v1/jobs/prepare',{protocol:'agentgate.job.prepare.v1',manifest:job.manifest,binding:job.binding,required_capabilities:job.requiredCapabilities}) as PreparedJob
  owned=validatePrepared(prepared,job);requireQualified(prepared.evidence,job.requiredCapabilities)
  try{verifyPreparedNode(prepared,job.binding,nodeTrust)}catch{throw new AgentGateError('agentgate-node-preparation-untrusted')}
  const authorization=structuredClone(await authorize(structuredClone(prepared)))
  if(!authorization||!Array.isArray(authorization.required_capabilities)||!same(authorization.binding,owned)||!same([...authorization.required_capabilities].sort(),[...job.requiredCapabilities].sort())||!authorization.grant||authorization.document===undefined)throw new AgentGateError('agentgate-authorization-binding-differs')
  const binding=structuredClone(owned);const headerDigest=prepared.audit_header_digest
  let state:'prepared'|'running'|'stopped'|'terminal'='prepared'
  let stopping:Promise<void>|undefined
  const stop=async(reason='gateway-job-stopped')=>{
   if(!identifier(reason))throw new AgentGateError('agentgate-stop-reason-invalid')
   if(state==='terminal')return
   if(!stopping){state='stopped';stopping=confirmStop(request,binding,reason)}
   await stopping
  }
  return {
   get binding(){return structuredClone(binding)},
   get auditHeaderDigest(){return headerDigest},
   stop,
   async run(){
    if(state!=='prepared')throw new AgentGateError('agentgate-prepared-run-consumed')
    state='running'
    try {
     const terminal=await request('POST','/v1/jobs/run',{protocol:'agentgate.job.run.v1',manifest:job.manifest,authorization,input:Buffer.from(job.input).toString('base64')}) as AgentTerminal
     validateTerminal(terminal,binding);state='terminal';return structuredClone(terminal)
    }catch(error){await stop('gateway-run-failed');throw error instanceof AgentGateError?error:new AgentGateError('agentgate-node-unavailable')}
   },
  }
 }catch(error){
  if(attempted)await confirmStop(request,owned??job.binding,'gateway-run-failed')
  throw new AgentGateError(error instanceof AgentGateError?error.code:'agentgate-node-unavailable',true)
 }
}
export async function runIsolatedAgent(job:GatewayJob,request:NodeRequest,authorize:(prepared:PreparedJob)=>Promise<GateAuthorization>,nodeTrust:NodeTrust):Promise<AgentTerminal>{
 return (await prepareIsolatedAgent(job,request,authorize,nodeTrust)).run()
}

type UnixClientOptions = {
 socketPath:string;nodeUID:number;timeoutMS:number;sign:(input:NodeProofInput)=>Promise<string>
}
export function unixNodeClient(options:UnixClientOptions):NodeRequest{return unixPolicyClient(options,'node')}
export function unixAuthorityClient(options:UnixClientOptions):NodeRequest{return unixPolicyClient(options,'authority')}
function unixPolicyClient(options: {
  socketPath: string; nodeUID: number; timeoutMS: number
  sign: (input: NodeProofInput) => Promise<string>
}, service:'node'|'authority'): NodeRequest {
  if (!safePath(options.socketPath) || !Number.isSafeInteger(options.nodeUID) || options.nodeUID < 0 || !Number.isSafeInteger(options.timeoutMS) || options.timeoutMS < 1 || options.timeoutMS > 86400000 || typeof options.sign !== 'function') throw new AgentGateError('agentgate-node-config-invalid')
  return async (method, path, body) => {
    if (service==='authority' ? (method!=='POST'||path!=='/v1/grants/issue') : (!['GET', 'POST'].includes(method) || !((method==='GET'&&path==='/v1/node/inventory')||/^\/v1\/jobs(?:\/prepare|\/run|\/[A-Za-z0-9_.:%-]+(?:\/stop)?)$/.test(path) || method==='GET'&&/^\/v1\/agents\/[A-Za-z0-9_.:-]+\/generation$/.test(path)))) throw new AgentGateError('agentgate-node-path-invalid')
    const socket = await lstat(options.socketPath)
    const parent = await lstat(dirname(options.socketPath))
    if (!socket.isSocket() || socket.isSymbolicLink() || socket.uid !== options.nodeUID || socket.mode & 0o002
      || !parent.isDirectory() || parent.uid!==options.nodeUID || parent.mode & 0o022 || await realpath(dirname(options.socketPath)) !== dirname(options.socketPath)) throw new AgentGateError('agentgate-node-socket-untrusted')
    const bytes = Buffer.from(body === undefined ? '' : JSON.stringify(body))
    const proof = await options.sign({ method, path, body: bytes, bodyDigest: hash(bytes) })
    if (!proof || proof.length > 16384 || /[\r\n]/.test(proof)) throw new AgentGateError('agentgate-agent-proof-invalid')
    return new Promise((resolve, reject) => {
      const req = httpRequest({ socketPath: options.socketPath, path, method, headers: { 'Content-Type': 'application/json', Authorization: `Alloyium-Proof ${proof}`, 'X-Request-ID': randomUUID() } }, response => {
        const chunks: Buffer[] = []; let size = 0
        response.on('data', chunk => { size += chunk.length; if (size > 4 << 20) response.destroy(new AgentGateError('agentgate-node-response-too-large')); else chunks.push(Buffer.from(chunk)) })
        response.on('error', () => reject(new AgentGateError('agentgate-node-unavailable')))
        response.on('end', () => {
          if (response.statusCode !== 200) { reject(new AgentGateError('agentgate-node-rejected')); return }
          try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))) } catch { reject(new AgentGateError('agentgate-node-response-invalid')) }
        })
      })
      const deadline = setTimeout(() => req.destroy(new AgentGateError('agentgate-node-timeout')), options.timeoutMS)
      req.once('close', () => clearTimeout(deadline))
      req.setTimeout(options.timeoutMS, () => req.destroy(new AgentGateError('agentgate-node-timeout')))
      req.on('error', () => reject(new AgentGateError('agentgate-node-unavailable')))
      req.end(bytes)
    })
  }
}


type EnrolledAgentKey={agentID:string;agentKey:string;privateKey:KeyObject}
export function enrolledNodeSigner(options:EnrolledAgentKey & {nodeID:string;bootID:string}):(input:NodeProofInput)=>Promise<string>{
 if(!identifier(options.nodeID))throw new AgentGateError('agentgate-agent-key-invalid')
 return enrolledServiceSigner({...options,audience:`agentgate-node.v1:${options.nodeID}`,epoch:options.bootID})
}
export function enrolledAuthoritySigner(options:EnrolledAgentKey & {authorityID:string;authorityEpoch:string}):(input:NodeProofInput)=>Promise<string>{
 if(!identifier(options.authorityID))throw new AgentGateError('agentgate-agent-key-invalid')
 return enrolledServiceSigner({...options,audience:`agentgate-authority.v1:${options.authorityID}`,epoch:options.authorityEpoch})
}
function enrolledServiceSigner(options:EnrolledAgentKey & {audience:string;epoch:string}):(input:NodeProofInput)=>Promise<string>{
 if(!identifier(options.agentID)||!identifier(options.epoch)||options.privateKey?.type!=='private'||options.privateKey.asymmetricKeyType!=='ed25519')throw new AgentGateError('agentgate-agent-key-invalid')
 const publicBytes=createPublicKey(options.privateKey).export({format:'der',type:'spki'})
 if(publicBytes.length!==44||publicBytes.subarray(12).toString('base64url')!==options.agentKey)throw new AgentGateError('agentgate-agent-key-differs')
 return async input=>{
  if(input.bodyDigest!==hash(input.body))throw new AgentGateError('agentgate-proof-body-differs')
  const claims={aud:options.audience,epoch:options.epoch,sub:options.agentID,method:input.method,path:input.path,body_sha256:input.bodyDigest,iat:Math.floor(Date.now()/1000),nonce:randomBytes(32).toString('base64url')}
  const header=Buffer.from('{"alg":"EdDSA","typ":"alloyium-request-proof-v1"}').toString('base64url')
  const unsigned=header+'.'+Buffer.from(JSON.stringify(claims)).toString('base64url')
  return unsigned+'.'+signBytes(null,Buffer.from(unsigned),options.privateKey).toString('base64url')
 }
}
