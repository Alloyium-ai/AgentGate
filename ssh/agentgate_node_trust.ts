// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
import { createHash, createPublicKey, verify } from 'node:crypto'
import { isDeepStrictEqual } from 'node:util'
import type { GateBinding, PreparedJob } from './agentgate_gateway_policy.ts'

export type NodeTrust = {
  publicKeys: Record<string, string>
  maxAgeSeconds: number
  nowWall?: () => number
}
export type NodeInventory = {
  protocol: 'agentgate.node.inventory.v1'; node_id: string; boot_id: string
  schema_digest: string; compiler_digest: string; artifact_digests: Record<string, string>
  target_report: Record<string, any>; target_digest: string
  wall_unix: number; mono_ns: string; key_id: string; signature: string
}
type Shape = 'string' | 'integer' | 'boolean' | { fields: [string, Shape, boolean?][] } | { map: Shape } | { array: Shape }
const fields = (...values: [string, Shape, boolean?][]): Shape => ({ fields: values })
const strings: Shape = { map: 'string' }
const binding = fields(...['agent_id','agent_key','job_digest','grant_id','run_id','node_id','boot_id','policy_digest','schema_digest','compiler_digest'].map(name => [name, 'string'] as [string, Shape]), ['artifact_digests', strings], ...['cgroup_id','generation','deadline_ns'].map(name => [name, 'string'] as [string, Shape]))
const capability = fields(['state','string'], ['mechanisms',{array:'string'}], ['evidence_digest','string'])
const evidence = fields(['binding',binding], ['phase','string'], ['quarantined','boolean'], ['released','boolean'], ['terminated','boolean'], ['readback_digest','string'], ['mandatory_hooks','boolean'], ['capabilities',{map:capability}], ['process',fields(['pid','integer'],['start_time_ticks','string'],['barrier_id','string']),true], ['empty','boolean'], ['no_domain','boolean',true], ['counters_available','boolean',true], ['rights_removed','boolean'], ['decisions','string'], ['lost','string'], ['digest','string'])
const prepared = fields(['preparation_key_id','string'], ['preparation_signature','string'], ['prepared_at_unix','integer'], ['prepared_mono_ns','string'], ['audit_header','string'], ['audit_header_digest','string'], ['protocol','string'], ['binding',binding], ['manifest_digest','string'], ['preparation_deadline_ns','string'], ['evidence',evidence])
const qualification = fields(...['protocol','producer_sha256','compiler_sha256','artifacts_sha256'].map(name=>[name,'string'] as [string,Shape]), ['policy_digests',{array:'string'}], ['required_capabilities',{array:'string'}], ['contracts_sha256','string'], ['evidence_sha256','string'])
const report = fields(...['schema_version','node','boot','challenge','kernel','architecture','source_revision','artifact_sha256','policy_schema_digest'].map(name=>[name,'string'] as [string,Shape]), ['inventory_sha256','string',true], ['btf_sha256','string',true], ['kernel_config_sha256','string',true], ['issued_at','integer'], ['valid_until','integer'], ['capabilities',{map:fields(['state','string'],['mechanisms',{array:'string'}],['receipt_sha256','string'])}], ['probes',{array:fields(['hook','string'],['helper','string'],['loaded','boolean'],['attached','boolean'],['error','string',true])}], ['qualification',qualification,true])
const inventory = fields(...['protocol','node_id','boot_id','schema_digest','compiler_digest'].map(name=>[name,'string'] as [string,Shape]), ['artifact_digests',strings], ['target_report',report], ['target_digest','string'], ['wall_unix','integer'], ['mono_ns','string'], ['key_id','string'], ['signature','string'])
const hash = (value: string | Uint8Array) => createHash('sha256').update(value).digest('hex')
const digest = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)
const id = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value)
const decimal = (value: unknown): value is string => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= 18446744073709551615n
function invalid(): never { throw new Error('agentgate-node-proof-invalid') }
const quote = (value: string) => JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, char => `\\u${char.charCodeAt(0).toString(16).padStart(4,'0')}`)
// Render Go struct order and UTF-8 map order, including numeric-looking keys.
function render(value: any, shape: Shape): string {
  if (shape === 'string') { if (typeof value !== 'string' || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) invalid(); return quote(value) }
  if (shape === 'integer') { if (!Number.isSafeInteger(value)) invalid(); return String(value) }
  if (shape === 'boolean') { if (typeof value !== 'boolean') invalid(); return String(value) }
  if ('array' in shape) { if(value===null)return 'null'; if (!Array.isArray(value) || value.length > 128) invalid(); return '['+value.map(item=>render(item,shape.array)).join(',')+']' }
  if('map' in shape&&value===null)return 'null'
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid()
  if ('map' in shape) {
    const keys=Object.keys(value)
    if(keys.length>64)invalid()
    keys.sort((a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b)))
    return '{'+keys.map(key=>quote(key)+':'+render(value[key],shape.map)).join(',')+'}'
  }
  if(Object.keys(value).some(key=>!shape.fields.some(([name])=>name===key)))invalid()
  return '{'+shape.fields.filter(([name,,omit])=>!omit || value[name]!==undefined&&value[name]!==null&&value[name]!==false&&value[name]!=='').map(([name,type])=>quote(name)+':'+render(value[name],type)).join(',')+'}'
}
function freshness(wall:number,trust:NodeTrust):number {
  const now=trust.nowWall?.()??Math.floor(Date.now()/1000)
  if(!trust.publicKeys || Object.keys(trust.publicKeys).length===0 || Object.keys(trust.publicKeys).length>32 || !Number.isSafeInteger(trust.maxAgeSeconds) || trust.maxAgeSeconds<1 || trust.maxAgeSeconds>30 || !Number.isSafeInteger(wall) || wall<=0 || !Number.isSafeInteger(now) || wall>now+1 || now-wall>trust.maxAgeSeconds)invalid()
  return Math.max(0,now-wall)
}
function signature(raw:Uint8Array,encoded:string,keyID:string,nodeID:string,trust:NodeTrust):void {
  if(!id(nodeID)||!id(keyID)||typeof encoded!=='string')invalid()
  const key=trust.publicKeys[nodeID+'/'+keyID]
  if(typeof key!=='string')invalid()
  const bytes=Buffer.from(key,'base64url');const sig=Buffer.from(encoded,'base64url')
  if(bytes.length!==32 || bytes.toString('base64url')!==key || sig.length!==64 || sig.toString('base64url')!==encoded)invalid()
  const publicKey=createPublicKey({format:'der',type:'spki',key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),bytes])})
  if(!verify(null,raw,publicKey,sig))invalid()
}
export function prepareSigningBytes(value:PreparedJob):Buffer {
  return Buffer.from('AGENTGATE_JOB_PREPARED_V1\n'+render({...value,preparation_signature:''},prepared))
}
export function verifyPreparedNode(value:PreparedJob,expected:GateBinding,trust:NodeTrust):void {
  const age=freshness(value.prepared_at_unix,trust)
  if(!isDeepStrictEqual({...expected,cgroup_id:value.binding.cgroup_id},value.binding) || !decimal(value.prepared_mono_ns) || !decimal(value.preparation_deadline_ns) || !decimal(value.binding.deadline_ns))invalid()
  const mono=BigInt(value.prepared_mono_ns),lease=BigInt(value.preparation_deadline_ns)
  if(lease<=mono || lease>BigInt(value.binding.deadline_ns) || lease-mono>30000000000n || BigInt(age)*1000000000n>=lease-mono)invalid()
  const e=value.evidence
  if(value.protocol!=='agentgate.job.prepared.v1'||value.manifest_digest!==value.binding.job_digest||!isDeepStrictEqual(e.binding,value.binding)||e.phase!=='quarantined'||!e.quarantined||e.released||e.terminated||!e.empty||e.rights_removed||!e.mandatory_hooks||e.lost!=='0'||!digest(e.digest)||!digest(e.readback_digest))invalid()
  const raw=Buffer.from(value.audit_header,'base64')
  if(raw.toString('base64')!==value.audit_header||hash(Buffer.concat([Buffer.from('AGENTGATE_JOB_AUDIT_HEADER_V1\n'),raw]))!==value.audit_header_digest)invalid()
  const header=JSON.parse(raw.toString('utf8'))
  if(!decimal(header.created_mono_ns)||BigInt(header.created_mono_ns)>mono)invalid()
  signature(prepareSigningBytes(value),value.preparation_signature,value.preparation_key_id,value.binding.node_id,trust)
}
export function nodeInventorySigningBytes(value:NodeInventory):Buffer {
  return Buffer.from('AGENTGATE_NODE_INVENTORY_V1\n'+render({...value,signature:''},inventory))
}
export function verifyNodeInventory(value:NodeInventory,expected:{nodeID:string;bootID:string;schemaDigest:string},trust:NodeTrust):void {
  const age=freshness(value.wall_unix,trust);const r=value.target_report
  if(value.protocol!=='agentgate.node.inventory.v1'||value.node_id!==expected.nodeID||value.boot_id!==expected.bootID||value.schema_digest!==expected.schemaDigest||!digest(value.compiler_digest)||!decimal(value.mono_ns)||!r||r.schema_version!=='agentgate.capabilities.v1'||r.node!==value.node_id||r.boot!==value.boot_id||r.policy_schema_digest!==value.schema_digest||r.architecture!=='x86_64'||!r.kernel||!Number.isSafeInteger(r.issued_at)||!Number.isSafeInteger(r.valid_until)||r.issued_at<0||r.valid_until<=r.issued_at||r.valid_until-r.issued_at>300||value.wall_unix<r.issued_at||value.wall_unix+age>=r.valid_until||Object.keys(value.artifact_digests??{}).length===0)invalid()
  if(!Object.entries(value.artifact_digests).every(([key,d])=>id(key)&&digest(d))||!Object.values(value.artifact_digests).includes(r.artifact_sha256)||![r.artifact_sha256,r.inventory_sha256,r.btf_sha256,r.kernel_config_sha256].every(digest)||hash(render(r,report))!==value.target_digest)invalid()
  signature(nodeInventorySigningBytes(value),value.signature,value.key_id,value.node_id,trust)
}
