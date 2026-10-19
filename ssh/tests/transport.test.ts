// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
import { expect, test } from 'bun:test'
import { createHash } from 'node:crypto'
import { runSSHCommand, validateSSHTransport, verifySSHIdentity } from '../agentgate_ssh_command.mts'
import { agentManifestDigest, validateManifest, validateTerminal } from '../agentgate_gateway_policy.ts'

test('the SSH manifest binds a small configured toolchain environment', () => {
  const workspace='/var/lib/agentgate/workspace'
  const manifest={protocol:'agentgate.job.manifest.v1',agent_kind:'ssh',runtime_version:'shell-v1',
    executable:'/usr/bin/dash',executable_digest:'a'.repeat(64),image_digest:`sha256:${'b'.repeat(64)}`,
    arguments:['-c','python3 -V'],workspace,environment:{PATH:'/usr/bin:/bin',HOME:workspace,LANG:'C.UTF-8',PYTHONDONTWRITEBYTECODE:'1'},
    input_digest:createHash('sha256').update('').digest('hex')} as any
  expect(() => validateManifest(manifest)).not.toThrow()
  const original=agentManifestDigest(manifest)
  const reduced={...manifest,environment:{PATH:'/usr/bin:/bin',HOME:workspace}}
  expect(agentManifestDigest(reduced)).not.toBe(original)
  for(const environment of [{...manifest.environment,PATH:'/usr/bin'}, {...manifest.environment,LD_PRELOAD:'/work/lib.so'}, {...manifest.environment,HOME:'/root'}])
    expect(() => validateManifest({...manifest,environment})).toThrow('agentgate-ssh-command-invalid')
})

test('the forced command accepts a noninteractive command without stdin', () => {
  expect(validateSSHTransport({command: 'printf ok', tty: undefined, configPath: '/etc/agentgate/gateway.json'}).command).toBe('printf ok')
})

test('the forced command rejects a TTY and a changed account', () => {
  expect(() => validateSSHTransport({command: 'id', tty: '/dev/pts/1', configPath: '/etc/agentgate/gateway.json'})).toThrow()
  expect(() => verifySSHIdentity({kind:'ssh',ssh_identity:{user:'pilot',uid:10001,gid:10001}} as any,{user:'other',uid:10001,gid:10001})).toThrow()
})

test('the SSH terminal rejects changed stderr and accepts empty stderr with a digest', () => {
  const binding = {run_id:'test'} as any
  const hash = (text:string) => createHash('sha256').update(text).digest('hex')
  const terminal = {protocol:'agentgate.job.terminal.v1',binding,state:'completed',exit_code:0,
    domain_empty:true,rights_removed:true,evidence_digest:'a'.repeat(64),evidence_verdict:'VALID_COMPLETE',
    output_digest:hash(''),
    stderr:Buffer.from('test failed\n').toString('base64'),stderr_digest:hash('test failed\n')} as any
  expect(() => validateTerminal(terminal,binding)).not.toThrow()
  expect(() => validateTerminal({...terminal,stderr:Buffer.from('changed\n').toString('base64')},binding)).toThrow('agentgate-stderr-digest-differs')
  expect(() => validateTerminal({...terminal,stderr:undefined,stderr_digest:hash('')},binding)).not.toThrow()
})

test('a disconnected SSH session calls stop on its prepared run', async () => {
  const controller = new AbortController()
  let entered!:()=>void
  const active = new Promise<void>(resolve => { entered=resolve })
  let finish!:(value:any)=>void
  const pending = new Promise<any>(resolve => { finish=resolve })
  let stops=0
  const terminal = {stderr_digest:'a'.repeat(64)}
  const run=runSSHCommand({transport:{command:'printf ok',tty:undefined,configPath:'/etc/agentgate/gateway.json'},
    peer:{user:'pilot',uid:10001,gid:10001},signal:controller.signal},{
    load:async()=>({config:{kind:'ssh',ssh_identity:{user:'pilot',uid:10001,gid:10001}}}) as any,
    open:async()=>({planSSHCommand:async()=>({job:{manifest:{}},document:{}}),node:{},nodeTrust:{},issue:async()=>({})}) as any,
    prepare:async()=>({run:()=>{entered();return pending},stop:async()=>{stops++;finish(terminal)}}) as any,
  })
  await active
  controller.abort()
  await expect(run).rejects.toThrow('agentgate-ssh-disconnected')
  expect(stops).toBe(1)
})

test('a live SSH session returns its terminal without a stop', async () => {
  const controller = new AbortController()
  const terminal = {stderr_digest:'a'.repeat(64)}
  let stops=0
  const result=await runSSHCommand({transport:{command:'printf ok',tty:undefined,configPath:'/etc/agentgate/gateway.json'},
    peer:{user:'pilot',uid:10001,gid:10001},signal:controller.signal},{
    load:async()=>({config:{kind:'ssh',ssh_identity:{user:'pilot',uid:10001,gid:10001}}}) as any,
    open:async()=>({planSSHCommand:async()=>({job:{manifest:{}},document:{}}),node:{},nodeTrust:{},issue:async()=>({})}) as any,
    prepare:async()=>({run:async()=>terminal,stop:async()=>{stops++}}) as any,
  })
  expect(result).toBe(terminal as any)
  expect(stops).toBe(0)
})

test('a close between terminal receipt and reply still stops the run', async () => {
  const controller=new AbortController()
  let stops=0
  const terminal=Object.defineProperty({},'stderr_digest',{get:()=>{
    controller.abort()
    return 'a'.repeat(64)
  }})
  const run=runSSHCommand({transport:{command:'printf ok',tty:undefined,configPath:'/etc/agentgate/gateway.json'},
    peer:{user:'pilot',uid:10001,gid:10001},signal:controller.signal},{
    load:async()=>({config:{kind:'ssh',ssh_identity:{user:'pilot',uid:10001,gid:10001}}}) as any,
    open:async()=>({planSSHCommand:async()=>({job:{manifest:{}},document:{}}),node:{},nodeTrust:{},issue:async()=>({})}) as any,
    prepare:async()=>({run:async()=>terminal,stop:async()=>{stops++}}) as any,
  })
  await expect(run).rejects.toThrow('agentgate-ssh-disconnected')
  expect(stops).toBe(1)
})

test('a close while the SSH reply is being written still stops the run', async () => {
  const controller=new AbortController()
  let stops=0
  let enterDelivery!:()=>void
  const delivering=new Promise<void>(resolve=>{enterDelivery=resolve})
  let releaseDelivery!:()=>void
  const pendingDelivery=new Promise<void>(resolve=>{releaseDelivery=resolve})
  const terminal={stderr_digest:'a'.repeat(64)}
  const run=runSSHCommand({transport:{command:'printf ok',tty:undefined,configPath:'/etc/agentgate/gateway.json'},
    peer:{user:'pilot',uid:10001,gid:10001},signal:controller.signal,
    deliver:async()=>{enterDelivery();await pendingDelivery}}, {
    load:async()=>({config:{kind:'ssh',ssh_identity:{user:'pilot',uid:10001,gid:10001}}}) as any,
    open:async()=>({planSSHCommand:async()=>({job:{manifest:{}},document:{}}),node:{},nodeTrust:{},issue:async()=>({})}) as any,
    prepare:async()=>({run:async()=>terminal,stop:async()=>{stops++}}) as any,
  })
  await delivering
  controller.abort()
  releaseDelivery()
  await expect(run).rejects.toThrow('agentgate-ssh-disconnected')
  expect(stops).toBe(1)
})

test('an SSH output failure stops the prepared run', async () => {
  const controller=new AbortController()
  let stops=0
  const terminal={stderr_digest:'a'.repeat(64)}
  const run=runSSHCommand({transport:{command:'printf ok',tty:undefined,configPath:'/etc/agentgate/gateway.json'},
    peer:{user:'pilot',uid:10001,gid:10001},signal:controller.signal,
    deliver:async()=>{throw new Error('output closed')}}, {
    load:async()=>({config:{kind:'ssh',ssh_identity:{user:'pilot',uid:10001,gid:10001}}}) as any,
    open:async()=>({planSSHCommand:async()=>({job:{manifest:{}},document:{}}),node:{},nodeTrust:{},issue:async()=>({})}) as any,
    prepare:async()=>({run:async()=>terminal,stop:async()=>{stops++}}) as any,
  })
  await expect(run).rejects.toThrow('output closed')
  expect(stops).toBe(1)
})
