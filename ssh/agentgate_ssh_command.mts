#!/usr/bin/env bun
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// OpenSSH ForceCommand entry point. The remote command is data until the node
// releases the enrolled shell into its fully admitted process domain.
import { userInfo } from 'node:os'
import { AgentGateError, prepareIsolatedAgent, type AgentTerminal, type PreparedAgentRun } from './agentgate_gateway_policy.ts'
import { loadManagedGatewayConfig, openManagedGatewayAdmission, type ManagedAdmission, type ManagedGatewayConfig } from './agentgate_gateway_bootstrap.ts'

export type SSHPeer = { user:string; uid:number; gid:number }
export type SSHTransport = { command:unknown; tty:unknown; configPath:unknown }

export function validateSSHTransport(transport:SSHTransport):{command:string;configPath:string}{
 const {command,tty,configPath}=transport
 if(typeof command!=='string'||!command||command.includes('\0')||command.includes('\uFFFD')||Buffer.byteLength(command)>16384||tty!==undefined)throw new AgentGateError('agentgate-ssh-transport-invalid')
 if(typeof configPath!=='string'||!configPath.startsWith('/')||configPath.includes('\0'))throw new AgentGateError('agentgate-ssh-config-invalid')
 return {command,configPath}
}

export function verifySSHIdentity(config:ManagedGatewayConfig,peer:SSHPeer):void{
 const expected=config.ssh_identity
 if(config.kind!=='ssh'||!expected||expected.user!==peer.user||expected.uid!==peer.uid||expected.gid!==peer.gid)throw new AgentGateError('agentgate-ssh-identity-denied')
}

export type SSHRunOptions={transport:SSHTransport;peer:SSHPeer;signal:AbortSignal;deliver?:(terminal:AgentTerminal)=>Promise<void>}
export type SSHDependencies={
 load?:typeof loadManagedGatewayConfig
 open?:typeof openManagedGatewayAdmission
 prepare?:typeof prepareIsolatedAgent
}

export async function runSSHCommand(options:SSHRunOptions,deps:SSHDependencies={}):Promise<AgentTerminal>{
 const {command,configPath}=validateSSHTransport(options.transport)
 const loaded=await(deps.load??loadManagedGatewayConfig)(configPath)
 verifySSHIdentity(loaded.config,options.peer)
 if(options.signal.aborted)throw new AgentGateError('agentgate-ssh-disconnected')
 const admission:ManagedAdmission=await(deps.open??openManagedGatewayAdmission)('ssh',{AGENTGATE_MANAGED_CONFIG:configPath},{load:async()=>loaded})
 const plan=await admission.planSSHCommand(command)
 if(options.signal.aborted)throw new AgentGateError('agentgate-ssh-disconnected')
 let prepared:PreparedAgentRun|undefined
 let stopping:Promise<void>|undefined
 const stop=()=>{
  if(prepared&&!stopping){stopping=prepared.stop('ssh-transport-closed');void stopping.catch(()=>{})}
 }
 options.signal.addEventListener('abort',stop,{once:true})
 try{
  prepared=await(deps.prepare??prepareIsolatedAgent)(plan.job,admission.node,p=>admission.issue({protocol:'agentgate.full-job-issue.v1',manifest:plan.job.manifest,prepared:p,document:plan.document}),admission.nodeTrust)
  if(options.signal.aborted){stop();await stopping;throw new AgentGateError('agentgate-ssh-disconnected')}
  const terminal=await prepared.run()
  // A stop may finish the node run after the SSH channel has closed. Its
  // terminal is cleanup evidence, not a successful reply to that channel.
  if(options.signal.aborted){
   stop()
   await stopping
   throw new AgentGateError('agentgate-ssh-disconnected')
  }
  if(!terminal.stderr_digest)throw new AgentGateError('agentgate-ssh-stderr-missing')
  await stopping
  if(options.signal.aborted){
   stop()
   await stopping
   throw new AgentGateError('agentgate-ssh-disconnected')
  }
  if(options.deliver)await options.deliver(terminal)
  if(options.signal.aborted){
   stop()
   await stopping
   throw new AgentGateError('agentgate-ssh-disconnected')
  }
  return terminal
 }catch(error){
  if(prepared){
   if(!stopping)stopping=prepared.stop('ssh-command-failed')
   await stopping
  }
  throw error
 }finally{options.signal.removeEventListener('abort',stop)}
}

function writeSSHReply(stream:NodeJS.WriteStream,body:string|undefined,signal:AbortSignal):Promise<void>{
 if(!body)return Promise.resolve()
 if(signal.aborted)return Promise.reject(new AgentGateError('agentgate-ssh-disconnected'))
 return new Promise((resolve,reject)=>{
  let done=false
  const finish=(error?:Error|null)=>{
   if(done)return
   done=true
   signal.removeEventListener('abort',abort)
   if(error)reject(error)
   else resolve()
  }
  const abort=()=>finish(new AgentGateError('agentgate-ssh-disconnected'))
  signal.addEventListener('abort',abort,{once:true})
  try{stream.write(Buffer.from(body,'base64'),finish)}
  catch(error){finish(error instanceof Error?error:new AgentGateError('agentgate-ssh-output-failed'))}
  if(signal.aborted)abort()
 })
}

export async function main(args:readonly string[]=process.argv.slice(2)):Promise<void>{
 if(args.length!==0)throw new AgentGateError('agentgate-ssh-arguments-invalid')
 const peer={user:userInfo().username,uid:process.getuid(),gid:process.getgid()}
 const controller=new AbortController()
 const cancel=()=>controller.abort()
 const parent=process.ppid
 const parentCheck=setInterval(()=>{if(process.ppid!==parent)cancel()},250)
 const output=()=>cancel()
 // An empty SSH stdin is normal for `ssh -n` and for noninteractive commands.
 // The authenticated sshd process and its channel signals own this lifetime.
 process.stdout.on('error',output)
 process.stdout.on('close',output)
 process.stderr.on('error',output)
 process.stderr.on('close',output)
 for(const name of ['SIGHUP','SIGTERM','SIGINT'] as const)process.on(name,cancel)
 try{
  const terminal=await runSSHCommand({transport:{command:process.env.SSH_ORIGINAL_COMMAND,tty:process.env.SSH_TTY,configPath:process.env.AGENTGATE_SSH_CONFIG},peer,signal:controller.signal,
   deliver:async terminal=>{
    await writeSSHReply(process.stdout,terminal.output,controller.signal)
    await writeSSHReply(process.stderr,terminal.stderr,controller.signal)
   }})
  if(controller.signal.aborted)throw new AgentGateError('agentgate-ssh-disconnected')
  process.exitCode=terminal.state==='completed'?0:terminal.state==='failed'&&terminal.exit_code>0&&terminal.exit_code<256?terminal.exit_code:1
 }finally{
  process.stdout.removeListener('error',output)
  process.stdout.removeListener('close',output)
  process.stderr.removeListener('error',output)
  process.stderr.removeListener('close',output)
  clearInterval(parentCheck)
  for(const name of ['SIGHUP','SIGTERM','SIGINT'] as const)process.removeListener(name,cancel)
 }
}

if((import.meta as ImportMeta & {main?:boolean}).main)await main().catch(error=>{
 const code=error instanceof AgentGateError?error.code:'agentgate-ssh-command-failed'
 process.stderr.write(JSON.stringify({error:{code}})+'\n')
 process.exitCode=1
})
