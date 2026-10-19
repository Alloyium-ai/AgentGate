// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
import { afterAll, expect, test } from 'bun:test'
import { createServer, request } from 'node:http'
import { access, chmod, mkdtemp, readFile, writeFile, rm, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { readBoundedTaskBody, startBridge } from '../taskboard_bridge.mts'

const owned: Array<() => Promise<void>> = []
afterAll(async () => { for (const close of owned.reverse()) await close() })

function call(socketPath: string, method: string, path: string): Promise<{status:number; body:string}> {
  return new Promise((resolve, reject) => {
    const client = request({socketPath, method, path}, response => {
      const chunks: Buffer[] = []
      response.on('data', chunk => chunks.push(chunk))
      response.on('end', () => resolve({status:response.statusCode ?? 0, body:Buffer.concat(chunks).toString()}))
    })
    client.on('error', reject)
    client.end()
  })
}

test('the Unix bridge exposes only one authenticated task read', async () => {
  const root = await mkdtemp(join(tmpdir(), 'agentgate-taskboard-'))
  owned.push(() => rm(root, {recursive:true, force:true}))
  const token = 'owned-scoped-test-token-123456'
  const tokenFile = join(root, 'token')
  await writeFile(tokenFile, token, {mode:0o600})
  const seen: Array<{url:string|undefined;authorization:string|undefined}> = []
  let permitWithoutToken = false
  const upstream = createServer((request, response) => {
    seen.push({url:request.url, authorization:request.headers.authorization})
    if (!request.headers.authorization && !permitWithoutToken) { response.writeHead(401).end(); return }
    response.writeHead(200, {'content-type':'application/json'})
    response.end(JSON.stringify({id:42,project_id:7,status:'Backlog',title:'Owned test',description:'x'.repeat(70000)}))
  })
  await new Promise<void>(resolve => upstream.listen(0, '127.0.0.1', resolve))
  owned.push(() => new Promise(resolve => upstream.close(() => resolve())))
  const address = upstream.address()
  if (!address || typeof address === 'string') throw new Error('test-upstream-absent')
  const socketPath = join(root, 'bridge', 'taskboard.sock')
  const snapshotPath = join(root, 'bridge', 'task.json')
  const bridge = await startBridge({socketPath, socketGID:process.getgid(), taskboardURL:`http://127.0.0.1:${address.port}/`,taskID:42,tokenFile,snapshotPath})
  owned.push(() => new Promise(resolve => bridge.close(() => resolve())))
  const snapshot = JSON.parse(await readFile(snapshotPath, 'utf8'))
  expect(snapshot.protocol).toBe('agentgate.taskboard-read.v1')
  expect(snapshot.task).toEqual({id:42,project_id:7,status:'Backlog',title:'Owned test'})
  expect(Date.parse(snapshot.valid_until)).toBeGreaterThan(Date.now())
  expect(JSON.stringify(snapshot)).not.toContain(token)
  const task = await call(socketPath, 'GET', '/task')
  expect(task.status).toBe(200)
  expect(JSON.parse(task.body)).toEqual({id:42,project_id:7,status:'Backlog',title:'Owned test'})
  expect(task.body).not.toContain(token)
  const proof = await call(socketPath, 'GET', '/auth-probe')
  expect(proof.status).toBe(200)
  expect(JSON.parse(proof.body)).toEqual({task_id:42,upstream_status:401})
  permitWithoutToken = true
  expect((await call(socketPath, 'GET', '/auth-probe')).status).toBe(502)
  expect((await call(socketPath, 'GET', '/task')).status).toBe(502)
  await expect(access(snapshotPath)).rejects.toThrow()
  expect((await call(socketPath, 'POST', '/task')).status).toBe(403)
  expect((await call(socketPath, 'GET', '/api/tasks/43')).status).toBe(403)
  expect(seen).toEqual([
    {url:'/api/tasks/42',authorization:undefined},
    {url:'/api/tasks/42',authorization:`Bearer ${token}`},
    {url:'/api/tasks/42',authorization:undefined},
    {url:'/api/tasks/42',authorization:`Bearer ${token}`},
    {url:'/api/tasks/42',authorization:undefined},
    {url:'/api/tasks/42',authorization:undefined},
    {url:'/api/tasks/42',authorization:undefined},
  ])
})

test('the bridge bounds the full upstream task response before parsing', async () => {
  const response = new Response(JSON.stringify({description:'x'.repeat(1 << 20)}))
  await expect(readBoundedTaskBody(response)).rejects.toThrow('bridge-upstream-oversize')
})

test('the bridge rejects a linked token and a DNS-selected upstream', async () => {
  const root = await mkdtemp(join(tmpdir(), 'agentgate-token-custody-'))
  owned.push(() => rm(root, {recursive:true, force:true}))
  const token = join(root, 'token')
  await writeFile(token, 'owned-scoped-test-token-123456', {mode:0o600})
  const linked = join(root, 'linked')
  await symlink(token, linked)
  const config = {socketPath:join(root, 'bridge.sock'),socketGID:process.getgid(),taskboardURL:'http://127.0.0.1:18180/',taskID:42,tokenFile:linked}
  await expect(startBridge(config)).rejects.toThrow('bridge-token-custody-invalid')
  await chmod(token, 0o644)
  await expect(startBridge({...config,tokenFile:token})).rejects.toThrow('bridge-token-custody-invalid')
  await chmod(token, 0o600)
  await expect(startBridge({...config,tokenFile:token,taskboardURL:'http://taskboard.example:18180/'})).rejects.toThrow('bridge-config-invalid')
  await expect(startBridge({...config,tokenFile:token,snapshotPath:join(root,'elsewhere.json')})).rejects.toThrow('bridge-config-invalid')
})

test('an upstream authorization failure invalidates an earlier task snapshot', async () => {
  const root = await mkdtemp(join(tmpdir(), 'agentgate-taskboard-auth-'))
  owned.push(() => rm(root, {recursive:true, force:true}))
  const tokenFile = join(root, 'token')
  await writeFile(tokenFile, 'owned-scoped-test-token-123456', {mode:0o600})
  let authorized = true
  const upstream = createServer((request, response) => {
    if (!request.headers.authorization) return void response.writeHead(401).end()
    if (!authorized) return void response.writeHead(403).end()
    response.writeHead(200, {'content-type':'application/json'})
    response.end(JSON.stringify({id:42,project_id:7,status:'Backlog',title:'Owned test'}))
  })
  await new Promise<void>(resolve => upstream.listen(0, '127.0.0.1', resolve))
  owned.push(() => new Promise(resolve => upstream.close(() => resolve())))
  const address = upstream.address()
  if (!address || typeof address === 'string') throw new Error('test-upstream-absent')
  const socketPath = join(root, 'bridge', 'taskboard.sock')
  const snapshotPath = join(root, 'bridge', 'task.json')
  const bridge = await startBridge({socketPath, socketGID:process.getgid(), taskboardURL:`http://127.0.0.1:${address.port}/`, taskID:42, tokenFile, snapshotPath})
  owned.push(() => new Promise(resolve => bridge.close(() => resolve())))
  expect(JSON.parse(await readFile(snapshotPath, 'utf8')).task.id).toBe(42)
  authorized = false
  expect((await call(socketPath, 'GET', '/task')).status).toBe(502)
  await expect(access(snapshotPath)).rejects.toThrow()
})
