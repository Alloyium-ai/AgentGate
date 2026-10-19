#!/usr/bin/env bun
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// A local read-only bridge keeps the upstream bearer outside the workload.
import { createServer, type Server } from 'node:http'
import { constants } from 'node:fs'
import { chmod, chown, lstat, mkdir, open, rename, unlink } from 'node:fs/promises'
import { dirname, isAbsolute, join } from 'node:path'
import { isIP } from 'node:net'
import { randomUUID } from 'node:crypto'

export type BridgeConfig = {
  socketPath: string
  socketGID: number
  taskboardURL: string
  taskID: number
  tokenFile: string
  snapshotPath?: string
}

const MAX_TASK_RESPONSE_BYTES = 1 << 20

export async function readBoundedTaskBody(response: Response): Promise<unknown> {
  if (!response.body) throw new Error('bridge-upstream-empty')
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  try {
    while (true) {
      const {done, value} = await reader.read()
      if (done) break
      size += value.byteLength
      if (size > MAX_TASK_RESPONSE_BYTES) throw new Error('bridge-upstream-oversize')
      chunks.push(value)
    }
    const raw = new Uint8Array(size)
    let offset = 0
    for (const chunk of chunks) { raw.set(chunk, offset); offset += chunk.byteLength }
    return JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(raw))
  } finally {
    await reader.cancel().catch(() => {})
    reader.releaseLock()
  }
}

function requireConfig(config: BridgeConfig): URL {
  const url = new URL(config.taskboardURL)
  const host = url.hostname.startsWith('[') && url.hostname.endsWith(']') ? url.hostname.slice(1, -1) : url.hostname
  if (!isAbsolute(config.socketPath) || !isAbsolute(config.tokenFile) ||
      !Number.isSafeInteger(config.socketGID) || config.socketGID < 0 ||
      !Number.isSafeInteger(config.taskID) || config.taskID < 1 ||
      !['http:', 'https:'].includes(url.protocol) || !isIP(host) ||
      !url.port || url.username || url.password || url.pathname !== '/' || url.search || url.hash ||
      (config.snapshotPath !== undefined && config.snapshotPath !== join(dirname(config.socketPath), 'task.json'))) {
    throw new Error('bridge-config-invalid')
  }
  return url
}

async function readToken(path: string): Promise<string> {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW)
    .catch(() => { throw new Error('bridge-token-custody-invalid') })
  try {
    const before = await file.stat()
    if (!before.isFile() || before.nlink !== 1 || (before.mode & 0o077) !== 0 ||
        before.uid !== process.getuid() || before.size < 16 || before.size > 4096) {
      throw new Error('bridge-token-custody-invalid')
    }
    const token = (await file.readFile('utf8')).trim()
    const after = await file.stat()
    if (!after.isFile() || before.dev !== after.dev || before.ino !== after.ino ||
        before.uid !== after.uid || before.mode !== after.mode || before.nlink !== after.nlink ||
        before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) {
      throw new Error('bridge-token-custody-invalid')
    }
    if (!/^[\x21-\x7e]{16,4096}$/.test(token)) throw new Error('bridge-token-invalid')
    return token
  } finally {
    await file.close()
  }
}

export async function startBridge(config: BridgeConfig): Promise<Server> {
  const upstream = requireConfig(config)
  const token = await readToken(config.tokenFile)
  const parent = dirname(config.socketPath)
  await mkdir(parent, { recursive: true, mode: 0o750 })
  await chown(parent, process.getuid(), config.socketGID)
  await chmod(parent, 0o750)
  const taskURL = new URL(`/api/tasks/${config.taskID}`, upstream)
  const credentialGate = async (): Promise<number> => {
    const result = await fetch(taskURL, {
      method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(4000),
    })
    await result.body?.cancel()
    if (result.status !== 401 && result.status !== 403) {
      throw new Error('bridge-upstream-not-credential-gated')
    }
    return result.status
  }
  const fetchTask = async () => {
    await credentialGate()
    const result = await fetch(taskURL, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
      redirect: 'manual',
      signal: AbortSignal.timeout(4000),
    })
    if (result.status !== 200) throw new Error('bridge-upstream-denied')
    const decoded = await readBoundedTaskBody(result)
    const body = decoded && typeof decoded === 'object' ? decoded as Record<string, unknown> : {}
    const nested = body.task
    const task = nested && typeof nested === 'object' ? nested as Record<string, unknown> : body
    if (task.id !== config.taskID || typeof task.project_id !== 'number' || !Number.isSafeInteger(task.project_id) ||
        typeof task.status !== 'string' || task.status.length > 64 ||
        typeof task.title !== 'string' || task.title.length > 512) throw new Error('bridge-task-shape-differs')
    return {id:task.id, project_id:task.project_id, status:task.status, title:task.title}
  }
  const server = createServer(async (request, response) => {
    if (request.method !== 'GET') {
      response.writeHead(403).end()
      return
    }
    if (request.url === '/auth-probe') {
      try {
        const status = await credentialGate()
        response.writeHead(200, {'content-type':'application/json', 'cache-control':'no-store'})
        response.end(JSON.stringify({task_id:config.taskID, upstream_status:status}))
      } catch {
        if (config.snapshotPath) await unlink(config.snapshotPath).catch(() => {})
        response.writeHead(502).end()
      }
      return
    }
    if (request.url !== '/task') {
      response.writeHead(403).end()
      return
    }
    try {
      const task = await fetchTask()
      response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' })
      response.end(JSON.stringify(task))
    } catch {
      if (config.snapshotPath) await unlink(config.snapshotPath).catch(() => {})
      response.writeHead(502).end()
    }
  })
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(config.socketPath, () => { server.removeListener('error', reject); resolve() })
  })
  await chown(config.socketPath, process.getuid(), config.socketGID)
  await chmod(config.socketPath, 0o660)
  const identity = await lstat(config.socketPath)
  server.on('close', () => { void lstat(config.socketPath).then(now => {
    if (now.dev === identity.dev && now.ino === identity.ino) return unlink(config.socketPath)
  }).catch(() => {}) })
  if (config.snapshotPath) {
    let refreshing = false
    const refresh = async () => {
      if (refreshing) return
      refreshing = true
      try {
        const task = await fetchTask()
        const temporary = `${config.snapshotPath}.${randomUUID()}`
        const file = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o644)
        try {
          await file.writeFile(JSON.stringify({protocol:'agentgate.taskboard-read.v1',task,valid_until:new Date(Date.now()+15000).toISOString()}))
          await file.chmod(0o644)
          await file.sync()
        } finally { await file.close() }
        try { await rename(temporary, config.snapshotPath!) }
        finally { await unlink(temporary).catch(() => {}) }
      } catch {
        await unlink(config.snapshotPath!).catch(() => {})
      } finally { refreshing = false }
    }
    await refresh()
    const interval = setInterval(() => { void refresh() }, 5000)
    interval.unref()
    server.on('close', () => { clearInterval(interval); void unlink(config.snapshotPath!).catch(() => {}) })
  }
  return server
}

if (import.meta.main) {
  const config: BridgeConfig = {
    socketPath: process.env.AGENTGATE_TASKBOARD_SOCKET ?? '',
    socketGID: Number(process.env.AGENTGATE_TASKBOARD_SOCKET_GID),
    taskboardURL: process.env.AGENTGATE_TASKBOARD_URL ?? '',
    taskID: Number(process.env.AGENTGATE_TASKBOARD_TASK_ID),
    tokenFile: process.env.AGENTGATE_TASKBOARD_TOKEN_FILE ?? '',
    snapshotPath: process.env.AGENTGATE_TASKBOARD_SNAPSHOT ?? '',
  }
  await startBridge(config).catch(() => { process.stderr.write('taskboard-bridge-start-failed\n'); process.exitCode = 1 })
}
