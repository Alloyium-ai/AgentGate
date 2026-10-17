// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
import { readFile, lstat, realpath, open } from 'node:fs/promises'
import { resolve, posix } from 'node:path'
import { constants } from 'node:fs'
import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'

export function sourceDigest(files) {
  const canonical = files.map(({ path, bytes, sha256 }) => ({ path, bytes, sha256 })).sort((a, b) => a.path.localeCompare(b.path))
  return createHash('sha256').update(JSON.stringify(canonical)).digest('hex')
}

export async function regularBytes(root, path) {
  if (typeof path !== 'string' || !path || posix.isAbsolute(path) || path.includes('\\') ||
      path.split('/').some(part => ['', '.', '..', '.git'].includes(part))) throw new Error('source_path_invalid')
  const full = resolve(root, path), stat = await lstat(full)
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 16 * 1024 * 1024 || await realpath(full) !== full) throw new Error('source_file_invalid')
  const file = await open(full, constants.O_RDONLY | constants.O_NOFOLLOW)
  try {
    const opened = await file.stat()
    if (opened.dev !== stat.dev || opened.ino !== stat.ino) throw new Error('source_file_changed')
    return await file.readFile()
  } finally { await file.close() }
}

export async function verifySource(root, expectedIdentifier) {
  root = await realpath(root)
  const manifest = JSON.parse(await regularBytes(root, 'SOURCE-MANIFEST.json'))
  const fields = new Set(['schema', 'source_id', 'source_sha256', 'stage', 'committed_bytes_verified', 'qualification', 'files', 'generated_artifacts'])
  if (manifest.schema !== 'agentgate.community.source-preview.v1' || manifest.stage !== 'experimental-source-preview' ||
      manifest.committed_bytes_verified !== true || Object.keys(manifest).some(key => !fields.has(key)) ||
      !Array.isArray(manifest.files) || !manifest.files.length || manifest.files.length > 2000 ||
      manifest.generated_artifacts && (!Array.isArray(manifest.generated_artifacts) || manifest.generated_artifacts.length > 2000)) throw new Error('source_manifest_invalid')
  const digest = sourceDigest(manifest.files)
  if (manifest.source_sha256 !== digest || manifest.source_id !== `agentgate-community-sha256:${digest}` ||
      expectedIdentifier && expectedIdentifier !== manifest.source_id) throw new Error('source_identifier_differs')
  const seen = new Set()
  for (const entry of [...manifest.files, ...(manifest.generated_artifacts ?? [])]) {
    if (Object.keys(entry).some(key => !['path', 'bytes', 'sha256'].includes(key)) || seen.has(entry.path) ||
        !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || !/^[a-f0-9]{64}$/.test(entry.sha256)) throw new Error('source_entry_invalid')
    seen.add(entry.path)
    const bytes = await regularBytes(root, entry.path)
    if (bytes.length !== entry.bytes || createHash('sha256').update(bytes).digest('hex') !== entry.sha256) throw new Error('source_hash_differs')
  }
  return manifest
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  verifySource(process.argv[2] ?? '.', process.argv[3]).then(manifest => console.log(JSON.stringify({
    result: 'SOURCE_CONSISTENCY_VERIFIED', source_id: manifest.source_id, files: manifest.files.length,
    trusted_identifier_compared: Boolean(process.argv[3]),
  }))).catch(() => { console.error('SOURCE_VERIFICATION_FAILED'); process.exitCode = 1 })
}
