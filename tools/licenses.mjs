// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
import { readFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { regularBytes, verifySource } from './verify-source.mjs'

const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const licenses = new Set(['Apache-2.0', 'GPL-2.0-only', 'CC-BY-4.0'])

export function validateLicenseMap(manifest, map) {
  if (map.schema !== 'agentgate.community.licenses.v1' || map.copyright_owner !== 'Dan Metcalf' || !Array.isArray(map.files)) throw new Error('license_map_invalid')
  const expected = new Set(manifest.files.map(file => file.path)), seen = new Set()
  for (const file of map.files) {
    if (!expected.has(file.path) || seen.has(file.path) || !licenses.has(file.license) || !['code', 'metadata', 'documentation', 'license-text', 'BPF'].includes(file.kind)) throw new Error('license_map_scope_differs')
    if (file.kind === 'BPF' && (file.license !== 'GPL-2.0-only' || !/^[a-f0-9]{64}$/.test(file.preserved_sha256 ?? ''))) throw new Error('BPF_license_differs')
    if (file.kind === 'code' && file.license !== 'Apache-2.0') throw new Error('first_party_license_differs')
    seen.add(file.path)
  }
  if (seen.size !== expected.size) throw new Error('license_map_incomplete')
  return map.files
}

export async function verifyLicenseFiles(root, manifest, map) {
  for (const file of validateLicenseMap(manifest, map)) {
    const bytes = await regularBytes(root, file.path)
    if (file.preserved_sha256 && hash(bytes) !== file.preserved_sha256) throw new Error('preserved_license_source_differs')
    if (file.kind === 'code') {
      const header = bytes.toString('utf8').split('\n').slice(0, 8).join('\n')
      if (!/SPDX-License-Identifier: Apache-2\.0\b/.test(header) || !header.includes('Copyright (c) 2026 Dan Metcalf')) throw new Error('first_party_header_differs')
    }
  }
  return map.files.length
}

export function reviewedModule(module, evidence) {
  if (evidence?.schema !== 'agentgate.community.dependency-licenses.v1' || !Array.isArray(evidence.modules)) throw new Error('dependency_license_evidence_invalid')
  const matches = evidence.modules.filter(record => record.module === module.Path && record.version === module.Version)
  if (matches.length !== 1 || matches[0].checksum !== module.Sum || typeof matches[0].expression !== 'string' || !matches[0].notices?.length) throw new Error('module_license_unreviewed')
  return matches[0]
}

export function verifySupplierEvidence(modules, evidence, notices, buildText) {
  const actual = new Map(notices.map(file => [file.path, file.sha256]))
  const linked = new Map(); let binary
  for (const line of buildText.split('\n')) {
    if (line.startsWith('/')) binary = line.split(':')[0].slice(1)
    const fields = line.split('\t')
    if (fields[1] === 'dep') {
      const key = `${fields[2]}@${fields[3]}`, values = linked.get(key) ?? []
      values.push(binary); linked.set(key, values)
    }
  }
  const used = new Set()
  for (const module of modules) {
    const record = reviewedModule(module, evidence), key = `${module.Path}@${module.Version}`
    if (used.has(key)) throw new Error('dependency_reference_duplicate')
    used.add(key)
    for (const notice of record.notices) if (actual.get(notice.path) !== notice.sha256) throw new Error('supplier_license_bytes_differ')
    if (JSON.stringify([...(linked.get(key) ?? [])].sort()) !== JSON.stringify([...record.binaries].sort())) throw new Error('dependency_binary_scope_differs')
  }
  if (used.size !== evidence.modules.length || [...linked.keys()].some(key => !used.has(key))) throw new Error('dependency_license_scope_differs')
}

async function main() {
  const root = resolve(process.argv[2] ?? '.'), manifest = await verifySource(root)
  const map = JSON.parse(await readFile(resolve(root, 'COMPONENT-LICENSES.json'), 'utf8'))
  const count = await verifyLicenseFiles(root, manifest, map)
  console.log(JSON.stringify({ result: 'SOURCE_LICENSE_SCOPE_VERIFIED', files: count, first_party: 'Apache-2.0', BPF: 'GPL-2.0-only', documentation: 'CC-BY-4.0' }))
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch(() => { console.error('SOURCE_LICENSE_SCOPE_FAILED'); process.exitCode = 1 })
