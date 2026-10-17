// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
import { readFile, writeFile, readdir, mkdir, lstat } from 'node:fs/promises'
import { resolve, dirname } from 'node:path'
import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'
import { verifySource, regularBytes } from './verify-source.mjs'
import { reviewedModule, verifySupplierEvidence, verifyLicenseFiles } from './licenses.mjs'

const hash = value => createHash('sha256').update(value).digest('hex')
const reference = (kind, name, version) => `${kind}:${hash(`${name}@${version}`)}`

export function parseModuleRecords(text) {
  if (Buffer.byteLength(text) > 8 * 1024 * 1024) throw new Error('module_records_too_large')
  const records = []; let depth = 0, start = 0, quoted = false, escaped = false
  for (let i = 0; i < text.length; i++) {
    const char = text[i]
    if (!depth) { if (/\s/.test(char)) continue; if (char !== '{') throw new Error('module_record_invalid'); start = i }
    if (quoted) { if (escaped) escaped = false; else if (char === '\\') escaped = true; else if (char === '"') quoted = false; continue }
    if (char === '"') quoted = true
    else if (char === '{' || char === '[') depth++
    else if (char === '}' || char === ']') { depth--; if (!depth) records.push(JSON.parse(text.slice(start, i + 1))) }
    if (depth < 0 || records.length > 1000) throw new Error('module_record_invalid')
  }
  if (depth || quoted || !records.length) throw new Error('module_record_incomplete')
  return records
}

function goComponents(records, sums, evidence) {
  const known = new Set(sums.trim().split('\n').map(line => line.trim()))
  return records.map(module => {
    if (!module.Path || !module.Version || module.Error || !known.has(`${module.Path} ${module.Version} ${module.Sum}`)) throw new Error('module_checksum_unbound')
    const review = reviewedModule(module, evidence)
    return { type: 'library', name: module.Path, version: module.Version, 'bom-ref': reference('go', module.Path, module.Version),
      purl: `pkg:golang/${module.Path}@${encodeURIComponent(module.Version)}`,
      licenses: [{ expression: review.expression }],
      properties: [{ name: 'agentgate:go-module-directory-checksum', value: module.Sum },
        { name: 'agentgate:supplier-license-scope', value: review.terms_scope },
        { name: 'agentgate:binary-module-records', value: review.binaries.join(',') || 'default source checks only' },
        { name: 'agentgate:additional-supplier-terms', value: review.additional_terms }] }
  })
}

function npmComponents(lock) {
  if (lock.lockfileVersion !== 3 || !lock.packages) throw new Error('npm_lock_invalid')
  return Object.entries(lock.packages).filter(([path]) => path !== '').map(([path, pkg]) => {
    const name = pkg.name ?? path.split('node_modules/').at(-1)
    if (!name || !pkg.version || !pkg.integrity || !pkg.resolved?.startsWith('https://registry.npmjs.org/')) throw new Error('npm_package_unbound')
    return { type: 'library', name, version: pkg.version, 'bom-ref': reference('npm', path, pkg.version),
      purl: `pkg:npm/${name.replace('@', '%40')}@${encodeURIComponent(pkg.version)}`,
      ...(pkg.license ? { licenses: [{ license: { name: pkg.license } }] } : {}),
      properties: [{ name: 'agentgate:npm-lock-path', value: path }, { name: 'agentgate:download-integrity', value: pkg.integrity },
        { name: 'agentgate:source-inventory-scope', value: 'locked package; optional platforms may not install' }] }
  })
}

export function dependencyBom(manifest, modules, sums, lock, created, evidence) {
  const components = [...goComponents(modules, sums, evidence), ...npmComponents(lock)]
  const refs = components.map(component => component['bom-ref'])
  if (new Set(refs).size !== refs.length) throw new Error('dependency_reference_duplicate')
  return { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1,
    metadata: { ...(created ? { timestamp: created } : {}), component: { type: 'application', name: 'AgentGate experimental source preview',
      'bom-ref': manifest.source_id, version: manifest.source_sha256,
      licenses: [{ expression: 'Apache-2.0 AND GPL-2.0-only AND CC-BY-4.0' }],
      properties: [{ name: 'agentgate:inventory-scope', value: 'Go default build/test dependency set and npm lock; not a linked-binary or runtime-image inventory' }] } },
    components, dependencies: [{ ref: manifest.source_id, dependsOn: refs }] }
}

async function writeArtifact(root, path, bytes) {
  await mkdir(dirname(resolve(root, path)), { recursive: true })
  try { await writeFile(resolve(root, path), bytes, { flag: 'wx', mode: 0o644 }) }
  catch (error) {
    if (error.code !== 'EEXIST' || !(await regularBytes(root, path)).equals(bytes)) throw new Error('generated_artifact_differs')
  }
}

export async function copyNotices(source, destination, prefix = '') {
  const files = []
  for (const name of (await readdir(resolve(source, prefix))).sort()) {
    const path = prefix ? `${prefix}/${name}` : name, stat = await lstat(resolve(source, path))
    if (stat.isSymbolicLink()) throw new Error('supplier_notice_linked')
    if (stat.isDirectory()) files.push(...await copyNotices(source, destination, path))
    else if (/license|notice|copying/i.test(name) || path.split('/').some(part => /^(?:licenses?|notices?)$/i.test(part))) {
      const bytes = await regularBytes(source, path), target = `DEPENDENCY-NOTICES/${path}`
      await writeArtifact(destination, target, bytes)
      files.push({ path: target, bytes: bytes.length, sha256: hash(bytes) })
    }
    if (files.length > 1900) throw new Error('supplier_notice_bound')
  }
  return files
}

async function main() {
  const root = resolve(process.argv[2] ?? '.'), manifest = await verifySource(root)
  if (!process.argv[3]) throw new Error('module_record_file_required')
  const modules = parseModuleRecords(await readFile(resolve(process.argv[3]), 'utf8'))
  const sums = (await regularBytes(root, 'go.sum')).toString(), lock = JSON.parse(await regularBytes(root, 'web/package-lock.json'))
  const evidence = JSON.parse(await regularBytes(root, 'DEPENDENCY-LICENSES.json'))
  await verifyLicenseFiles(root, manifest, JSON.parse(await regularBytes(root, 'COMPONENT-LICENSES.json')))
  const notices = await copyNotices(dirname(dirname(resolve(process.argv[3]))), root)
  if (!notices.length) throw new Error('supplier_notices_missing')
  verifySupplierEvidence(modules, evidence, notices, await readFile(resolve(dirname(process.argv[3]), 'build.txt'), 'utf8'))
  const bom = dependencyBom(manifest, modules, sums, lock, undefined, evidence)
  bom.metadata.component.properties.push({ name: 'agentgate:supplier-notice-files', value: String(notices.length) })
  const output = Buffer.from(JSON.stringify(bom, null, 2) + '\n')
  await writeArtifact(root, 'SBOM.cdx.json', output)
  manifest.generated_artifacts = [...notices, { path: 'SBOM.cdx.json', bytes: output.length, sha256: hash(output) }]
  await writeFile(resolve(root, 'SOURCE-MANIFEST.json'), JSON.stringify(manifest, null, 2) + '\n', { mode: 0o644 })
  console.log(JSON.stringify({ result: 'SOURCE_DEPENDENCY_INVENTORY_CREATED', source_id: manifest.source_id, components: bom.components.length }))
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch(error => {
  const known = new Set(['module_checksum_unbound', 'npm_package_unbound', 'supplier_notices_missing', 'generated_artifact_differs'])
  console.error('SOURCE_DEPENDENCY_INVENTORY_FAILED', known.has(error.message) ? error.message : 'input_or_io_invalid'); process.exitCode = 1
})
