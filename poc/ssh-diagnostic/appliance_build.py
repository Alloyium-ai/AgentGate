# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Build only the three POC components and the pinned QEMU appliance."""
import json
import hashlib
import tarfile
import os
from pathlib import Path
import subprocess
from appliance_common import DEFAULT_BASE, LABEL, output, run


def revision(root, explicit):
    value = explicit or output(['git', '-C', str(root), 'rev-parse', 'HEAD'])
    if len(value) !=40 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('a40-character source revision is required')
    return value


def builder(binding):
    name = binding.get('build_builder') or binding['name'] + '-build'
    existing = subprocess.run(['docker', 'buildx', 'inspect', name], capture_output=True, timeout=10)
    if existing.returncode:
        run(['docker', 'buildx', 'create', '--name', name, '--driver', 'docker-container'])
    run(['docker', 'buildx', 'inspect', name, '--bootstrap'], timeout=120, stdout=subprocess.DEVNULL)
    run(['docker', 'update', '--cpus', '4', '--memory', '6g', '--memory-swap', '6g',
         'buildx_buildkit_' + name + '0'], stdout=subprocess.DEVNULL)
    return name


def build(root, state, binding):
    name = builder(binding)
    base = binding['coding_base']
    run(['docker', 'pull', base], timeout=300, stdout=subprocess.DEVNULL)
    base_info = json.loads(output(['docker', 'image', 'inspect', base]))[0]
    pinned = base if '@sha256:' in base else base_info['RepoDigests'][0]
    binding['coding_base_digest'] = pinned
    specs = [('target', 'ssh/Dockerfile', 'coding-target'),
             ('bridge', 'ssh/Dockerfile', 'taskboard-bridge'),
             ('artifacts', 'poc/ssh-diagnostic/Dockerfile', None),
             ('appliance', 'poc/ssh-diagnostic/appliance/Dockerfile', None)]
    binding['images'] = {}
    for component, dockerfile, target in specs:
        tag = binding['name'] + '-' + component
        args = ['docker', 'buildx', 'build', '--builder', name, '--load', '--progress', 'plain',
                '--build-arg', 'SOURCE_REVISION=' + binding['revision'],
                '--label', LABEL + '=' + binding['owner'], '-t', tag, '-f', str(root / dockerfile)]
        if target:
            args += ['--target', target]
        if component == 'target':
            args += ['--build-arg', 'CODING_BASE_IMAGE=' + pinned]
        with (state / 'build.log').open('ab') as log:
            run(args + [str(root)], timeout=1800, stdout=log, stderr=subprocess.STDOUT)
        binding['images'][component] = output(['docker', 'image', 'inspect', tag, '--format', '{{.Id}}'])
    copy = output(['docker', 'create', '--name', binding['name'] + '-copy', binding['images']['artifacts'], 'true'])
    try:
        (state / 'artifacts').mkdir(exist_ok=True)
        for file in ('pilot-network-diagnostic', 'network_policy.bpf.o'):
            run(['docker', 'cp', copy + ':/' + file, str(state / 'artifacts' / file)])
    finally:
        run(['docker', 'rm', copy], stdout=subprocess.DEVNULL)
    run(['docker', 'save', '-o', str(state / 'images.tar'), binding['name'] + '-target', binding['name'] + '-bridge'], timeout=180)
    binding['archive_config_digests'] = archive_digests(state / 'images.tar', binding['name'])
    binding['archive_identity'] = archive_identity(state / 'images.tar', binding['name'])


def archive_digests(path, name):
    """Bind each owned tag to the actual exported configuration bytes."""
    result = {}
    with tarfile.open(path) as archive:
        manifest = json.load(archive.extractfile('manifest.json'))
        for component in ('target', 'bridge'):
            tag = name + '-' + component + ':latest'
            entries = [entry for entry in manifest if tag in (entry.get('RepoTags') or [])]
            if len(entries) !=1:
                raise ValueError('owned image tag missing or duplicated in export: ' + tag)
            raw = archive.extractfile(entries[0]['Config']).read()
            result[component] = 'sha256:' + hashlib.sha256(raw).hexdigest()
    return result


def archive_identity(path, name):
    """Retain config bytes, rootfs diff IDs, and matching OCI manifest digests."""
    configs = archive_digests(path, name)
    result = {key: {'config_digest': value, 'manifest_digests': [], 'rootfs_diff_ids': []}
              for key, value in configs.items()}
    with tarfile.open(path) as archive:
        files = {entry.name: entry for entry in archive.getmembers() if entry.isfile()}
        docker_manifest = json.load(archive.extractfile('manifest.json'))
        for component, identity in result.items():
            entry = next(item for item in docker_manifest if name + '-' + component + ':latest' in (item.get('RepoTags') or []))
            config = json.load(archive.extractfile(entry['Config']))
            identity['rootfs_diff_ids'] = config.get('rootfs', {}).get('diff_ids', [])
        for entry in files.values():
            if not entry.name.startswith('blobs/sha256/') or entry.size > 1024 * 1024:
                continue
            raw = archive.extractfile(entry).read()
            try:
                manifest = json.loads(raw)
            except (ValueError, UnicodeError):
                continue
            if manifest.get('schemaVersion') !=2 or not isinstance(manifest.get('config'), dict) or not isinstance(manifest.get('layers'), list):
                continue
            digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
            for identity in result.values():
                if manifest['config'].get('digest') == identity['config_digest']:
                    identity['manifest_digests'].append(digest)
    return result
