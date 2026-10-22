#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Install the fixed diagnostic on an operator-owned disposable VM."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import urlunsplit

from gateway import read_root_file
from settings import validate_settings
from image_contract import validate_image


def checked_run(args, **kwargs):
    """Run a bounded trusted setup step."""
    return subprocess.run(args, check=True, timeout=45, **kwargs)


def image_id(reference, revision):
    """Bind a local image ID to the same public build revision."""
    item = json.loads(subprocess.check_output(['docker', 'image', 'inspect', reference], timeout=5))[0]
    if item['Config'].get('Labels', {}).get('org.opencontainers.image.revision') != revision:
        raise ValueError('target or bridge source revision differs')
    return item['Id']


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('instance', 'source-revision', 'artifacts', 'policy',
                 'target-image', 'bridge-image', 'token-file', 'public-key', 'ipv6-subnet'):
        parser.add_argument('--' + name, required=True)
    return parser.parse_args()


def main():
    args = arguments()
    if os.geteuid() != 0 or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,31}', args.instance):
        raise ValueError('root and a simple instance name are required')
    root = Path('/var/lib/agentgate-poc-' + args.instance)
    source = Path(__file__).resolve().parent
    artifacts = Path(args.artifacts).resolve()
    policy_bytes = Path(args.policy).read_bytes()
    info = json.loads(subprocess.check_output([str(artifacts / 'pilot-network-diagnostic'),
                                               'network-info', str(Path(args.policy).resolve())], timeout=5))
    board = info['document']['taskboard']
    authority = board['address'] + ':' + str(board['port'])
    data = dict(instance=args.instance, source=args.source_revision,
                policy_format=info['document']['version'],
                target_image=image_id(args.target_image, args.source_revision),
                bridge_image=image_id(args.bridge_image, args.source_revision),
                taskboard_url=urlunsplit(('http', authority, '/', '', '')),
                task_id=board['task_id'], ipv6_subnet=args.ipv6_subnet)
    settings = validate_settings(data, root)
    validate_image(data['target_image'])
    token = read_root_file(Path(args.token_file).resolve())
    if not 16 <= len(token.strip()) <= 4096:
        raise ValueError('invalid taskboard token length')
    # Refuse an existing install instead of changing an active endpoint.
    root.mkdir(mode=0o700)
    names = ['gateway.py', 'operator-gateway.py', 'settings.py', 'run-in-target.sh',
             'prepare-command.sh', 'start-target.sh', 'restart-target.sh', 'start-guard.sh',
             'install-key.py', 'stop.py', 'prepare-policy.py', 'prepare-resolver.py']
    for name in names:
        shutil.copyfile(source / name, root / name)
        (root / name).chmod(0o500)
    # The host-control objects always install; the active policy decides each command.
    for name in ('pilot-network-diagnostic', 'network_policy.bpf.o', 'fs_access.bpf.o', 'process_guard.bpf.o'):
        shutil.copyfile(artifacts / name, root / name)
        (root / name).chmod(0o500 if name == 'pilot-network-diagnostic' else 0o400)
    for name, content in [('settings.json', json.dumps(data).encode()), ('policy.json', policy_bytes),
                          ('poc-key.pub', Path(args.public_key).read_bytes())]:
        (root / name).write_bytes(content)
        (root / name).chmod(0o400)
    (root / 'secrets').mkdir(mode=0o700)
    (root / 'secrets/taskboard.token').write_bytes(token)
    (root / 'secrets/taskboard.token').chmod(0o600)
    checked_run(['python3', str(root / 'prepare-policy.py')])
    checked_run([str(root / 'start-target.sh')])
    # The first SSH request starts a fresh target. Setup never executes a payload.
    checked_run(['docker', 'rm', '-f', settings['name']], stdout=subprocess.DEVNULL)
    (root / 'initialized').touch(mode=0o600)
    checked_run([str(root / 'install-key.py')])
    print('diagnostic_configured=' + str(root))


if __name__ == '__main__':
    main()
