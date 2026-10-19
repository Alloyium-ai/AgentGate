#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Stop one idle diagnostic and revoke its forced SSH key; retain audit and workspace."""
import fcntl
import os
from pathlib import Path
import subprocess

from settings import load_settings


def main():
    root = Path(__file__).resolve().parent
    settings = load_settings(root / 'settings.json')
    lock = os.open(root / 'single-job.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        domain = Path(settings['domain'])
        if domain.exists() and 'populated 0' not in (domain / 'cgroup.events').read_text().splitlines():
            raise RuntimeError('diagnostic domain is active; retry after the command ends')
        if Path(settings['pins']).exists():
            raise RuntimeError('guard pins remain; inspect the private guard log before stopping')
        public = (root / 'poc-key.pub').read_text().split()
        key_path = Path('/root/.ssh/authorized_keys')
        forced = f'restrict,command="{root}/operator-gateway.py" {public[0]} {public[1]}'
        lines = key_path.read_text().splitlines()
        temporary = key_path.with_name('authorized_keys.agentgate-stop')
        with temporary.open('x') as output:
            os.chmod(temporary, 0o600)
            output.write('\n'.join(line for line in lines if line != forced) + '\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, key_path)
        for container in (settings['name'], settings['bridge_container']):
            inspected = subprocess.run(['docker', 'container', 'inspect', container], capture_output=True, timeout=5)
            if inspected.returncode == 0:
                subprocess.run(['docker', 'rm', '-f', container], check=True, timeout=10,
                               stdout=subprocess.DEVNULL)
        for network in (settings['network'], settings['bridge_network']):
            subprocess.run(['docker', 'network', 'rm', network], check=True, timeout=10,
                           stdout=subprocess.DEVNULL)
        if domain.exists():
            domain.rmdir()
        print('diagnostic_stopped=true audit_and_workspace_retained=true')
    finally:
        os.close(lock)


if __name__ == '__main__':
    main()
