# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Protected state and strict SSH helpers for the Docker VM appliance."""
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import stat
import subprocess
import time

DEFAULT_BASE = 'ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55'
LABEL = 'ai.agentgate.poc.owner'


def run(args, timeout=30, **kwargs):
    """Run one bounded operation, retaining subprocess errors."""
    return subprocess.run(args, check=True, timeout=timeout, **kwargs)


def output(args, timeout=30):
    return subprocess.check_output(args, timeout=timeout).decode().strip()


def protected(path):
    """Read a caller-owned regular input without following a symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077:
            raise ValueError('input must be a caller-owned regular file, mode0600: ' + str(path))
        raw = os.read(fd, 65537)
        if len(raw) > 65536:
            raise ValueError('input exceeds65536 bytes')
        return raw
    finally:
        os.close(fd)


def write(path, raw):
    """Atomically replace a protected state file."""
    temporary = path.with_name(path.name + '.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as target:
        target.write(raw); target.flush(); os.fsync(target.fileno())
    os.replace(temporary, path)


def preflight():
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'amd64'):
        raise ValueError('supported host required: Linux x86_64 with Docker and /dev/kvm')
    if not Path('/dev/kvm').is_char_device():
        raise ValueError('supported host requires the /dev/kvm character device')
    for name in ('docker', 'ssh', 'scp', 'ssh-keygen'):
        if not shutil.which(name):
            raise ValueError('required host command is missing: ' + name)
    run(['docker', 'info'], stdout=subprocess.DEVNULL)
    run(['docker', 'buildx', 'version'], stdout=subprocess.DEVNULL)


def load(path):
    return json.loads(protected(path / 'binding.json'))


def ssh(state, binding, key='management-key'):
    return ['ssh', '-T', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=3',
            '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'HostKeyAlias=' + binding['name'],
            '-o', 'UserKnownHostsFile=' + str(state / 'known_hosts'),
            '-i', str(state / key), '-p', str(binding['port']), 'root@127.0.0.1']


def admin(state, binding, command, timeout=30):
    return output(ssh(state, binding) + [command], timeout)


def copy_guest(state, binding, source, destination):
    args = ssh(state, binding)
    # scp shares all strict identity options, with a capital P for the port.
    args[0] = 'scp'; args.remove('-T'); args[-3] = '-P'
    args = args[:-1] + [str(source), 'root@127.0.0.1:' + destination]
    run(args, timeout=180)


def wait_guest(state, binding):
    deadline = time.monotonic() + 600
    command = 'test -e /var/lib/cloud/agentgate-ready && test "$(uname -r)" =6.8.0-142-generic && grep -qw bpf /sys/kernel/security/lsm && systemctl is-active --quiet docker'
    # A quoted exact kernel comparison also produces a useful setup diagnostic.
    command = command.replace('=6.8', '= 6.8')
    last = ''
    while time.monotonic() < deadline:
        result = subprocess.run(ssh(state, binding) + [command], capture_output=True, timeout=8)
        if result.returncode == 0:
            return
        last = result.stderr.decode(errors='replace')[-1000:]
        time.sleep(2)
    raise RuntimeError('guest readiness timed out; inspect Docker logs and the protected state directory. ' + last)


def inspect_owned(binding):
    result = subprocess.run(['docker', 'inspect', binding['name']], capture_output=True, timeout=5)
    if result.returncode:
        if b'No such object' in result.stderr:
            return None
        raise RuntimeError(result.stderr.decode())
    item = json.loads(result.stdout)[0]
    if item['Config'].get('Labels', {}).get(LABEL) != binding['owner']:
        raise ValueError('container name belongs to another instance')
    if item['Image'] != binding['images']['appliance']:
        raise ValueError('appliance image binding differs; use a new state directory')
    return item


def ready_command(state, binding):
    return shlex.join(ssh(state, binding, 'workload-key'))
