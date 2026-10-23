# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Configure or check the exact guest installation without exposing a management key."""
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
from appliance_common import admin, copy_guest, ready_command, run, ssh, write

GUEST = '/var/lib/agentgate-poc-demo'

def guest_owner(info):
    """Bind staged inputs to root custody inside the owned guest."""
    info.uid = info.gid = 0
    info.uname = info.gname = 'root'
    return info



def configure(root, state, binding):
    """Transfer versioned components and secrets through pinned management SSH."""
    installed = admin(state, binding, 'test ! -e ' + GUEST + '/settings.json || echo installed')
    if installed:
        admin(state, binding, 'test -e ' + GUEST + '/appliance-installed && test -e ' + GUEST + '/initialized || { echo \"guest setup is partial; state retained; inspect the setup logs or use a new state directory\" >&2; exit 1; }')
        actual = json.loads(admin(state, binding, 'cat ' + GUEST + '/settings.json'))
        if (actual['source'] != binding['revision'] or actual['target_image'] != binding.get('guest_images', binding['images'])['target'] or
                actual['bridge_image'] != binding.get('guest_images', binding['images'])['bridge']):
            raise ValueError('guest source/image binding differs; existing state retained')
        return
    package = state / 'setup.tar'
    with tarfile.open(package, 'w') as out:
        for file in (root / 'poc/ssh-diagnostic').glob('*'):
            if file.is_file() and file.suffix in ('.py', '.sh'):
                out.add(file, arcname='source/' + file.name, filter=guest_owner)
        for file in (state / 'artifacts').iterdir():
            out.add(file, arcname='artifacts/' + file.name, filter=guest_owner)
        for file in ('images.tar', 'policy.json', 'taskboard.token', 'workload-key.pub'):
            out.add(state / file, arcname=file, filter=guest_owner)
    package.chmod(0o600)
    copy_guest(state, binding, package, '/root/agentgate-setup.tar')
    command = ('set -eu; mkdir -p /root/agentgate-setup; chmod 0700 /root/agentgate-setup; '
               'tar -xf /root/agentgate-setup.tar -C /root/agentgate-setup; cd /root/agentgate-setup; '
               'chmod 0600 taskboard.token workload-key.pub policy.json; docker load -i images.tar >/dev/null')
    admin(state, binding, command, timeout=120)
    binding['guest_images'] = resolve_guest_images(state, binding)
    write(state / 'binding.json', json.dumps(binding, sort_keys=True).encode())
    images = binding['guest_images']
    command = ('cd /root/agentgate-setup; python3 source/configure.py --instance demo --source-revision ' + binding['revision'] +
               ' --artifacts artifacts --policy policy.json --token-file /root/agentgate-setup/taskboard.token'
               ' --public-key workload-key.pub --ipv6-subnet fd42:a6e7:2026:1234::/64'
               ' --target-image ' + images['target'] + ' --bridge-image ' + images['bridge'] +
               ' && docker update --restart unless-stopped ag-mvp-demo-bridge >/dev/null')
    admin(state, binding, command, timeout=120)


def resolve_guest_images(state, binding):
    """Retain separate host and guest IDs with exact archive digest verification."""
    result = {}
    for component in ('target', 'bridge'):
        tag = binding['name'] + '-' + component + ':latest'
        items = json.loads(admin(state, binding, 'docker image inspect ' + shlex.quote(tag)))
        item = items[0]
        identity = binding['archive_identity'][component]
        allowed = {binding['images'][component], identity['config_digest']} | set(identity['manifest_digests'])
        if item.get('RootFS', {}).get('Layers', []) != identity['rootfs_diff_ids']:
            raise ValueError('guest rootfs differs from the exact exported config')
        if item['Id'] not in allowed or item['Config'].get('Labels', {}).get('org.opencontainers.image.revision') != binding['revision']:
            raise ValueError('guest image digest/source differs from the exported image')
        result[component] = item['Id']
    return result



class GuestBusy(RuntimeError):
    """A guarded command holds the guest's single-job lock."""


BUSY_EXIT = 75


def guest_locked(command):
    """Run a guest shell command only while no guarded command is active."""
    return 'flock -n -E ' + str(BUSY_EXIT) + ' ' + GUEST + '/single-job.lock sh -ec ' + shlex.quote(command)


def admin_locked(state, binding, command, timeout=60):
    try:
        return admin(state, binding, guest_locked(command), timeout)
    except subprocess.CalledProcessError as error:
        if error.returncode == BUSY_EXIT:
            raise GuestBusy('a guarded command is running in the appliance; retry when it finishes') from None
        raise


def install_policy(state, binding, path):
    """Copy a validated policy to the guest and swap it in between commands."""
    copy_guest(state, binding, path, GUEST + '/policy.pending.json')
    pending = GUEST + '/policy.pending.json'
    admin_locked(state, binding, 'chmod 0600 ' + pending + '; ' + GUEST + '/pilot-network-diagnostic network-info ' +
                 pending + ' >/dev/null; sync ' + pending + '; mv ' + pending + ' ' + GUEST + '/policy.json')


def health(state, binding):
    """Check exact source, policy and bridge state without starting a command."""
    data = json.loads(admin(state, binding, 'cat ' + GUEST + '/settings.json'))
    if data['source'] != binding['revision'] or data['target_image'] != binding.get('guest_images', binding['images'])['target']:
        raise ValueError('guest source/image binding differs')
    info = json.loads(admin(state, binding, GUEST + '/pilot-network-diagnostic network-info ' + GUEST + '/policy.json'))
    if info['digest'] != binding['policy_digest']:
        raise ValueError('guest policy binding differs; run: appliance.py grant sync')
    admin(state, binding, 'test "$(docker inspect ag-mvp-demo-bridge --format \'{{.State.Running}}\')" = true')
    return {'state': 'ready', 'policy_digest': info['digest'], 'ssh': ready_command(state, binding)}


def audit(state, binding):
    result = admin(state, binding, 'cat ' + GUEST + '/audit.jsonl ' + GUEST + '/operator-events.jsonl', timeout=15)
    # The private copy is created at mode 0600 and replaced atomically.
    write(state / 'audit.jsonl', (result + '\n').encode())
    return result


def transition(state, binding, stopping):
    """Hold the command lock while validating idle state and changing the stop marker."""
    code = """from pathlib import Path
root=Path('/var/lib/agentgate-poc-demo')
domain=Path('/sys/fs/cgroup/ag-mvp-demo-domain')
pins=Path('/sys/fs/bpf/ag-mvp-net-ag-mvp-demo-domain')
host_pins=Path('/sys/fs/bpf/ag-mvp-host-ag-mvp-demo-domain')
assert not domain.exists() or 'populated 0' in (domain/'cgroup.events').read_text().splitlines(), 'command is active'
assert not pins.exists() and not host_pins.exists(), 'guard pins remain'
import subprocess
item=subprocess.run(['docker','inspect','ag-mvp-demo-target'],capture_output=True)
assert item.returncode != 0 and b'no such object' in item.stderr.lower(), 'owned target remains; inspect audit; state retained'
marker=root/'appliance-stopping'
ACTION
"""
    action = "marker.touch(mode=0o400)" if stopping else "marker.unlink(missing_ok=True)"
    command = 'flock -n ' + GUEST + '/single-job.lock python3 -c ' + shlex.quote(code.replace('ACTION', action))
    admin(state, binding, command)
