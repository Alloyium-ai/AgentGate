# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Boot only the owned persistent QEMU disk; handle Docker stop through ACPI."""
import json
from pathlib import Path
import signal
import socket
import subprocess
import time

ROOT = Path('/state')

def run(args):
    subprocess.run(args, check=True, timeout=30)


def seed():
    """Provision pinned keys, Docker, and BPF LSM inside the disposable guest."""
    config = json.loads((ROOT / 'binding.json').read_text())
    public = (ROOT / 'management-key.pub').read_text().strip()
    private = (ROOT / 'guest-host-key').read_text()
    host_public = (ROOT / 'guest-host-key.pub').read_text().strip()
    data = {'disable_root': False, 'ssh_pwauth': False,
            'users': [{'name': 'root', 'lock_passwd': True, 'ssh_authorized_keys': [public]}],
            'ssh_deletekeys': False,
            'ssh_keys': {'ed25519_private': private, 'ed25519_public': host_public},
            'package_update': True, 'packages': ['docker.io'],
            'write_files': [
                {'path': '/etc/alloyium-disposable-vm', 'permissions': '0444',
                 'content': 'kernel-poc-' + config['name']},
                {'path': '/etc/ssh/sshd_config.d/01-agentgate.conf',
                 'content': 'PermitRootLogin prohibit-password\nPasswordAuthentication no\n'},
                {'path': '/etc/fstab', 'append': True,
                 'content': '\nbpf /sys/fs/bpf bpf defaults 0 0\n'}],
            'runcmd': [['sh', '-ec',
                'mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf; '
                'list=$(cat /sys/kernel/security/lsm); '
                'printf \'GRUB_CMDLINE_LINUX="lsm=%s,bpf"\n\' "$list" > /etc/default/grub.d/99-agentgate.cfg; '
                'update-grub; systemctl enable docker; touch /var/lib/cloud/agentgate-ready; reboot']]}
    (ROOT / 'user-data').write_text('#cloud-config\n' + json.dumps(data))
    (ROOT / 'meta-data').write_text('instance-id: ' + config['name'] + '\nlocal-hostname: agentgate-poc\n')
    run(['cloud-localds', str(ROOT / 'seed.img'), str(ROOT / 'user-data'), str(ROOT / 'meta-data')])
    run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', '/opt/agentgate/noble.img', str(ROOT / 'disk.qcow2')])
    run(['qemu-img', 'resize', str(ROOT / 'disk.qcow2'), '20G'])


def main():
    if not (ROOT / 'disk.qcow2').exists():
        seed()
    monitor = ROOT / 'monitor.sock'
    monitor.unlink(missing_ok=True)
    relay = subprocess.Popen(['socat', '-t', '300', '-T', '300',
        'TCP-LISTEN:23264,bind=0.0.0.0,reuseaddr,fork,max-children=16',
        'TCP:127.0.0.1:23265,connect-timeout=3'])
    process = subprocess.Popen(['qemu-system-x86_64', '-enable-kvm', '-cpu', 'host', '-m', '3072', '-smp', '2',
        '-drive', 'file=/state/disk.qcow2,if=virtio', '-drive', 'file=/state/seed.img,format=raw,if=virtio',
        '-netdev', 'user,id=n1,hostfwd=tcp:127.0.0.1:23265-:22', '-device', 'virtio-net-pci,netdev=n1',
        '-monitor', 'unix:/state/monitor.sock,server=on,wait=off', '-nographic'])
    def stop(_number, _frame):
        try:
            with socket.socket(socket.AF_UNIX) as client:
                client.connect(str(monitor)); client.sendall(b'system_powerdown\n')
            process.wait(timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            process.terminate()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        raise SystemExit(process.wait())
    finally:
        relay.terminate()
        relay.wait(timeout=5)

if __name__ == '__main__':
    main()
