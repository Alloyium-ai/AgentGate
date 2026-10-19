#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
# Isolated fixed diagnostic only. Never call this normal AgentGate admission.
import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import time

MAX_PENDING_OUTPUT = 1 << 20


def read_root_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o077:
            raise ValueError('untrusted diagnostic configuration')
        data = os.read(fd, 65537)
        if len(data) > 65536:
            raise ValueError('oversized diagnostic configuration')
        return data
    finally:
        os.close(fd)


def process_state(pid):
    with open(f'/proc/{pid}/stat', encoding='ascii') as source:
        raw = source.read()
    fields = raw.rsplit(')', 1)[1].split()
    return fields[0], int(fields[19])


def start_ticks(pid):
    return process_state(pid)[1]


def alive(pid, ticks):
    try:
        state, actual_ticks = process_state(pid)
        return state not in ('Z', 'X') and actual_ticks == ticks
    except (FileNotFoundError, ProcessLookupError, ValueError):
        return False


def pins_live(path):
    try:
        meta = os.lstat(path)
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o077:
            return False
        for index in range(6):
            item = os.lstat(os.path.join(path, f'link-{index}'))
            if not stat.S_ISREG(item.st_mode) or item.st_uid != 0:
                return False
        return True
    except OSError:
        return False


def inspect_target(config):
    result = subprocess.run(['/usr/bin/docker', 'inspect', config['container']],
                            check=True, capture_output=True, timeout=5,
                            env={'PATH': '/usr/bin:/bin'})
    target = json.loads(result.stdout)[0]
    host = target['HostConfig']
    if target['Id'] != config['container_id'] or target['Image'] != config['image_id'] or not target['State']['Running']:
        raise ValueError('target identity changed')
    if host['Privileged'] or not host['ReadonlyRootfs'] or 'ALL' not in host['CapDrop'] or \
       'no-new-privileges' not in ' '.join(host['SecurityOpt']).lower() or host['PidMode'] == 'host' or \
       host['IpcMode'] == 'host' or host['NetworkMode'] != config['network'] or \
       target['Config']['User'] != '65534:65534':
        raise ValueError('target rights changed')
    for mount in target['Mounts']:
        if 'docker.sock' in mount['Source'] or 'docker.sock' in mount['Destination']:
            raise ValueError('docker socket entered target')
    pid = target['State']['Pid']
    if not pid or '0::/' not in open(f'/proc/{pid}/cgroup', encoding='ascii').read():
        raise ValueError('target process identity changed')
    return target


def append_audit(path, record):
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o077:
            raise ValueError('audit custody changed')
        os.write(fd, (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def relay_process(process, session_alive, guard_alive, deadline_ns, output_fds=(1, 2)):
    """Relay command output without letting a stalled SSH reader extend the cutoff."""
    selector = selectors.DefaultSelector()
    streams = {'stdout': process.stdout, 'stderr': process.stderr}
    destinations = dict(zip(streams, output_fds))
    pending = {name: bytearray() for name in streams}
    hashes = {name: hashlib.sha256() for name in streams}
    lengths = {name: 0 for name in streams}
    for name, stream in streams.items():
        selector.register(stream, selectors.EVENT_READ, ('read', name))
        os.set_blocking(destinations[name], False)
    state = 'completed'
    try:
        while selector.get_map() or process.poll() is None:
            if not session_alive():
                state = 'disconnected'
                break
            if not guard_alive():
                state = 'guard_lost'
                break
            if time.monotonic_ns() >= deadline_ns:
                state = 'expired'
                break
            for key, _ in selector.select(timeout=0.1):
                direction, name = key.data
                if direction == 'read':
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    hashes[name].update(chunk)
                    lengths[name] += len(chunk)
                    if not pending[name]:
                        selector.register(destinations[name], selectors.EVENT_WRITE, ('write', name))
                    pending[name].extend(chunk)
                    if len(pending[name]) > MAX_PENDING_OUTPUT:
                        state = 'output_backpressure'
                        break
                else:
                    try:
                        written = os.write(destinations[name], pending[name])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        state = 'disconnected'
                        break
                    del pending[name][:written]
                    if not pending[name]:
                        selector.unregister(destinations[name])
            if state != 'completed':
                break
    finally:
        selector.close()
    return state, hashes, lengths


def wait_empty_domain(path, timeout_ns=5_000_000_000):
    started = time.monotonic_ns()
    while True:
        with open(os.path.join(path, 'cgroup.events'), encoding='ascii') as source:
            events = dict(line.split() for line in source)
        with open(os.path.join(path, 'cgroup.procs'), encoding='ascii') as source:
            members = source.read()
        if events.get('populated') == '0' and events.get('frozen') == '0' and not members.strip():
            return True, time.monotonic_ns() - started
        if time.monotonic_ns() - started >= timeout_ns:
            return False, time.monotonic_ns() - started
        time.sleep(0.05)


def main():
    if len(sys.argv) != 2 or os.geteuid() != 0 or os.environ.get('SSH_TTY'):
        raise ValueError('invalid SSH diagnostic transport')
    command = os.environ.get('SSH_ORIGINAL_COMMAND', '')
    if not command or '\x00' in command or len(command.encode()) > 16384:
        raise ValueError('invalid SSH command')
    config = json.loads(read_root_file(sys.argv[1]))
    wanted = {'container', 'container_id', 'image_id', 'network', 'domain',
              'runner_path', 'runner_sha256', 'guard_pid', 'guard_start_ticks',
              'guard_ready', 'guard_pins', 'deadline_ns', 'audit_path',
              'source_revision', 'policy_digest'}
    if set(config) != wanted or not config['container'].startswith('ag-mvp-') or \
       not config['domain'].startswith('/sys/fs/cgroup/ag-mvp-') or \
       not config['runner_path'].startswith('/var/lib/agentgate-poc-') or \
       not config['guard_pins'].startswith('/sys/fs/bpf/ag-mvp-net-'):
        raise ValueError('invalid SSH diagnostic binding')
    if hashlib.sha256(read_root_file(config['runner_path'])).hexdigest() != config['runner_sha256']:
        raise ValueError('diagnostic runner changed')
    guard_pid = int(config['guard_pid'])
    guard_ticks = int(config['guard_start_ticks'])
    if not alive(guard_pid, guard_ticks) or not pins_live(config['guard_pins']) or \
       read_root_file(config['guard_ready']) != b'guard-attached\n' or \
       time.monotonic_ns() >= int(config['deadline_ns']):
        raise ValueError('kernel guard unavailable')
    target = inspect_target(config)
    parent = os.getppid()
    parent_ticks = start_ticks(parent)
    started = time.monotonic_ns()
    hashes = {'stdout': hashlib.sha256(), 'stderr': hashlib.sha256()}
    lengths = {'stdout': 0, 'stderr': 0}
    state = 'launch_error'
    cleaned = False
    cleanup_wait_ns = 0
    process = None
    try:
        process = subprocess.Popen([config['runner_path'], str(target['State']['Pid']),
                                    config['domain'], command], stdin=sys.stdin.buffer,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, env={'PATH': '/usr/bin:/bin'}, close_fds=True)
        state = 'relay_error'
        state, hashes, lengths = relay_process(
            process, lambda: alive(parent, parent_ticks),
            lambda: alive(guard_pid, guard_ticks) and pins_live(config['guard_pins']),
            int(config['deadline_ns']))
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=1)
        exit_code = process.returncode if state == 'completed' else 1
    finally:
        try:
            with open(os.path.join(config['domain'], 'cgroup.kill'), 'w', encoding='ascii') as sink:
                sink.write('1')
            subprocess.run(['/usr/bin/docker', 'rm', '-f', config['container']],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=5, env={'PATH': '/usr/bin:/bin'})
            cleaned, cleanup_wait_ns = wait_empty_domain(config['domain'])
            if not cleaned:
                state = 'cleanup_incomplete'
        finally:
            if not cleaned and state == 'completed':
                state = 'cleanup_incomplete'
            finished = time.monotonic_ns()
            append_audit(config['audit_path'], {
                'scope': 'fixed-diagnostic-only; no normal admission',
                'source_revision': config['source_revision'], 'policy_digest': config['policy_digest'],
                'container_id': target['Id'], 'image_id': target['Image'],
                'command_sha256': hashlib.sha256(command.encode()).hexdigest(),
                'stdout_sha256': hashes['stdout'].hexdigest(), 'stderr_sha256': hashes['stderr'].hexdigest(),
                'stdout_bytes': lengths['stdout'], 'stderr_bytes': lengths['stderr'],
                'started_mono_ns': started, 'finished_mono_ns': finished,
                'state': state, 'exit_code': exit_code if cleaned and 'exit_code' in locals() else 1,
                'domain_killed': cleaned, 'cleanup_wait_ns': cleanup_wait_ns})
    return exit_code if cleaned and 0 <= exit_code < 256 else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(f'agentgate-poc-ssh-error: {type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)
