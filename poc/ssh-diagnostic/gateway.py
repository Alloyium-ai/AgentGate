#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
# Isolated fixed diagnostic only. Never call this normal AgentGate admission.
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

MAX_PENDING_OUTPUT = 1 << 20
# The only link counts. Network guard links, and the host-control links (20
# filesystem LSM hooks plus 3 process LSM hooks). start-guard.sh and the
# operator gateway use these values; a Go test binds them to the attached lists.
NETWORK_LINKS = 6
HOST_LINKS = 23
# Fixed target mounts and the directory that may hold approved host folders.
WORKSPACE_PATH = '/var/lib/agentgate/workspace'
STREAMS_PATH = '/run/agentgate/streams'
TASKBOARD_PATH = '/run/agentgate/taskboard'
HOST_MOUNT_ROOT = '/var/lib/agentgate/mounts'
# Command windows. A policy without a launch mode is the SSH command policy:
# its window stays capped at 25 seconds. A launch policy names its mode, and
# its duration_seconds is the launch lifetime, enforced here and in the kernel.
SSH_WINDOW_S = 25
LIFETIME_BOUNDS = {None: (1, 60), 'oneshot': (1, 3600), 'session': (60, 86400)}


def command_deadline(mode, duration, start_ns, now_ns):
    """Return the host deadline for one guarded command or launch.

    start_ns is taken before the guard starts, so the host deadline is never
    later than the kernel policy expiry the guard computes from its own start.
    """
    if mode not in LIFETIME_BOUNDS or type(duration) is not int:
        raise ValueError('invalid command mode or lifetime')
    low, high = LIFETIME_BOUNDS[mode]
    if not low <= duration <= high:
        raise ValueError('lifetime outside %d..%d seconds' % (low, high))
    if mode is None:
        deadline = min(now_ns + SSH_WINDOW_S * 1_000_000_000, start_ns + duration * 1_000_000_000)
        # Unchanged SSH rule: at least one second must remain.
        if deadline <= now_ns + 1_000_000_000:
            raise ValueError('command window elapsed during setup')
        return deadline
    deadline = start_ns + duration * 1_000_000_000
    if deadline <= now_ns + 200_000_000:
        raise ValueError('launch lifetime elapsed during setup')
    return deadline


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


def pins_live(path, count=NETWORK_LINKS):
    try:
        meta = os.lstat(path)
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o077:
            return False
        for index in range(count):
            item = os.lstat(os.path.join(path, f'link-{index}'))
            if not stat.S_ISREG(item.st_mode) or item.st_uid != 0:
                return False
        return True
    except OSError:
        return False


def remove_pin_directory(path, link_count):
    """Remove one orphaned pin directory holding only this guard's own entries.

    The caller must first prove the domain is empty and the guard has exited.
    """
    meta = os.lstat(path)
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_mode & 0o077:
        raise ValueError('guard pin directory custody differs')
    links = {f'link-{index}' for index in range(link_count)}
    entries = os.listdir(path)
    for name in entries:
        item = os.lstat(os.path.join(path, name))
        if stat.S_ISLNK(item.st_mode) or not (name in links or name.startswith('map-')):
            raise ValueError('guard pin directory contains an unexpected entry: ' + name)
    for name in entries:
        os.unlink(os.path.join(path, name))
    os.rmdir(path)


def expected_mounts(config):
    """Return every mount the target may hold: three fixed ones and approved host folders."""
    expected = {WORKSPACE_PATH: ('volume', True, None), STREAMS_PATH: ('bind', True, None),
                TASKBOARD_PATH: ('volume', False, None)}
    for item in config['host_mounts']:
        expected[item['path']] = ('bind', not item['read_only'], item['source'])
    return expected


def check_mounts(mounts, config):
    expected = expected_mounts(config)
    seen = set()
    for mount in mounts:
        if 'docker.sock' in mount['Source'] or 'docker.sock' in mount['Destination']:
            raise ValueError('docker socket entered target')
        want = expected.get(mount['Destination'])
        if want is None or mount['Destination'] in seen or mount['Type'] != want[0] or \
           bool(mount['RW']) != want[1] or (want[2] is not None and mount['Source'] != want[2]):
            raise ValueError('target mount differs from the approved set: ' + str(mount['Destination']))
        seen.add(mount['Destination'])
    if seen != set(expected):
        raise ValueError('an approved target mount is absent')


def valid_host_mounts(value):
    if not isinstance(value, list) or len(value) > 8:
        return False
    paths = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {'path', 'source', 'read_only'} or \
           not isinstance(item['path'], str) or not isinstance(item['source'], str) or \
           not isinstance(item['read_only'], bool) or not item['source'].startswith('/') or \
           not item['path'].startswith(HOST_MOUNT_ROOT + '/') or item['path'] in paths or \
           not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,31}', item['path'][len(HOST_MOUNT_ROOT) + 1:]):
            return False
        paths.add(item['path'])
    return True


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
    check_mounts(target['Mounts'], config)
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


def relay_process(process, session_alive, guard_alive, deadline_ns, output_fds=(1, 2), sinks=None,
                  should_stop=None):
    """Relay command output without letting a stalled SSH reader extend the cutoff.

    With sinks (one callable per stream) output goes to bounded host logs
    instead of descriptors; should_stop ends the relay with state 'stopped'.
    """
    selector = selectors.DefaultSelector()
    streams = {'stdout': process.stdout, 'stderr': process.stderr}
    destinations = dict(zip(streams, output_fds))
    pending = {name: bytearray() for name in streams}
    hashes = {name: hashlib.sha256() for name in streams}
    lengths = {name: 0 for name in streams}
    for name, stream in streams.items():
        selector.register(stream, selectors.EVENT_READ, ('read', name))
        if sinks is None:
            os.set_blocking(destinations[name], False)
    state = 'completed'
    try:
        while selector.get_map() or process.poll() is None:
            if should_stop is not None and should_stop():
                state = 'stopped'
                break
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
                    if sinks is not None:
                        sinks[name](chunk)
                        continue
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


def domain_members(path):
    with open(os.path.join(path, 'cgroup.procs'), encoding='ascii') as source:
        return [int(line) for line in source.read().split() if line.isdigit()][:4096]


def graceful_stop(path, grace_ns, members=domain_members, kill=os.kill):
    """Ask every domain member to exit, then wait up to grace_ns for an empty domain.

    The cgroup kill always follows; this only gives the agent a chance to exit.
    """
    if grace_ns <= 0:
        return False
    try:
        for pid in members(path):
            try:
                kill(pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        return wait_empty_domain(path, grace_ns)[0]
    except (OSError, ValueError):
        return False


def remove_target(name):
    subprocess.run(['/usr/bin/docker', 'rm', '-f', name],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=5, env={'PATH': '/usr/bin:/bin'})


def stop_process(process):
    """Stop the runner's whole process group; the domain kill follows regardless."""
    if process.poll() is not None:
        return
    for number, wait in ((signal.SIGTERM, 1), (signal.SIGKILL, 2)):
        try:
            os.killpg(process.pid, number)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            process.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def cleanup_domain(config):
    """Kill the domain and remove the target as independent steps; report each failure."""
    errors = []
    try:
        with open(os.path.join(config['domain'], 'cgroup.kill'), 'w', encoding='ascii') as sink:
            sink.write('1')
    except OSError as error:
        errors.append(f'cgroup.kill: {error}')
    try:
        remove_target(config['container'])
    except (OSError, subprocess.SubprocessError) as error:
        errors.append(f'target removal: {type(error).__name__}')
    try:
        cleaned, waited = wait_empty_domain(config['domain'])
    except (OSError, ValueError) as error:
        errors.append(f'domain readback: {error}')
        cleaned, waited = False, 0
    # Any failed step leaves the command's cleanup unproven, so its exit is 1.
    return cleaned and not errors, waited, errors


def execute(config, command, target, guard_ok, session_alive, output_fds=(1, 2), stdin=None):
    """Run one command in the bound target. Cleanup and the audit always run."""
    result = execute_detailed(config, command, target, guard_ok, session_alive, output_fds, stdin)
    return result['returncode']


def execute_detailed(config, command, target, guard_ok, session_alive, output_fds=(1, 2), stdin=None,
                     sinks=None, should_stop=None, grace_ns=0, audit_extra=None):
    """execute() with the full result: state, exit code, cleanup and output digests.

    A launch passes log sinks, a stop request and a graceful-stop period; the
    SSH path passes none of them and behaves exactly as before.
    """
    host_controls = config['host_controls']
    started = time.monotonic_ns()
    hashes = {'stdout': hashlib.sha256(), 'stderr': hashlib.sha256()}
    lengths = {'stdout': 0, 'stderr': 0}
    state = 'launch_error'
    exit_code = 1
    cleaned = False
    cleanup_wait_ns = 0
    cleanup_errors = []
    process = None
    try:
        # With host controls the runner joins the domain last, so the policy never
        # applies to the trusted helpers that enter the target namespaces.
        process = subprocess.Popen([config['runner_path'], str(target['State']['Pid']),
                                    config['domain'], command] + (['late-join'] if host_controls else []),
                                   stdin=stdin if stdin is not None else sys.stdin.buffer,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, env={'PATH': '/usr/bin:/bin'}, close_fds=True)
        state = 'relay_error'
        state, hashes, lengths = relay_process(process, session_alive, guard_ok,
                                               int(config['deadline_ns']), output_fds, sinks, should_stop)
        grace = grace_ns(state) if callable(grace_ns) else grace_ns
        if state in ('stopped', 'expired', 'disconnected') and grace > 0:
            graceful_stop(config['domain'], grace)
        stop_process(process)
        exit_code = process.returncode if state == 'completed' else 1
    finally:
        try:
            if process is not None:
                stop_process(process)
                for stream in (process.stdout, process.stderr):
                    stream.close()
        finally:
            cleaned, cleanup_wait_ns, cleanup_errors = cleanup_domain(config)
            if not cleaned:
                state = 'cleanup_incomplete'
            record = {
                'scope': 'fixed-diagnostic-only; no normal admission',
                'source_revision': config['source_revision'], 'policy_digest': config['policy_digest'],
                'host_controls': host_controls,
                'host_mounts': [item['path'] for item in config['host_mounts']],
                'container_id': target['Id'], 'image_id': target['Image'],
                'command_sha256': hashlib.sha256(command.encode()).hexdigest(),
                'stdout_sha256': hashes['stdout'].hexdigest(), 'stderr_sha256': hashes['stderr'].hexdigest(),
                'stdout_bytes': lengths['stdout'], 'stderr_bytes': lengths['stderr'],
                'started_mono_ns': started, 'finished_mono_ns': time.monotonic_ns(),
                'state': state, 'exit_code': exit_code if cleaned else 1,
                'domain_killed': cleaned, 'cleanup_wait_ns': cleanup_wait_ns,
                'cleanup_errors': cleanup_errors}
            record.update(audit_extra or {})
            append_audit(config['audit_path'], record)
    return {'returncode': exit_code if cleaned and 0 <= exit_code < 256 else 1, 'state': state,
            'exit_code': exit_code if cleaned else 1, 'cleaned': cleaned, 'cleanup_errors': cleanup_errors,
            'stdout_sha256': hashes['stdout'].hexdigest(), 'stderr_sha256': hashes['stderr'].hexdigest(),
            'stdout_bytes': lengths['stdout'], 'stderr_bytes': lengths['stderr'],
            'started_mono_ns': started, 'finished_mono_ns': time.monotonic_ns()}


BINDING_KEYS = {'container', 'container_id', 'image_id', 'network', 'domain',
                'runner_path', 'runner_sha256', 'guard_pid', 'guard_start_ticks',
                'guard_ready', 'guard_pins', 'deadline_ns', 'audit_path',
                'source_revision', 'policy_digest', 'host_controls', 'host_pins', 'host_mounts'}


def load_binding(path):
    """Validate the guard binding; return (config, guard_ok, target).

    The SSH gateway and the launch runtime share this check exactly.
    """
    config = json.loads(read_root_file(path))
    if set(config) != BINDING_KEYS or not config['container'].startswith('ag-mvp-') or \
       not config['domain'].startswith('/sys/fs/cgroup/ag-mvp-') or \
       not config['runner_path'].startswith('/var/lib/agentgate-poc-') or \
       not config['guard_pins'].startswith('/sys/fs/bpf/ag-mvp-net-') or \
       not isinstance(config['host_controls'], bool) or \
       config['host_controls'] != bool(config['host_pins']) or \
       (config['host_controls'] and not config['host_pins'].startswith('/sys/fs/bpf/ag-mvp-host-')) or \
       not valid_host_mounts(config['host_mounts']) or \
       (config['host_mounts'] and not config['host_controls']):
        raise ValueError('invalid SSH diagnostic binding')
    host_controls = config['host_controls']

    def guard_ok():
        return alive(guard_pid, guard_ticks) and pins_live(config['guard_pins'], NETWORK_LINKS) and \
            (not host_controls or pins_live(config['host_pins'], HOST_LINKS))
    if hashlib.sha256(read_root_file(config['runner_path'])).hexdigest() != config['runner_sha256']:
        raise ValueError('diagnostic runner changed')
    guard_pid = int(config['guard_pid'])
    guard_ticks = int(config['guard_start_ticks'])
    if not guard_ok() or \
       read_root_file(config['guard_ready']) != b'guard-attached\n' or \
       time.monotonic_ns() >= int(config['deadline_ns']):
        raise ValueError('kernel guard unavailable')
    return config, guard_ok, inspect_target(config)


def main():
    if len(sys.argv) != 2 or os.geteuid() != 0 or os.environ.get('SSH_TTY'):
        raise ValueError('invalid SSH diagnostic transport')
    command = os.environ.get('SSH_ORIGINAL_COMMAND', '')
    if not command or '\x00' in command or len(command.encode()) > 16384:
        raise ValueError('invalid SSH command')
    config, guard_ok, target = load_binding(sys.argv[1])
    parent = os.getppid()
    parent_ticks = start_ticks(parent)
    return execute(config, command, target, guard_ok, lambda: alive(parent, parent_ticks))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(f'agentgate-poc-ssh-error: {type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)
