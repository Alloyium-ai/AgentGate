#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Re-arm one guarded Docker target per authenticated SSH command.

This is a fixed, isolated diagnostic. It never grants normal product admission.
"""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from settings import load_settings

ROOT = Path(__file__).resolve().parent
SETTINGS = load_settings(ROOT / 'settings.json')
DOMAIN = Path(SETTINGS['domain'])
PINS = Path(SETTINGS['pins'])
HOST_PINS = Path(SETTINGS['host_pins'])
TARGET = SETTINGS['name']
# The guard writes its receipt after SIGTERM. Its own cleanup bound is shorter.
GUARD_EXIT_WAIT_S = 5
SOURCE = SETTINGS['source']
POLICY = None


def empty_domain():
    return not DOMAIN.exists() or 'populated 0' in (DOMAIN / 'cgroup.events').read_text().splitlines()


def archive_previous():
    history = ROOT / 'history'
    history.mkdir(mode=0o700, exist_ok=True)
    files = ('guard-ready', 'guard-receipt.json', 'guard.log', 'config.json', 'policy-active.json',
             'mounts-active.json')
    if any((ROOT / name).exists() for name in files):
        directory = history / str(time.time_ns())
        directory.mkdir(mode=0o700)
        for name in files:
            path = ROOT / name
            if path.exists():
                path.rename(directory / name)


def read_guard_pid():
    config = ROOT / 'config.json'
    if not config.exists():
        return None
    data = json.loads(config.read_text())
    pid = int(data['guard_pid'])
    raw = Path(f'/proc/{pid}/stat').read_text()
    ticks = int(raw.rsplit(')', 1)[1].split()[19])
    return pid if ticks == int(data['guard_start_ticks']) else None


def guard_alive():
    try:
        return read_guard_pid() is not None
    except (FileNotFoundError, KeyError, ValueError):
        return False


def load_gateway():
    spec = importlib.util.spec_from_file_location('poc_gateway', ROOT / 'gateway.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pins_remain():
    return PINS.exists() or HOST_PINS.exists()


def release_orphaned_pins():
    """Release only owned pins after the measured domain and target are empty."""
    if not pins_remain():
        return
    if not empty_domain() or guard_alive():
        raise RuntimeError('guard pins retained while domain or guard is active')
    target = subprocess.run(['/usr/bin/docker', 'inspect', TARGET], capture_output=True,
                            timeout=5, env={'PATH': '/usr/bin:/bin'})
    if target.returncode == 0 or b'no such object' not in target.stderr.lower():
        raise RuntimeError('target absence is not verified')
    gateway = load_gateway()
    # A killed guard leaves both directories; the host one must not wedge the next command.
    for path, links in ((PINS, gateway.NETWORK_LINKS), (HOST_PINS, gateway.HOST_LINKS)):
        if path.exists() or path.is_symlink():
            try:
                gateway.remove_pin_directory(path, links)
            except ValueError as error:
                raise RuntimeError(str(error)) from error


def cleanup(pid):
    errors = []
    if DOMAIN.exists():
        try:
            (DOMAIN / 'cgroup.kill').write_text('1')
        except OSError as error:
            errors.append(f'cgroup.kill: {error}')
    subprocess.run(['/usr/bin/docker', 'rm', '-f', TARGET], capture_output=True,
                   timeout=8, env={'PATH': '/usr/bin:/bin'})
    if pid and guard_alive():
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + GUARD_EXIT_WAIT_S
    while time.monotonic() < deadline:
        if empty_domain() and not pins_remain() and not guard_alive():
            break
        time.sleep(0.1)
    if pins_remain():
        try:
            release_orphaned_pins()
        except (OSError, RuntimeError) as error:
            errors.append(f'orphaned pins: {error}')
    if not empty_domain() or pins_remain():
        errors.append('owned domain or guard pins remain')
    record = {'scope': 'fixed-diagnostic-only; no normal admission',
              'source_revision': SOURCE, 'policy_digest': POLICY,
              'domain_empty': empty_domain(), 'pins_absent': not pins_remain(),
              'cleanup_errors': errors, 'finished_mono_ns': time.monotonic_ns()}
    append_event(record)
    if errors:
        raise RuntimeError('; '.join(errors))


def append_event(record):
    load_gateway().append_audit(str(ROOT / 'operator-events.jsonl'), record)


def run_gateway():
    module = load_gateway()
    original = sys.argv
    try:
        sys.argv = [str(ROOT / 'gateway.py'), str(ROOT / 'config.json')]
        return module.main()
    finally:
        sys.argv = original


def main():
    global POLICY
    if os.geteuid() != 0 or os.environ.get('SSH_TTY') or len(sys.argv) != 1:
        raise ValueError('invalid operator diagnostic transport')
    command = os.environ.get('SSH_ORIGINAL_COMMAND', '')
    if not command or '\x00' in command or len(command.encode()) > 16384:
        raise ValueError('invalid SSH command')
    lock = os.open(ROOT / 'single-job.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError('operator diagnostic busy')
    if (ROOT / 'appliance-stopping').exists():
        os.close(lock)
        raise RuntimeError('appliance stop requested; use the start command')
    pid = None
    result = 1
    try:
        if not empty_domain() or pins_remain():
            # A guard killed earlier leaves pins; release them once nothing is live.
            release_orphaned_pins()
        if not empty_domain() or pins_remain():
            raise RuntimeError('previous command domain or pins remain')
        archive_previous()
        subprocess.run([str(ROOT / 'prepare-command.sh')], check=True, timeout=25,
                       stdout=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin'})
        pid = read_guard_pid()
        POLICY = json.loads((ROOT / 'config.json').read_text())['policy_digest']
        result = run_gateway()
    except BaseException as error:
        append_event({'scope': 'fixed-diagnostic-only; no normal admission',
                      'source_revision': SOURCE, 'policy_digest': POLICY,
                      'command_sha256': hashlib.sha256(command.encode()).hexdigest(),
                      'state': 'setup_or_gateway_failed', 'error': str(error),
                      'finished_mono_ns': time.monotonic_ns()})
        raise
    finally:
        if pid is None:
            try:
                pid = read_guard_pid()
            except (FileNotFoundError, KeyError, ValueError):
                pid = None
        cleanup(pid)
        os.close(lock)
    return result


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(f'agentgate-operator-poc-error: {type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)
