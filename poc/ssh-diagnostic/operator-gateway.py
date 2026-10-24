#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Re-arm one guarded Docker target per authenticated SSH command.

This is a fixed, isolated diagnostic. It never grants normal product admission.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from domain_control import Instance, load_gateway
from settings import load_settings

ROOT = Path(__file__).resolve().parent
SETTINGS = load_settings(ROOT / 'settings.json')
# The guard writes its receipt after SIGTERM. Its own cleanup bound is shorter.
GUARD_EXIT_WAIT_S = 5
SOURCE = SETTINGS['source']
POLICY = None
# domain_control holds the shared custody steps, including the link counts
# used to release orphaned pins.
INSTANCE = Instance(ROOT, SETTINGS)


def empty_domain():
    return INSTANCE.empty_domain()


def archive_previous():
    INSTANCE.archive_previous()


def read_guard_pid():
    return INSTANCE.read_guard_pid()


def pins_remain():
    return INSTANCE.pins_remain()


def release_orphaned_pins():
    INSTANCE.release_orphaned_pins()


def cleanup(pid):
    errors = INSTANCE.teardown(pid, GUARD_EXIT_WAIT_S)
    record = {'scope': 'fixed-diagnostic-only; no normal admission',
              'source_revision': SOURCE, 'policy_digest': POLICY,
              'domain_empty': empty_domain(), 'pins_absent': not pins_remain(),
              'cleanup_errors': errors, 'finished_mono_ns': time.monotonic_ns()}
    append_event(record)
    if errors:
        raise RuntimeError('; '.join(errors))


def append_event(record):
    INSTANCE.append_event(record)


def run_gateway():
    module = load_gateway(ROOT)
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
