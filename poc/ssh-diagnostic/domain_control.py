# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Shared custody of one instance's command domain, target, guard and pins.

The SSH operator gateway and the launch runtime use exactly these steps to
prepare a fresh guarded target and to tear it down. Teardown never claims
success unless the domain is empty and both pin directories are gone.
"""
import importlib.util
import json
from pathlib import Path
import signal
import os
import subprocess
import time

# Files of one guarded command in the instance root. They are archived before
# the next command and moved into a launch's own directory after a launch.
COMMAND_FILES = ('guard-ready', 'guard-receipt.json', 'guard.log', 'config.json', 'policy-active.json',
                 'mounts-active.json', 'launch-mounts.json', 'target.json')
# The SSH archive keeps its historical file list.
SSH_ARCHIVE_FILES = ('guard-ready', 'guard-receipt.json', 'guard.log', 'config.json', 'policy-active.json',
                     'mounts-active.json')


def load_gateway(root):
    spec = importlib.util.spec_from_file_location('poc_gateway', Path(root) / 'gateway.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Instance:
    """One installed POC instance: /var/lib/agentgate-poc-NAME and its owned resources."""

    def __init__(self, root, settings, run=subprocess.run, gateway=None):
        self.root = Path(root)
        self.settings = settings
        self.domain = Path(settings['domain'])
        self.pins = Path(settings['pins'])
        self.host_pins = Path(settings['host_pins'])
        self.target = settings['name']
        self.run = run
        self.gateway = gateway or load_gateway(self.root)

    def empty_domain(self):
        return not self.domain.exists() or 'populated 0' in (self.domain / 'cgroup.events').read_text().splitlines()

    def archive_previous(self, files=SSH_ARCHIVE_FILES):
        history = self.root / 'history'
        history.mkdir(mode=0o700, exist_ok=True)
        if any((self.root / name).exists() for name in files):
            directory = history / str(time.time_ns())
            directory.mkdir(mode=0o700)
            for name in files:
                path = self.root / name
                if path.exists():
                    path.rename(directory / name)

    def read_guard_pid(self):
        config = self.root / 'config.json'
        if not config.exists():
            return None
        data = json.loads(config.read_text())
        pid = int(data['guard_pid'])
        raw = Path(f'/proc/{pid}/stat').read_text()
        ticks = int(raw.rsplit(')', 1)[1].split()[19])
        return pid if ticks == int(data['guard_start_ticks']) else None

    def guard_alive(self):
        try:
            return self.read_guard_pid() is not None
        except (FileNotFoundError, KeyError, ValueError):
            return False

    def pins_remain(self):
        return self.pins.exists() or self.host_pins.exists()

    def target_absent(self):
        target = self.run(['/usr/bin/docker', 'inspect', self.target], capture_output=True,
                          timeout=5, env={'PATH': '/usr/bin:/bin'})
        return target.returncode != 0 and b'no such object' in target.stderr.lower()

    def release_orphaned_pins(self):
        """Release only owned pins after the measured domain and target are empty."""
        if not self.pins_remain():
            return
        if not self.empty_domain() or self.guard_alive():
            raise RuntimeError('guard pins retained while domain or guard is active')
        if not self.target_absent():
            raise RuntimeError('target absence is not verified')
        gateway = self.gateway
        # A killed guard leaves both directories; the host one must not wedge the next command.
        for path, links in ((self.pins, gateway.NETWORK_LINKS), (self.host_pins, gateway.HOST_LINKS)):
            if path.exists() or path.is_symlink():
                try:
                    gateway.remove_pin_directory(path, links)
                except ValueError as error:
                    raise RuntimeError(str(error)) from error

    def teardown(self, pid, guard_wait_s=5, sleep=time.sleep, clock=time.monotonic):
        """Kill the domain, remove the target, stop the guard, release orphaned pins.

        Every step runs even if another fails. Returns the list of failures;
        an empty list means the domain is empty and no pin remains.
        """
        errors = []
        if self.domain.exists():
            try:
                (self.domain / 'cgroup.kill').write_text('1')
            except OSError as error:
                errors.append(f'cgroup.kill: {error}')
        try:
            self.run(['/usr/bin/docker', 'rm', '-f', self.target], capture_output=True,
                     timeout=8, env={'PATH': '/usr/bin:/bin'})
        except (OSError, subprocess.SubprocessError) as error:
            errors.append(f'target removal: {type(error).__name__}')
        if pid and self.guard_alive():
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        deadline = clock() + guard_wait_s
        while clock() < deadline:
            if self.empty_domain() and not self.pins_remain() and not self.guard_alive():
                break
            sleep(0.1)
        if self.pins_remain():
            try:
                self.release_orphaned_pins()
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                errors.append(f'orphaned pins: {error}')
        if not self.empty_domain() or self.pins_remain():
            errors.append('owned domain or guard pins remain')
        return errors

    def append_event(self, record):
        self.gateway.append_audit(str(self.root / 'operator-events.jsonl'), record)
