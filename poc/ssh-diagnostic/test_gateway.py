# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Custody checks for the one-shot SSH diagnostic gateway."""

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock


SOURCE = pathlib.Path(__file__).with_name('gateway.py')
SPEC = importlib.util.spec_from_file_location('agentgate_ssh_diagnostic', SOURCE)
GATEWAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATEWAY)


class GatewayCustodyTest(unittest.TestCase):
    def test_cleanup_claim_requires_empty_and_unfrozen_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            events = pathlib.Path(directory) / 'cgroup.events'
            members = pathlib.Path(directory) / 'cgroup.procs'
            events.write_text('populated 0\nfrozen 0\n')
            members.write_text('')
            self.assertTrue(GATEWAY.wait_empty_domain(directory, 1_000_000)[0])
            members.write_text('42\n')
            self.assertFalse(GATEWAY.wait_empty_domain(directory, 1_000_000)[0])
            members.write_text('')
            events.write_text('populated 0\nfrozen 1\n')
            self.assertFalse(GATEWAY.wait_empty_domain(directory, 1_000_000)[0])

    def test_normal_output_and_exit_remain_available(self):
        out_read, out_write = os.pipe()
        err_read, err_write = os.pipe()
        process = None
        try:
            os.set_blocking(out_read, False)
            os.set_blocking(err_read, False)
            process = subprocess.Popen(
                [sys.executable, '-c',
                 'import sys; print("normal"); print("warning", file=sys.stderr)'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            state, _, lengths = GATEWAY.relay_process(
                process, lambda: True, lambda: True,
                time.monotonic_ns() + 2_000_000_000, (out_write, err_write))
            self.assertEqual(state, 'completed')
            self.assertEqual(process.wait(timeout=2), 0)
            self.assertEqual(os.read(out_read, 64), b'normal\n')
            self.assertEqual(os.read(err_read, 64), b'warning\n')
            self.assertEqual(lengths, {'stdout': 7, 'stderr': 8})
        finally:
            if process is not None and process.poll() is None:
                process.kill()
            if process is not None:
                process.wait(timeout=2)
                process.stdout.close()
                process.stderr.close()
            for fd in (out_read, out_write, err_read, err_write):
                os.close(fd)

    def test_stalled_ssh_output_cannot_extend_deadline(self):
        read_fd, write_fd = os.pipe()
        error_read, error_write = os.pipe()
        process = None
        try:
            os.set_blocking(write_fd, False)
            while True:
                try:
                    os.write(write_fd, b'x' * 65536)
                except BlockingIOError:
                    break
            process = subprocess.Popen(
                [sys.executable, '-c', 'import sys,time; print("ready", flush=True); time.sleep(5)'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            started = time.monotonic()
            state, hashes, lengths = GATEWAY.relay_process(
                process, lambda: True, lambda: True,
                time.monotonic_ns() + 250_000_000, (write_fd, error_write))
            self.assertEqual(state, 'expired')
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertEqual(lengths['stdout'], len(b'ready\n'))
            self.assertEqual(hashes['stdout'].hexdigest(),
                             GATEWAY.hashlib.sha256(b'ready\n').hexdigest())
        finally:
            if process is not None and process.poll() is None:
                process.kill()
            if process is not None:
                process.wait(timeout=2)
                process.stdout.close()
                process.stderr.close()
            for fd in (read_fd, write_fd, error_read, error_write):
                os.close(fd)

    def test_output_backpressure_stops_unbounded_producer(self):
        read_fd, write_fd = os.pipe()
        error_read, error_write = os.pipe()
        process = None
        try:
            process = subprocess.Popen(
                [sys.executable, '-c', 'import os; os.write(1, b"x" * 2097152)'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            state, _, lengths = GATEWAY.relay_process(
                process, lambda: True, lambda: True,
                time.monotonic_ns() + 3_000_000_000, (write_fd, error_write))
            self.assertEqual(state, 'output_backpressure')
            self.assertGreater(lengths['stdout'], GATEWAY.MAX_PENDING_OUTPUT)
        finally:
            if process is not None and process.poll() is None:
                process.kill()
            if process is not None:
                process.wait(timeout=2)
                process.stdout.close()
                process.stderr.close()
            for fd in (read_fd, write_fd, error_read, error_write):
                os.close(fd)

    def test_process_identity_rejects_wrong_start(self):
        pid = os.getpid()
        ticks = GATEWAY.start_ticks(pid)
        self.assertTrue(GATEWAY.alive(pid, ticks))
        self.assertFalse(GATEWAY.alive(pid, ticks + 1))

    def test_pinned_guard_requires_all_root_owned_links(self):
        if os.geteuid() != 0:
            self.skipTest('root-owned diagnostic pin custody needs root')
        with tempfile.TemporaryDirectory() as directory:
            pins = pathlib.Path(directory) / 'pins'
            pins.mkdir(mode=0o700)
            for index in range(6):
                (pins / f'link-{index}').write_bytes(b'pinned')
            self.assertTrue(GATEWAY.pins_live(pins))
            (pins / 'link-5').unlink()
            self.assertFalse(GATEWAY.pins_live(pins))
            (pins / 'link-5').symlink_to(pins / 'link-4')
            self.assertFalse(GATEWAY.pins_live(pins))

    def test_host_control_pins_require_every_host_link(self):
        if os.geteuid() != 0:
            self.skipTest('root-owned diagnostic pin custody needs root')
        with tempfile.TemporaryDirectory() as directory:
            pins = pathlib.Path(directory) / 'pins'
            pins.mkdir(mode=0o700)
            for index in range(GATEWAY.HOST_LINKS):
                (pins / f'link-{index}').write_bytes(b'pinned')
            self.assertTrue(GATEWAY.pins_live(pins, GATEWAY.HOST_LINKS))
            # A network-sized set never satisfies the host-control requirement.
            (pins / f'link-{GATEWAY.HOST_LINKS - 1}').unlink()
            self.assertTrue(GATEWAY.pins_live(pins))
            self.assertFalse(GATEWAY.pins_live(pins, GATEWAY.HOST_LINKS))

    def test_host_link_count_matches_the_compiled_program_lists(self):
        source = (pathlib.Path(__file__).parents[2] / 'internal/fsrules/runtime.go').read_text()
        listing = source.split('LSMPrograms:')[1].split('}')[0]
        filesystem = len(__import__('re').findall(r'"fs_[a-z]+"', listing))
        process = (pathlib.Path(__file__).parents[2] / 'internal/processrules/runtime.go').read_text()
        hooks = len(__import__('re').findall(r'"process_[a-z]+"', process.split('func Programs')[1].split('}')[0]))
        self.assertEqual(filesystem + hooks, GATEWAY.HOST_LINKS)
        # start-guard.sh holds no count of its own: it checks with gateway.py's values.
        guard = (pathlib.Path(__file__).with_name('start-guard.sh')).read_text()
        self.assertNotRegex(guard, r'seq 0 \d|for index in 0 1')
        self.assertIn('pins_live(sys.argv[12],NETWORK_LINKS)', guard)
        self.assertIn('pins_live(host_pins,HOST_LINKS)', guard)
        operator = (pathlib.Path(__file__).with_name('operator-gateway.py')).read_text()
        self.assertNotIn('range(6)', operator)
        # The orphaned-pin release moved to the shared custody module.
        control = (pathlib.Path(__file__).with_name('domain_control.py')).read_text()
        self.assertNotIn('range(6)', control)
        self.assertIn('gateway.HOST_LINKS', control)
        self.assertIn('Instance(ROOT, SETTINGS)', operator)

    def test_late_join_runs_the_command_only_after_joining(self):
        script = pathlib.Path(__file__).with_name('run-in-target.sh').read_text()
        inner = script.split("/bin/sh -c -- \\\n    '")[1].split("' \\\n    agentgate-join")[0]
        self.assertIn('echo "$$" >&3', inner)
        unified = [line for line in pathlib.Path('/proc/self/cgroup').read_text().splitlines()
                   if line.startswith('0::/')]
        if len(unified) != 1:
            self.skipTest('cgroup v2 membership format required')
        current = unified[0]
        member = current[len('0::/'):]
        def join(procs, command, domain):
            # The trusted runner opens the descriptor, so an outer shell does the same.
            return subprocess.run(
                ['/bin/sh', '-c', 'exec 3>"$1"; shift; exec /bin/sh -c "$@"', 'outer', str(procs),
                 inner, 'agentgate-join', command, domain],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=10)

        with tempfile.TemporaryDirectory() as directory:
            procs = pathlib.Path(directory) / 'cgroup.procs'
            done = join(procs, 'ls /proc/$$/fd | tr "\\n" " "', member)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertRegex(procs.read_text(), r'^\d+\n$')
            # The command sees stdio only: the join descriptor is already closed.
            self.assertNotIn('3', done.stdout.decode().split())
            # A wrong membership exits 125 and never reaches the command.
            marker = pathlib.Path(directory) / 'ran'
            refused = join(procs, f'touch {marker}', 'not-this-domain')
            self.assertEqual(refused.returncode, 125)
            self.assertFalse(marker.exists())
            # A failed join write also stops the command.
            closed = subprocess.run(['/bin/sh', '-c', inner, 'agentgate-join', f'touch {marker}', member],
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
            self.assertNotEqual(closed.returncode, 0)
            self.assertFalse(marker.exists())

    def test_root_file_rejects_accessible_mode_and_symlink(self):
        if os.geteuid() != 0:
            self.skipTest('root-owned diagnostic file custody needs root')
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'config.json'
            path.write_bytes(b'{}')
            path.chmod(0o600)
            self.assertEqual(GATEWAY.read_root_file(path), b'{}')
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                GATEWAY.read_root_file(path)
            path.chmod(0o600)
            link = pathlib.Path(directory) / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                GATEWAY.read_root_file(link)

    def test_audit_is_one_line_and_rejects_mode_change(self):
        if os.geteuid() != 0:
            self.skipTest('root-owned diagnostic audit custody needs root')
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'audit.jsonl'
            record = {'state': 'completed', 'exit_code': 0}
            GATEWAY.append_audit(path, record)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.read_bytes(), (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode())
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                GATEWAY.append_audit(path, record)


class GatewayExecutionTest(unittest.TestCase):
    """execute() always kills the domain, removes the target, and audits once."""

    def fixture(self, body, domain=True):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = pathlib.Path(directory.name)
        path = root / 'domain'
        if domain:
            path.mkdir()
            (path / 'cgroup.events').write_text('populated 0\nfrozen 0\n')
            (path / 'cgroup.procs').write_text('')
        runner = root / 'runner.sh'
        runner.write_text('#!/bin/sh\n' + body)
        runner.chmod(0o700)
        config = {'runner_path': str(runner), 'domain': str(path), 'container': 'ag-mvp-test-target',
                  'deadline_ns': time.monotonic_ns() + 5_000_000_000, 'host_controls': False,
                  'host_mounts': [], 'audit_path': str(root / 'audit.jsonl'),
                  'source_revision': 'a' * 40, 'policy_digest': 'b' * 64}
        target = {'State': {'Pid': 4242}, 'Id': 'c' * 64, 'Image': 'sha256:' + 'd' * 64}
        audits, removed = [], []
        patcher = unittest.mock.patch.multiple(
            GATEWAY, append_audit=lambda path, record: audits.append(record),
            remove_target=lambda name: removed.append(name))
        patcher.start()
        self.addCleanup(patcher.stop)
        return root, config, target, audits, removed

    def run_execute(self, config, target, guard=lambda: True):
        out_read, out_write = os.pipe()
        err_read, err_write = os.pipe()
        try:
            code = GATEWAY.execute(config, 'command', target, guard, lambda: True,
                                   (out_write, err_write), subprocess.DEVNULL)
            os.set_blocking(out_read, False)
            try:
                output = os.read(out_read, 4096)
            except BlockingIOError:
                output = b''
            return code, output
        finally:
            for fd in (out_read, out_write, err_read, err_write):
                os.close(fd)

    def test_completed_command_returns_its_exit_after_cleanup(self):
        root, config, target, audits, removed = self.fixture('echo "$3"; exit 7\n')
        code, output = self.run_execute(config, target)
        self.assertEqual((code, output), (7, b'command\n'))
        self.assertEqual(removed, ['ag-mvp-test-target'])
        self.assertEqual((root / 'domain' / 'cgroup.kill').read_text(), '1')
        self.assertEqual(len(audits), 1)
        self.assertEqual((audits[0]['state'], audits[0]['exit_code'], audits[0]['domain_killed']), ('completed', 7, True))
        self.assertEqual(audits[0]['cleanup_errors'], [])

    def test_launch_failure_still_cleans_up_and_audits(self):
        _, config, target, audits, removed = self.fixture('exit 0\n')
        config['runner_path'] = config['runner_path'] + '.missing'
        with self.assertRaises(FileNotFoundError):
            self.run_execute(config, target)
        self.assertEqual(removed, ['ag-mvp-test-target'])
        self.assertEqual((audits[0]['state'], audits[0]['exit_code']), ('launch_error', 1))

    def test_guard_loss_mid_command_stops_the_runner(self):
        root, config, target, audits, _ = self.fixture('echo $$ > "$0.pid"; exec sleep 30\n')
        calls = []

        def guard():
            calls.append(1)
            return len(calls) < 5
        started = time.monotonic()
        code, _ = self.run_execute(config, target, guard)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual((code, audits[0]['state']), (1, 'guard_lost'))
        pid = int((root / 'runner.sh.pid').read_text())
        self.assertFalse(pathlib.Path(f'/proc/{pid}').exists(), 'the runner survived guard loss')

    def test_each_cleanup_step_runs_even_when_another_fails(self):
        _, config, target, audits, removed = self.fixture('exit 0\n', domain=False)
        code, _ = self.run_execute(config, target)
        self.assertEqual(code, 1)
        self.assertEqual(removed, ['ag-mvp-test-target'])
        self.assertEqual((audits[0]['state'], audits[0]['domain_killed']), ('cleanup_incomplete', False))
        self.assertTrue(any(item.startswith('cgroup.kill') for item in audits[0]['cleanup_errors']))

    def test_failed_target_removal_fails_the_command(self):
        _, config, target, audits, _ = self.fixture('exit 0\n')

        def refuse(name):
            raise subprocess.CalledProcessError(1, ['docker', 'rm'])
        with unittest.mock.patch.object(GATEWAY, 'remove_target', refuse):
            code, _ = self.run_execute(config, target)
        self.assertEqual((code, audits[0]['state']), (1, 'cleanup_incomplete'))

    def test_audit_failure_is_an_error_after_cleanup(self):
        _, config, target, _, removed = self.fixture('exit 0\n')

        def broken(path, record):
            raise ValueError('audit custody changed')
        with unittest.mock.patch.object(GATEWAY, 'append_audit', broken):
            with self.assertRaisesRegex(ValueError, 'audit custody'):
                self.run_execute(config, target)
        self.assertEqual(removed, ['ag-mvp-test-target'])


class TargetMountTest(unittest.TestCase):
    FIXED = [{'Type': 'volume', 'Source': '/v/work', 'Destination': '/var/lib/agentgate/workspace', 'RW': True},
             {'Type': 'bind', 'Source': '/run/agentgate/poc-demo/streams', 'Destination': '/run/agentgate/streams', 'RW': True},
             {'Type': 'volume', 'Source': '/v/bridge', 'Destination': '/run/agentgate/taskboard', 'RW': False}]

    def test_only_the_approved_mount_set_passes(self):
        config = {'host_mounts': [{'path': '/var/lib/agentgate/mounts/repo', 'source': '/srv/repo', 'read_only': True}],
                  'taskboard_bridge': True}
        repo = {'Type': 'bind', 'Source': '/srv/repo', 'Destination': '/var/lib/agentgate/mounts/repo', 'RW': False}
        GATEWAY.check_mounts(self.FIXED + [repo], config)
        for name, mounts in {
            'missing host mount': self.FIXED,
            'writable host mount': self.FIXED + [dict(repo, RW=True)],
            'other source': self.FIXED + [dict(repo, Source='/etc')],
            'extra mount': self.FIXED + [repo, dict(repo, Destination='/data')],
            'duplicate': self.FIXED + [repo, repo],
            'writable bridge': [self.FIXED[0], self.FIXED[1], dict(self.FIXED[2], RW=True), repo],
            'socket': self.FIXED + [repo, {'Type': 'bind', 'Source': '/var/run/docker.sock',
                                           'Destination': '/var/lib/agentgate/mounts/x', 'RW': True}],
        }.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                GATEWAY.check_mounts(mounts, config)
        GATEWAY.check_mounts(self.FIXED, {'host_mounts': [], 'taskboard_bridge': True})

    def test_a_target_without_the_bridge_must_not_hold_it(self):
        config = {'host_mounts': [], 'taskboard_bridge': False}
        GATEWAY.check_mounts(self.FIXED[:2], config)
        with self.assertRaisesRegex(ValueError, 'differs from the approved set: /run/agentgate/taskboard'):
            GATEWAY.check_mounts(self.FIXED, config)
        with self.assertRaisesRegex(ValueError, 'absent'):
            GATEWAY.check_mounts(self.FIXED[:2], dict(config, taskboard_bridge=True))

    def test_binding_accepts_only_exact_host_mount_records(self):
        good = [{'path': '/var/lib/agentgate/mounts/repo', 'source': '/srv/repo', 'read_only': True}]
        self.assertTrue(GATEWAY.valid_host_mounts(good))
        self.assertTrue(GATEWAY.valid_host_mounts([]))
        for bad in ([dict(good[0], path='/etc/repo')], [dict(good[0], path='/var/lib/agentgate/mounts/a/b')],
                    [dict(good[0], path='/var/lib/agentgate/mounts/')], [dict(good[0], path='/var/lib/agentgate/mounts/..')],
                    good * 2, [dict(good[0], source='relative')],
                    [dict(good[0], read_only='yes')], [dict(good[0], extra=1)], good * 9, 'none'):
            self.assertFalse(GATEWAY.valid_host_mounts(bad), bad)


class PinDirectoryTest(unittest.TestCase):
    def test_orphaned_pins_release_only_owned_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            pins = pathlib.Path(directory) / 'pins'
            pins.mkdir(mode=0o700)
            for index in range(GATEWAY.HOST_LINKS):
                (pins / f'link-{index}').write_bytes(b'')
            (pins / 'map-0-events').write_bytes(b'')
            GATEWAY.remove_pin_directory(pins, GATEWAY.HOST_LINKS)
            self.assertFalse(pins.exists())
            pins.mkdir(mode=0o700)
            (pins / f'link-{GATEWAY.NETWORK_LINKS}').write_bytes(b'')
            with self.assertRaisesRegex(ValueError, 'unexpected entry'):
                GATEWAY.remove_pin_directory(pins, GATEWAY.NETWORK_LINKS)
            self.assertTrue((pins / f'link-{GATEWAY.NETWORK_LINKS}').exists())
            (pins / f'link-{GATEWAY.NETWORK_LINKS}').unlink()
            (pins / 'link-0').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(ValueError, 'unexpected entry'):
                GATEWAY.remove_pin_directory(pins, GATEWAY.NETWORK_LINKS)
            (pins / 'link-0').unlink()
            pins.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'custody'):
                GATEWAY.remove_pin_directory(pins, GATEWAY.NETWORK_LINKS)


class RunnerArgumentTest(unittest.TestCase):
    SCRIPT = pathlib.Path(__file__).with_name('run-in-target.sh')

    def inner(self):
        script = self.SCRIPT.read_text()
        return script.split("/bin/sh -c -- \\\n    '")[1].split("' \\\n    agentgate-join")[0]

    def test_commands_are_never_shell_options_and_keep_their_bytes(self):
        unified = [line for line in pathlib.Path('/proc/self/cgroup').read_text().splitlines()
                   if line.startswith('0::/')]
        if len(unified) != 1:
            self.skipTest('cgroup v2 membership format required')
        member = unified[0][len('0::/'):]
        with tempfile.TemporaryDirectory() as directory:
            procs = pathlib.Path(directory) / 'cgroup.procs'
            for command, expected in [
                    ('+x 2>/dev/null; echo ran', b'ran\n'),
                    ('-e 2>/dev/null; echo ran', b'ran\n'),
                    ('printf "%s|" "a\'b" \'c"d\'\necho', b'a\'b|c"d|\n'),
                    ('echo "$#"', b'0\n')]:
                done = subprocess.run(
                    ['/bin/sh', '-c', 'exec 3>"$1"; shift; exec /bin/sh -c -- "$@"', 'outer', str(procs),
                     self.inner(), 'agentgate-join', command, member],
                    stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
                self.assertEqual(done.stdout, expected, (command, done.stderr))

    def test_runner_refuses_empty_commands_and_foreign_domains(self):
        if os.geteuid() != 0:
            self.skipTest('the runner refuses every non-root caller first')
        for args in (['1', '/sys/fs/cgroup/ag-mvp-demo-domain', ''],
                     ['1', '/sys/fs/cgroup/ag-mvp-demo/../x', 'true'],
                     ['1', '/sys/fs/cgroup/ag-mvp-demo-domain/sub', 'true'],
                     ['1', '/sys/fs/cgroup/other', 'true'],
                     ['1x', '/sys/fs/cgroup/ag-mvp-demo-domain', 'true'],
                     ['1', '/sys/fs/cgroup/ag-mvp-demo-domain', 'true', 'other-mode']):
            done = subprocess.run(['/bin/sh', str(self.SCRIPT)] + args, capture_output=True, timeout=10)
            self.assertNotEqual(done.returncode, 0, args)
            if args[3:] != ['other-mode']:
                self.assertEqual(done.returncode, 2, args)


if __name__ == '__main__':
    unittest.main()
