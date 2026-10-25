# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Per-launch lifetime tests for the shared runtime pieces (gateway, scripts, mounts)."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from test_launch import GATEWAY  # noqa: E402

S = 1_000_000_000


class DeadlineTest(unittest.TestCase):
    def test_ssh_window_is_unchanged(self):
        start, now = 100 * S, 101 * S
        # The SSH policy requires 25; the window is min(now + 25 s, start + duration).
        self.assertEqual(GATEWAY.command_deadline(None, 25, start, now), 125 * S)
        self.assertEqual(GATEWAY.command_deadline(None, 60, start, now), 126 * S)
        with self.assertRaises(ValueError):
            GATEWAY.command_deadline(None, 61, start, now)
        with self.assertRaises(ValueError):
            GATEWAY.command_deadline(None, 0, start, now)
        # At most one second left refuses, exactly as before.
        with self.assertRaises(ValueError):
            GATEWAY.command_deadline(None, 2, start, now)

    def test_launch_lifetimes_are_hard_caps_from_before_the_guard_starts(self):
        start, now = 100 * S, 102 * S
        for mode, seconds, ok in (('oneshot', 1, False), ('oneshot', 3, True), ('oneshot', 3600, True),
                                  ('oneshot', 3601, False), ('session', 59, False), ('session', 60, True),
                                  ('session', 86400, True), ('session', 86401, False), ('daemon', 60, False),
                                  ('session', 60.0, False), ('session', True, False)):
            with self.subTest(mode=mode, seconds=seconds):
                if ok:
                    self.assertEqual(GATEWAY.command_deadline(mode, seconds, start, now), start + seconds * S)
                else:
                    with self.assertRaises(ValueError):
                        GATEWAY.command_deadline(mode, seconds, start, now)

    def test_start_guard_uses_the_shared_deadline_and_requires_host_controls(self):
        script = (HERE / 'start-guard.sh').read_text()
        self.assertIn('command_deadline(mode,duration,start_ns,time.monotonic_ns())', script)
        self.assertIn("assert mode is None or host_controls", script)
        self.assertNotIn('25_000_000_000', script)
        self.assertNotIn('assert 1 <= duration <= 60', script)

    def test_ssh_policy_preparation_refuses_a_launch_policy(self):
        self.assertIn("a launch-mode policy cannot serve SSH commands", (HERE / 'prepare-policy.py').read_text())


class RelayTest(unittest.TestCase):
    def test_sinks_receive_output_without_descriptors_and_stop_ends_the_relay(self):
        received = {'stdout': bytearray(), 'stderr': bytearray()}
        sinks = {name: received[name].extend for name in received}
        process = subprocess.Popen([sys.executable, '-c', 'import sys,time; print("a", flush=True); '
                                    'print("b", file=sys.stderr, flush=True); time.sleep(30)'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            started = time.monotonic()
            calls = []
            state, _, lengths = GATEWAY.relay_process(process, lambda: True, lambda: True,
                                                      time.monotonic_ns() + 20 * S, sinks=sinks,
                                                      should_stop=lambda: calls.append(1) or len(calls) > 10)
            self.assertEqual(state, 'stopped')
            self.assertLess(time.monotonic() - started, 5)
            self.assertEqual((bytes(received['stdout']), bytes(received['stderr'])), (b'a\n', b'b\n'))
            self.assertEqual(lengths, {'stdout': 2, 'stderr': 2})
        finally:
            process.kill()
            process.wait()
            process.stdout.close()
            process.stderr.close()

    def test_graceful_stop_signals_members_then_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            domain = Path(directory)
            (domain / 'cgroup.events').write_text('populated 1\nfrozen 0\n')
            (domain / 'cgroup.procs').write_text('11\n12\n')
            sent = []

            def kill(pid, number):
                sent.append((pid, number))
                (domain / 'cgroup.events').write_text('populated 0\nfrozen 0\n')
                (domain / 'cgroup.procs').write_text('')
            self.assertTrue(GATEWAY.graceful_stop(str(domain), S, kill=kill))
            self.assertEqual(sent, [(11, signal.SIGTERM), (12, signal.SIGTERM)])
            self.assertFalse(GATEWAY.graceful_stop(str(domain), 0, kill=kill))
            (domain / 'cgroup.events').write_text('populated 1\nfrozen 0\n')
            (domain / 'cgroup.procs').write_text('13\n')
            started = time.monotonic()
            self.assertFalse(GATEWAY.graceful_stop(str(domain), S // 5, kill=lambda pid, number: None))
            self.assertLess(time.monotonic() - started, 2)
            self.assertFalse(GATEWAY.graceful_stop(str(domain / 'absent'), S, kill=kill))


class RestartTargetArgumentTest(unittest.TestCase):
    """restart-target.sh refuses any launch argument it cannot prove safe before Docker runs."""

    def run_script(self, *args):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('restart-target.sh',):
                (root / name).write_text((HERE / name).read_text())
                (root / name).chmod(0o700)
            fake = root / 'bin'
            fake.mkdir()
            # A stand-in python3 renders fixed settings; a docker stand-in records any call.
            (fake / 'python3').write_text('#!/bin/sh\necho "domain=%s/absent-domain"; echo "root=%s"; '
                                          'echo "target_image=sha256:%s"\n' % (root, root, 'e' * 64))
            (fake / 'docker').write_text('#!/bin/sh\necho "$@" >> %s/docker.calls\nexit 1\n' % root)
            for item in fake.iterdir():
                item.chmod(0o700)
            done = subprocess.run(['/bin/bash', str(root / 'restart-target.sh')] + list(args),
                                  env={'PATH': str(fake) + ':/usr/bin:/bin'}, capture_output=True, timeout=10)
            return done.returncode, (root / 'docker.calls').exists()

    def test_invalid_launch_arguments_exit_2_before_docker(self):
        good = 'sha256:' + 'a' * 64
        for args in (('--launch', good), ('--launch', good, '59'), ('--launch', good, '90001'),
                     ('--launch', 'sha256:' + 'A' * 64, '600'), ('--launch', 'sha256:' + 'a' * 63, '600'),
                     ('--launch', 'busybox:latest', '600'), ('--other', good, '600'), ('--launch', good, '6x0'),
                     ('--launch', good, ''), ('--launch', good + ';id', '600'), ('x',)):
            with self.subTest(args=args):
                self.assertEqual(self.run_script(*args), (2, False))

    def test_invalid_bridge_arguments_exit_2_before_docker(self):
        good = 'sha256:' + 'a' * 64
        for args in (('--launch', good, '600', '--bridge'), ('--launch', good, '600', '--taskboard-bridge', 'x'),
                     ('--launch', good, '600', ''), ('--taskboard-bridge',)):
            with self.subTest(args=args):
                self.assertEqual(self.run_script(*args), (2, False))

    def test_valid_arguments_reach_the_domain_check(self):
        # The fake domain is absent, so the script stops at its first custody check.
        code, docker = self.run_script('--launch', 'sha256:' + 'a' * 64, '86700')
        self.assertNotEqual(code, 2)
        self.assertFalse(docker)
        code, docker = self.run_script()
        self.assertNotEqual(code, 2)


class RestartTargetBridgeTest(unittest.TestCase):
    """The taskboard bridge volume reaches a launch target only when the launch asks.

    restart-target.sh runs for real against a Docker stand-in that records
    every call; nothing here touches Docker.
    """

    def run_script(self, *args):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / 'restart-target.sh').write_text((HERE / 'restart-target.sh').read_text())
        (root / 'restart-target.sh').chmod(0o700)
        domain = root / 'domain'
        domain.mkdir()
        (domain / 'cgroup.events').write_text('populated 0\nfrozen 0\n')
        (root / 'mounts-active.json').write_text('[]')
        settings = {'domain': domain, 'root': root, 'target_image': 'sha256:' + 'e' * 64, 'name': 'ag-mvp-test-target',
                    'network': 'ag-mvp-test-net', 'workspace': 'ag-mvp-test-work', 'artifact': root / 'streams',
                    'bridge': 'ag-mvp-test-bridge-volume', 'bridge_image': 'sha256:' + 'b' * 64,
                    'bridge_container': 'ag-mvp-test-bridge', 'bridge_network': 'ag-mvp-test-bridge-net',
                    'task_id': '7', 'taskboard_url': 'http://10.10.10.10:8080'}
        (root / 'settings.py').write_text('import shlex\n' + ''.join(
            'print(%r + "=" + shlex.quote(%r))\n' % (k, str(v)) for k, v in settings.items()))
        (root / 'mounts.py').write_text('')
        (root / 'prepare-resolver.py').write_text('')
        fake = root / 'bin'
        fake.mkdir()
        calls = root / 'docker.calls'
        (fake / 'docker').write_text(
            '#!/bin/sh\nprintf "%%s\\n" "$*" >> %s\n'
            'case "$1 $2" in\n'
            '  "container inspect") exit 1 ;;\n'
            '  "image inspect") echo "$3" ;;\n'
            '  "volume inspect") echo "/var/lib/docker/volumes/$3/_data" ;;\n'
            '  *) case "$1" in inspect) echo "id-$2" ;; run) echo started ;; *) exit 1 ;; esac ;;\n'
            'esac\n' % calls)
        (fake / 'install').write_text('#!/bin/sh\nfor last; do :; done\nmkdir -p "$last"\n')
        for item in fake.iterdir():
            item.chmod(0o700)
        done = subprocess.run(['/bin/bash', str(root / 'restart-target.sh')] + list(args),
                              env={'PATH': str(fake) + ':/usr/bin:/bin'}, capture_output=True, timeout=20)
        self.assertEqual(done.returncode, 0, done.stderr.decode())
        runs = [line for line in calls.read_text().splitlines() if line.startswith('run ')]
        self.assertEqual(len(runs), 1)
        return runs[0], json.loads((root / 'target.json').read_text()), calls.read_text()

    def test_a_launch_without_the_bridge_has_no_path_to_it(self):
        run, target, calls = self.run_script('--launch', 'sha256:' + 'a' * 64, '700')
        self.assertNotIn('/run/agentgate/taskboard', run)
        self.assertNotIn('bridge', run)
        self.assertFalse([key for key in target if key.startswith('bridge_')], target)
        self.assertNotIn('ag-mvp-test-bridge', calls, 'the bridge container is not even inspected')
        self.assertIn('--entrypoint /bin/sh sha256:' + 'a' * 64, run)

    def test_a_launch_that_asks_and_the_ssh_command_get_it_read_only(self):
        for args in (('--launch', 'sha256:' + 'a' * 64, '700', '--taskboard-bridge'), ()):
            with self.subTest(args=args):
                run, target, _ = self.run_script(*args)
                self.assertIn('--mount type=volume,source=ag-mvp-test-bridge-volume,target=/run/agentgate/taskboard,readonly', run)
                self.assertEqual((target['bridge_path'], target['bridge_volume'], target['bridge_task_id'], target['bridge_container_id']),
                                 ('/run/agentgate/taskboard', 'ag-mvp-test-bridge-volume', 7, 'id-ag-mvp-test-bridge'))
                self.assertEqual(sum(key.startswith('bridge_') for key in target), 8)


class LaunchMountsTest(unittest.TestCase):
    def test_launch_mounts_come_only_from_the_root_owned_launch_list(self):
        import mounts
        source = (HERE / 'mounts.py').read_text()
        self.assertIn("read_private(Path(argv[1]) / LAUNCH_MOUNTS)", source)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / mounts.LAUNCH_MOUNTS).write_text(mounts.render_document([]).decode())
            (root / mounts.LAUNCH_MOUNTS).chmod(0o644)
            with self.assertRaisesRegex(mounts.MountError, 'mode 0600'):
                mounts.main(['launch', str(root)]) if os.geteuid() == 0 else mounts.read_private(root / mounts.LAUNCH_MOUNTS)
            (root / mounts.LAUNCH_MOUNTS).chmod(0o600)
            self.assertEqual(mounts.parse_document(mounts.read_private(root / mounts.LAUNCH_MOUNTS)), [])

    def test_launch_snapshots_do_not_enter_the_operator_mounts_file(self):
        import mounts
        if not hasattr(__import__('tarfile'), 'data_filter'):
            self.skipTest('Python tarfile filters required')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / 'folder'
            folder.mkdir()
            (folder / 'a.txt').write_text('a')
            archive = root / 'a.tar'
            mounts.build_snapshot(folder, archive)
            mounts.install_snapshot(root, 'repo', archive, record=False)
            self.assertFalse((root / 'mounts.json').exists())
            self.assertTrue((root / 'shares' / 'repo' / 'a.txt').exists())
            mounts.install_snapshot(root, 'repo', archive)
            self.assertTrue((root / 'mounts.json').exists())


if __name__ == '__main__':
    unittest.main()
