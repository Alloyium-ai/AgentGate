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
        guard = (pathlib.Path(__file__).with_name('start-guard.sh')).read_text()
        self.assertIn('seq 0 %d' % (GATEWAY.HOST_LINKS - 1), guard)

    def test_late_join_runs_the_command_only_after_joining(self):
        script = pathlib.Path(__file__).with_name('run-in-target.sh').read_text()
        inner = script.split("/bin/sh -c \\\n    '")[1].split("' \\\n    agentgate-join")[0]
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


if __name__ == '__main__':
    unittest.main()
