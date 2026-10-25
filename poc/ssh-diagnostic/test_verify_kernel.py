# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Logic tests for verify-kernel.sh with the guard, docker and probe driver faked.

No BPF-LSM kernel, Docker or VM is available here, so every kernel-dependent
step is a stand-in; these tests check the script's staging, refusals, verbatim
reporting and that it never asserts kernel_verified itself.
"""
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / 'verify-kernel.sh'
sys.path.insert(0, str(HERE))


class VerifyKernelTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.root = self.base / 'instance'
        self.root.mkdir()
        self.marker = self.base / 'marker'
        self.marker.write_text('kernel-poc-verify\n')
        for name in ('network_policy.bpf.o', 'fs_access.bpf.o', 'process_guard.bpf.o'):
            (self.root / name).write_bytes(b'\x00')
        self.behaviour = {
            'preflight': {'rc': 0, 'stdout': '{"ok": true, "kernel": "6.8.0-142-generic"}', 'stderr': ''},
            'load-check': {'rc': 0, 'stdout': '{"ok": true, "objects": []}', 'stderr': ''},
            'network-info': {'rc': 1, 'stdout': '', 'stderr': 'deny tree /etc/secret contains allow /etc/secret/readable'},
        }
        self.write_guard()

    def write_guard(self):
        guard = self.root / 'pilot-network-diagnostic'
        guard.write_text('#!/usr/bin/env python3\n'
                         'import json, sys\n'
                         'behaviour = json.loads(%r)\n'
                         'entry = behaviour.get(sys.argv[1], {"rc": 0, "stdout": "{}", "stderr": ""})\n'
                         'sys.stdout.write(entry["stdout"])\n'
                         'sys.stderr.write(entry["stderr"])\n'
                         'sys.exit(entry["rc"])\n' % json.dumps(self.behaviour))
        guard.chmod(0o755)

    def write_probe(self, result):
        probe = self.root / 'verify-probe.sh'
        probe.write_text('#!/bin/sh\n'
                         'cat > "$1" <<\'JSON\'\n' + json.dumps(result) + '\nJSON\n'
                         'exit %d\n' % (0 if result.get('ok') else 1))
        probe.chmod(0o755)

    def run_script(self, *args, marker=None, instance='demo'):
        env = dict(os.environ, AGENTGATE_VERIFY_ROOT=str(self.root),
                   AGENTGATE_VERIFY_MARKER=str(marker if marker is not None else self.marker))
        return subprocess.run(['/bin/bash', str(SCRIPT), '--instance', instance, *args],
                              capture_output=True, timeout=30, env=env)

    def report(self, done):
        return json.loads(done.stdout.decode())

    def test_refuses_to_run_without_the_disposable_marker(self):
        done = self.run_script(marker=self.base / 'absent')
        self.assertEqual(done.returncode, 3)
        self.assertIn('disposable-VM marker', done.stderr.decode())
        self.marker.write_text('production-machine\n')
        self.assertEqual(self.run_script().returncode, 3)

    def test_rejects_hostile_instance_names_and_missing_root(self):
        for instance in ('../escape', 'Demo', 'a b', '-x'):
            self.assertEqual(self.run_script(instance=instance).returncode, 2, instance)
        env = dict(os.environ, AGENTGATE_VERIFY_ROOT=str(self.base / 'nope'), AGENTGATE_VERIFY_MARKER=str(self.marker))
        done = subprocess.run(['/bin/bash', str(SCRIPT), '--instance', 'demo'], capture_output=True, timeout=30, env=env)
        self.assertEqual(done.returncode, 4)

    def test_self_check_passes_and_writes_a_report(self):
        report_path = self.base / 'self.json'
        done = self.run_script('--self-check', '--report', str(report_path))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(report_path.read_text())['checks'][0]['stage'], 'self-check')
        self.assertEqual(stat.S_IMODE(report_path.stat().st_mode), 0o600)

    def test_full_pass_records_every_stage_and_the_service_sets_verification(self):
        self.write_probe({'ok': True, 'probes': [{'name': 'denied-read-etc-shadow', 'errno': 'EACCES', 'ok': True}],
                          'denials': [{'operation': 'open', 'path': '/etc/shadow'}]})
        report_path = self.base / 'report.json'
        done = self.run_script('--report', str(report_path))
        self.assertEqual(done.returncode, 0, done.stderr)
        report = self.report(done)
        stages = [c['stage'] for c in report['checks']]
        self.assertEqual(stages, ['preflight', 'bpf-load', 'deny-overrides-allow', 'probes'])
        self.assertTrue(report['ok'] and all(c['ok'] for c in report['checks']))
        self.assertEqual(report['kernel'], '6.8.0-142-generic')
        self.assertEqual(report['probes'][0]['name'], 'denied-read-etc-shadow')
        self.assertEqual(report['denials'][0]['path'], '/etc/shadow')
        # The kit never asserts the verified flag; the service decides.
        self.assertNotIn('kernel_verified', report)
        self.assertNotIn('kernel_verified', report_path.read_text())

    def test_verifier_errors_are_reported_verbatim_and_fail_the_run(self):
        self.behaviour['load-check'] = {'rc': 1, 'stdout': '{"ok": false}',
                                        'stderr': 'attach fs_path_mknod: program rejected: '
                                                  'invalid func bpf_d_path#147 for this hook'}
        self.write_guard()
        self.write_probe({'ok': True, 'probes': []})
        done = self.run_script()
        self.assertEqual(done.returncode, 5)
        report = self.report(done)
        load = next(c for c in report['checks'] if c['stage'] == 'bpf-load')
        self.assertFalse(load['ok'])
        self.assertIn('invalid func bpf_d_path#147 for this hook', load['detail'])
        self.assertFalse(report['ok'])

    def test_a_more_specific_allow_beneath_a_deny_must_be_rejected(self):
        self.write_probe({'ok': True, 'probes': []})
        # The faked validator rejects it: the stage passes.
        done = self.run_script()
        overlap = next(c for c in self.report(done)['checks'] if c['stage'] == 'deny-overrides-allow')
        self.assertTrue(overlap['ok'])
        self.assertIn('rejected as expected', overlap['detail'])
        # If the validator ever accepts it, the stage fails and the run fails.
        self.behaviour['network-info'] = {'rc': 0, 'stdout': '{"digest":"x"}', 'stderr': ''}
        self.write_guard()
        done = self.run_script()
        self.assertEqual(done.returncode, 5)
        overlap = next(c for c in self.report(done)['checks'] if c['stage'] == 'deny-overrides-allow')
        self.assertFalse(overlap['ok'])

    def test_failed_preflight_is_recorded_verbatim(self):
        self.behaviour['preflight'] = {'rc': 1, 'stdout': '{"ok": false, "error": "BPF LSM absent"}',
                                       'stderr': 'refuse kernel load: BPF LSM absent from active VM LSM list'}
        self.write_guard()
        self.write_probe({'ok': True, 'probes': []})
        done = self.run_script()
        self.assertEqual(done.returncode, 5)
        preflight = next(c for c in self.report(done)['checks'] if c['stage'] == 'preflight')
        self.assertFalse(preflight['ok'])
        self.assertIn('BPF LSM absent from active VM LSM list', preflight['detail'])

    def test_missing_probe_driver_fails_the_run(self):
        done = self.run_script()
        self.assertEqual(done.returncode, 5)
        probes = next(c for c in self.report(done)['checks'] if c['stage'] == 'probes')
        self.assertFalse(probes['ok'])
        self.assertIn('behaviour was not exercised', probes['detail'])

    def test_a_failing_probe_fails_the_run(self):
        self.write_probe({'ok': False, 'probes': [{'name': 'write-to-usr', 'errno': '0', 'ok': False,
                                                   'note': 'write to /usr unexpectedly succeeded'}]})
        done = self.run_script()
        self.assertEqual(done.returncode, 5)
        report = self.report(done)
        self.assertFalse(report['ok'])
        self.assertFalse(next(c for c in report['checks'] if c['stage'] == 'probes')['ok'])

    def test_work_directory_is_cleaned_up(self):
        before = set(Path(tempfile.gettempdir()).glob('agentgate-verify.*'))
        self.write_probe({'ok': True, 'probes': []})
        self.run_script()
        after = set(Path(tempfile.gettempdir()).glob('agentgate-verify.*'))
        self.assertEqual(before, after)


class ProbeJudgementTest(unittest.TestCase):
    def setUp(self):
        import verify_kernel
        self.kit = verify_kernel
        self.good = {name: ('0' if expected == 'allowed' else 'EPERM' if expected == 'permission' else 'ENOENT'
                            if expected == 'unreadable' else 'EACCES') for name, expected, _ in verify_kernel.CHECKS}

    def lines(self, outcomes):
        return '\n'.join('%s %s' % item for item in outcomes.items()) + '\n'

    def test_every_expectation_passes_with_the_right_outcomes(self):
        verdict = self.kit.judge(self.lines(self.good), 'canary-value')
        self.assertTrue(verdict['ok'], verdict)
        names = {p['name'] for p in verdict['probes']}
        for required in ('allow-create', 'allow-exec-tree', 'allow-read-sibling', 'deny-read-tree', 'deny-write-readonly',
                         'deny-exec-nontree', 'deny-mknod-regular', 'deny-mkfifo', 'deny-unix-bind', 'deny-hardlink',
                         'deny-ptrace', 'deny-foreign-dns', 'allow-broker-endpoint', 'deny-broker-other-port',
                         'deny-broker-gateway', 'deny-broker-neighbour', 'deny-secret-mount', 'deny-secret-store', 'secret-canary-absent'):
            self.assertIn(required, names)

    def test_a_guard_negative_requires_permission_not_a_generic_failure(self):
        # A deny that fails for an unrelated reason (EROFS, ECONNREFUSED, a
        # timeout, ENOEXEC, EXDEV) must not pass: only EPERM/EACCES does.
        for name in ('deny-read-tree', 'deny-write-readonly', 'deny-exec-nontree', 'deny-mknod-regular',
                     'deny-hardlink', 'deny-ptrace', 'deny-broker-gateway', 'deny-foreign-dns'):
            for value in ('0', 'EROFS', 'EXDEV', 'ENOEXEC', 'ECONNREFUSED', 'ETIMEDOUT', 'None', 'missing'):
                outcomes = dict(self.good, **{name: value})
                with self.subTest(name=name, value=value):
                    self.assertEqual(self.kit.judge(self.lines(outcomes), 'canary-value')['ok'], value in self.kit.PERMISSION)

    def test_wrong_outcomes_fail(self):
        for name, value in (('allow-create', 'EACCES'), ('allow-exec-tree', 'EACCES'), ('allow-read-sibling', 'EACCES'),
                            ('deny-mkfifo', '0'), ('deny-unix-bind', '0'), ('deny-exec-nontree', '0'),
                            ('allow-broker-endpoint', 'EPERM'), ('deny-broker-other-port', 'ECONNREFUSED'),
                            ('deny-broker-gateway', 'None'), ('deny-broker-neighbour', '0'), ('deny-secret-store', '0')):
            outcomes = dict(self.good, **{name: value})
            with self.subTest(name=name, value=value):
                self.assertFalse(self.kit.judge(self.lines(outcomes), 'canary-value')['ok'])
        missing = dict(self.good)
        del missing['deny-mkfifo']
        self.assertFalse(self.kit.judge(self.lines(missing), 'canary-value')['ok'])

    def test_required_host_denials_follow_the_receipt_counts(self):
        full = {'filesystem': {'operations': {op: {'allowed': 2, 'denied': 1} for op in ('read', 'write', 'execute', 'create', 'hardlink')}},
                'process': {'operations': {'ptrace': {'allowed': 0, 'denied': 1}}}}
        probes = self.kit.required_denials({}, full)
        self.assertTrue(probes and all(p['ok'] for p in probes), probes)
        # The create denial alone (only path_mknod working) leaves read, write,
        # execute, hardlink and ptrace with no recorded denial: those must fail.
        only_create = {'filesystem': {'operations': {'create': {'denied': 3}}}, 'process': {'operations': {}}}
        failing = {p['name'] for p in self.kit.required_denials({}, only_create) if not p['ok']}
        self.assertEqual(failing, {'host-denial-filesystem-read', 'host-denial-filesystem-write',
                                   'host-denial-filesystem-execute', 'host-denial-filesystem-hardlink',
                                   'host-denial-process-ptrace'})
        # No operations at all (enforcement off): every required denial fails.
        self.assertTrue(all(not p['ok'] for p in self.kit.required_denials({}, {})))
        self.assertEqual(self.kit.host_denial_counts({'filesystem': {'operations': {'read': {'denied': 4}}}}), {('filesystem', 'read'): 4})

    def test_the_secret_canary_must_never_appear(self):
        text = self.lines(self.good) + 'canary-value\n'
        verdict = self.kit.judge(text, 'canary-value')
        self.assertFalse(verdict['ok'])
        self.assertFalse(next(p for p in verdict['probes'] if p['name'] == 'secret-canary-absent')['ok'])

    def test_command_line(self):
        out = io.StringIO()
        self.assertEqual(self.kit.main(['checks'], stdout=out), 0)
        self.assertTrue(any(item['name'] == 'deny-unix-bind' for item in json.loads(out.getvalue())))
        out = io.StringIO()
        self.assertEqual(self.kit.main(['judge', 'x' * 16], stdin=io.StringIO(self.lines(self.good)), stdout=out), 0)
        self.assertTrue(json.loads(out.getvalue())['ok'])


class ProbeDriverTest(unittest.TestCase):
    """verify-probe.sh with Docker, the launch runtime and the guard faked: its wiring only."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.root, self.bin = self.base / 'instance', self.base / 'bin'
        self.root.mkdir()
        self.bin.mkdir()
        self.store = self.base / 'secrets' / 'verify-probe'
        self.docker_log = self.base / 'docker.log'
        docker = self.bin / 'docker'
        docker.write_text('#!/bin/sh\nprintf "%%s\\n" "$*" >> %s\n' % self.docker_log)
        docker.chmod(0o755)
        guard = self.root / 'pilot-network-diagnostic'
        guard.write_text('#!/bin/sh\nprintf \'{"digest":"%s","document":{}}\'\n' % ('ab' * 32))
        guard.chmod(0o755)

    # A host block whose recorded denials satisfy every required operation.
    FULL_DENIALS = {op: {'allowed': 1, 'denied': 1} for op in ('read', 'write', 'execute', 'create', 'hardlink')}

    def write_launch(self, outcomes, joined=True, leak=False, fs_operations=None, process_operations=None, fs_denials=None):
        host = {'filesystem': {'operations': fs_operations if fs_operations is not None else dict(self.FULL_DENIALS),
                               'denials': fs_denials if fs_denials is not None else [{'path': '/var/lib/agentgate/mounts/fixtures/blocked/secret'}]},
                'process': {'operations': process_operations if process_operations is not None else {'ptrace': {'allowed': 0, 'denied': 1}},
                            'denials': []}}
        receipt = {'broker': {'target_joined': joined}, 'evidence': {'host': host}}
        lines = ''.join('%s %s\n' % item for item in outcomes.items())
        (self.root / 'launch.py').write_text(
            'import json, pathlib, sys\n'
            'root = pathlib.Path(%r)\n'
            'if sys.argv[1] == "run":\n'
            '    (root / "job.json").write_bytes(sys.stdin.buffer.read())\n'
            'elif sys.argv[1] == "receipt":\n'
            '    print(json.dumps(%r))\n'
            'elif sys.argv[1] == "logs":\n'
            '    sys.stdout.write(%r)\n'
            '    if %r:\n'
            '        sys.stdout.write((pathlib.Path(%r) / "probe").read_text())\n'
            % (str(self.root), receipt, lines, leak, str(self.store)))

    def run_probe(self):
        env = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'], AGENTGATE_VERIFY_PROBE_ROOT=str(self.root),
                   AGENTGATE_VERIFY_PROBE_IMAGE='sha256:' + 'c' * 64, AGENTGATE_VERIFY_PROBE_STORE=str(self.store))
        result = self.base / 'result.json'
        done = subprocess.run(['/bin/bash', str(HERE / 'verify-probe.sh'), str(result)], capture_output=True, timeout=60, env=env)
        return done, (json.loads(result.read_text()) if result.exists() else None)

    def good(self):
        import verify_kernel
        return {name: ('0' if expected == 'allowed' else 'EPERM' if expected == 'permission' else 'ENOENT')
                for name, expected, _ in verify_kernel.CHECKS}

    def test_the_driver_builds_a_broker_launch_and_cleans_up(self):
        self.write_launch(self.good())
        done, result = self.run_probe()
        self.assertEqual(done.returncode, 0, done.stderr.decode() + json.dumps(result))
        self.assertTrue(result['ok'])
        docker = self.docker_log.read_text()
        self.assertIn('network create --internal --driver bridge --subnet 172.30.255.0/29 --gateway 172.30.255.1 '
                      'agentgate-kernelverify00000000000000000000-broker', docker)
        self.assertIn('--ip 172.30.255.2 --read-only --cap-drop ALL', docker)
        self.assertIn('rm -f agentgate-verify-broker', docker)
        self.assertIn('network rm agentgate-kernelverify00000000000000000000-broker', docker)
        job = json.loads((self.root / 'job.json').read_text())
        self.assertEqual(job['policy']['broker'], {'address': '172.30.255.2', 'protocol': 'tcp', 'port': 8443})
        self.assertNotIn('taskboard', job['policy'])
        self.assertEqual(job['policy_digest'], 'ab' * 32)
        self.assertEqual(job['broker']['env'], {'PROBE_BROKER_URL': 'http://172.30.255.2:8443/probe'})
        import launch_job
        launch = launch_job.check_job(json.dumps(job).encode(), ['snapshots', 'live-mounts'])
        self.assertEqual(launch['env']['PROBE_BROKER_URL'], 'http://172.30.255.2:8443/probe')
        # The launch mounts the fixtures folder read-write and asks for it in the spec.
        self.assertEqual(len(launch['mounts']), 1)
        mount = launch['mounts'][0]
        self.assertEqual((mount['name'], mount['mode']), ('fixtures', 'read-write'))
        self.assertTrue(mount['source'].endswith('/fixtures') and mount['source'].startswith('/'), mount['source'])
        self.assertEqual(job['spec']['mounts'], job['mounts'])  # same_mounts holds
        self.assertEqual(launch['workdir'], '/var/lib/agentgate/mounts/fixtures/work')
        self.assertFalse(self.store.exists(), 'the canary store outlived the probe')

    def test_a_leaked_canary_or_an_unjoined_target_fails(self):
        self.write_launch(self.good(), leak=True)
        done, result = self.run_probe()
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(next(p for p in result['probes'] if p['name'] == 'secret-canary-absent')['ok'])
        self.write_launch(self.good(), joined=False)
        done, result = self.run_probe()
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(next(p for p in result['probes'] if p['name'] == 'target-joined-broker-network')['ok'])

    def test_the_suite_fails_when_the_deny_tree_enforcement_is_off(self):
        # Every probe reports EACCES (looks denied), but the guard recorded no
        # denial: enforcement is silently off and the error came from elsewhere.
        probes_denied = {name: ('0' if expected == 'allowed' else 'EACCES' if expected == 'permission' else 'ENOENT')
                         for name, expected, _ in self._checks()}
        self.write_launch(probes_denied, fs_operations={}, process_operations={}, fs_denials=[])
        done, result = self.run_probe()
        self.assertNotEqual(done.returncode, 0, 'the suite passed with no recorded denial')
        failing = {p['name'] for p in result['probes'] if not p['ok']}
        self.assertIn('denials-container-absolute', failing)
        for op in ('read', 'write', 'execute', 'create', 'hardlink'):
            self.assertIn('host-denial-filesystem-' + op, failing)
        self.assertIn('host-denial-process-ptrace', failing)

    def test_the_suite_fails_when_only_path_mknod_denies(self):
        # The create hook denies, but read/write/execute/hardlink and ptrace do
        # not: their probes look EACCES yet no host denial was recorded.
        looks_denied = {name: ('0' if expected == 'allowed' else 'EACCES' if expected == 'permission' else 'ENOENT')
                        for name, expected, _ in self._checks()}
        self.write_launch(looks_denied, fs_operations={'create': {'denied': 2}}, process_operations={},
                          fs_denials=[{'path': '/var/lib/agentgate/mounts/fixtures/work/node'}])
        done, result = self.run_probe()
        self.assertNotEqual(done.returncode, 0, 'the suite passed with only path_mknod enforcing')
        failing = {p['name'] for p in result['probes'] if not p['ok']}
        self.assertEqual(failing, {'host-denial-filesystem-read', 'host-denial-filesystem-write',
                                   'host-denial-filesystem-execute', 'host-denial-filesystem-hardlink',
                                   'host-denial-process-ptrace'})
        self.assertNotIn('host-denial-filesystem-create', [p['name'] for p in result['probes'] if not p['ok']])

    def test_a_host_side_denial_path_fails_the_container_absolute_check(self):
        self.write_launch(self.good(), fs_denials=[{'path': '/var/lib/docker/overlay2/abc/merged/etc/shadow'}])
        done, result = self.run_probe()
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(next(p for p in result['probes'] if p['name'] == 'denials-container-absolute')['ok'])

    def _checks(self):
        import verify_kernel
        return verify_kernel.CHECKS


if __name__ == '__main__':
    unittest.main()
