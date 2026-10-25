# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Launch runtime tests. Docker, the guard and the kernel are replaced by recorders.

The command execution itself is real: gateway.execute_detailed runs a stand-in
runner script on this host, so relaying, log bounds, stop requests, expiry,
graceful stops and the shell command quoting are exercised for real. Nothing
here proves BPF behavior.
"""
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import launch  # noqa: E402
import launch_job  # noqa: E402
from launch_job import JobError  # noqa: E402

SPEC = importlib.util.spec_from_file_location('agentgate_launch_gateway', HERE / 'gateway.py')
GATEWAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATEWAY)

FULL_POLICY = json.loads((HERE / 'policy.full.example.json').read_text())


def spec(**changes):
    value = {'version': 'agentgate.launch.v1', 'name': 'repo-fixer', 'target': 'local', 'mode': 'oneshot',
             'lifetime_seconds': 30,
             'agent': {'image': 'sha256:' + 'a' * 64, 'command': ['python3', '-c', 'print(6+6)'],
                       'env': {'EDITOR': 'vi'}},
             'access': {'profile': 'python-dev', 'version': 3}, 'mounts': [], 'secrets': [], 'approval': 'auto'}
    for key, item in changes.items():
        value[key] = item
    return value


def job(launch_id='launch-1', grace=1, log_limit=1 << 20, upload=4096, mounts=None, lifetime=None, **spec_changes):
    if mounts and 'mounts' not in spec_changes:
        # The service resolves exactly the requested mounts (launch_job.same_mounts).
        spec_changes['mounts'] = copy.deepcopy(mounts)
    launch_spec = spec(**spec_changes)
    lifetime = launch_spec['lifetime_seconds'] if lifetime is None else lifetime
    policy = dict(copy.deepcopy(FULL_POLICY), mode=launch_spec['mode'], duration_seconds=lifetime)
    return {'version': 'agentgate.launcher-job.v1', 'launch_id': launch_id, 'job_id': 'job-' + launch_id,
            'spec': launch_spec, 'spec_digest': 'c' * 64, 'policy': policy, 'policy_digest': 'd' * 64,
            'profile_policy_digest': 'e' * 64, 'stop_grace_seconds': grace, 'log_limit_bytes': log_limit,
            'upload_limit_bytes': upload, 'lifetime_seconds': lifetime, 'mounts': mounts or [],
            'expires_at_ms': int(time.time() * 1000) + 3_600_000, 'broker': None}


BROKER_ADDRESS = '172.30.7.2'


def broker_job(launch_id='launch-1', **changes):
    """A launch with one brokered secret: the policy holds the broker endpoint instead of the taskboard."""
    value = job(launch_id=launch_id, secrets=[{'ref': 'anthropic', 'expose': {'env': 'ANTHROPIC_BASE_URL'}}], **changes)
    del value['policy']['taskboard']
    value['policy']['broker'] = {'address': BROKER_ADDRESS, 'protocol': 'tcp', 'port': 8443}
    value['broker'] = {'network': 'agentgate-%s-broker' % launch_id, 'subnet': '172.30.7.0/29', 'address': BROKER_ADDRESS,
                       'port': 8443, 'target_address': '172.30.7.3',
                       'env': {'ANTHROPIC_BASE_URL': 'http://%s:8443/anthropic' % BROKER_ADDRESS}}
    return value


def raw(value):
    return json.dumps(value).encode()


class Events:
    """An Emitter stand-in that keeps every event."""

    def __init__(self, healthy=True):
        self.items, self.healthy, self.dropped = [], healthy, 0

    def emit(self, event, droppable=False):
        self.items.append(event)
        return True

    def kinds(self):
        return [item['event'] for item in self.items]

    def states(self):
        return [item['state'] for item in self.items if item['event'] == 'state']


class FakeHost:
    """Recorder for every Docker, script and guard step; execution runs a real runner."""

    def __init__(self, directory, runner_body=None, deadline_s=5.0, fail=None, cleanup_errors=None,
                 guard_ok=lambda: True, capabilities=('snapshots', 'live-mounts')):
        self.directory = Path(directory)
        self.steps = []
        self.fail = fail or {}
        self.cleanup_errors = cleanup_errors or []
        self.deadline_s = deadline_s
        self.guard_ok = guard_ok
        self.caps = list(capabilities)
        self.domain = self.directory / 'domain'
        self.domain.mkdir()
        (self.domain / 'cgroup.events').write_text('populated 0\nfrozen 0\n')
        (self.domain / 'cgroup.procs').write_text('')
        self.workspace = self.directory / 'workspace'
        self.workspace.mkdir()
        self.runner = self.directory / 'runner.sh'
        # The stand-in runner runs the launch command with /bin/sh as the real
        # one does, with cd redirected to a temporary workspace.
        self.runner.write_text(runner_body or (
            '#!/bin/sh\nexec /bin/sh -c \'cd() { command cd "$WS"; }; eval "$1"\' agentgate "$3"\n'))
        self.runner.chmod(0o700)
        self.commands = []
        self.audits = []
        # The stdio pipes the gateway asked the guard to record, per command.
        self.stdio = []
        self.guard_receipt_value = {'complete': True, 'stop': 'signal', 'events': [{'Allowed': 0, 'Port': 53}],
                                    'host': {'complete': True, 'filesystem': {'denials': [{'path': '/etc/shadow'}] * 300},
                                             'process': {'denials': []}},
                                    'network': {'observed': 1, 'complete': True}}

    def step(self, name, *args):
        self.steps.append((name,) + args)
        if name in self.fail:
            raise self.fail[name]

    def capability_names(self):
        return self.caps

    def precheck(self):
        self.step('precheck')

    def stage_policy(self, policy):
        self.step('stage_policy', policy['mode'], policy['duration_seconds'])
        return {'digest': 'd' * 64, 'document': policy}

    def resolve_image(self, reference):
        self.step('resolve_image', reference)
        return 'sha256:' + 'f' * 64

    def check_image(self, image_id, program):
        self.step('check_image', image_id, program)

    def stage_mounts(self, entries, launch_value):
        self.step('stage_mounts', entries)

    def start_target(self, image_id, keepalive, taskboard_bridge=False):
        self.step('start_target', image_id, keepalive, taskboard_bridge)

    def start_guard(self):
        self.step('start_guard')

    def connect_broker(self, broker):
        self.step('connect_broker', broker['network'], broker['target_address'])

    def guard_pid(self):
        return 4321

    def command_identity(self):
        return {'container_id': 'c' * 64, 'guard_pid': 4321, 'guard_start_ticks': 1, 'deadline_ns': 1}

    def bind(self):
        self.step('bind')
        config = {'runner_path': str(self.runner), 'domain': str(self.domain), 'container': 'ag-mvp-test-target',
                  'deadline_ns': time.monotonic_ns() + int(self.deadline_s * 1e9), 'host_controls': True,
                  'host_mounts': [], 'audit_path': str(self.directory / 'audit.jsonl'),
                  'source_revision': 'a' * 40, 'policy_digest': 'd' * 64}
        return config, self.guard_ok, {'State': {'Pid': 1}, 'Id': 'c' * 64, 'Image': 'sha256:' + 'f' * 64}

    def execute(self, config, command, target, guard_ok, alive, sinks, should_stop, grace, extra):
        self.commands.append(command)
        with unittest.mock.patch.multiple(GATEWAY, append_audit=lambda path, record: self.audits.append(record),
                                          remove_target=lambda name: None,
                                          record_stdio=lambda config, pipes: self.stdio.append(pipes)), \
                unittest.mock.patch.dict(os.environ, {'WS': str(self.workspace)}):
            return GATEWAY.execute_detailed(config, command, target, guard_ok, alive, stdin=subprocess.DEVNULL,
                                            sinks=sinks, should_stop=should_stop, grace_ns=grace, audit_extra=extra)

    def teardown(self, pid):
        self.step('teardown', pid)
        return list(self.cleanup_errors)

    def guard_receipt(self):
        return self.guard_receipt_value

    def mount_identities(self):
        return [{'path': '/var/lib/agentgate/mounts/repo', 'device': 1, 'inode': 2}]

    def digests(self):
        return {name: 'b' * 64 for name in launch.OBJECTS + ('pilot-network-diagnostic', 'run-in-target.sh')}

    def collect_command_files(self, destination, expected=None):
        self.step('collect', str(destination))
        Path(destination).mkdir(exist_ok=True)
        return True


class LaunchTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.launches = self.root / 'launches'
        self.launches.mkdir(mode=0o700)

    def host(self, **kwargs):
        directory = self.root / ('host-%d' % len(list(self.root.iterdir())))
        directory.mkdir()
        return FakeHost(directory, **kwargs)

    def run_job(self, value, host=None, alive=lambda: True, signalled=lambda: False, events=None):
        host = host or self.host()
        events = events or Events()
        receipt = launch.run_launch(raw(value), host, self.launches, events, alive, signalled)
        return receipt, host, events


class LaunchRunTest(LaunchTestCase):
    def test_oneshot_runs_in_order_and_returns_a_complete_receipt(self):
        receipt, host, events = self.run_job(job())
        names = [step[0] for step in host.steps]
        self.assertEqual(names, ['precheck', 'stage_policy', 'resolve_image', 'check_image', 'stage_mounts',
                                 'start_target', 'start_guard', 'bind', 'teardown', 'collect'])
        self.assertEqual(host.steps[1], ('stage_policy', 'oneshot', 30))
        # The target outlives the lifetime so its main process never ends a session early.
        # The policy keeps the taskboard and grants reading its bridge: the launch asks for the bridge.
        self.assertEqual(host.steps[5], ('start_target', 'sha256:' + 'f' * 64, 30 + launch.KEEPALIVE_MARGIN_S, True))
        self.assertEqual(host.steps[3][2], 'python3')
        self.assertEqual((receipt['state'], receipt['reason'], receipt['exit_code']), ('stopped', 'exited', 0))
        self.assertEqual(receipt['logs']['stdout']['bytes'], 3)
        self.assertEqual(receipt['logs']['stdout']['sha256'], hashlib.sha256(b'12\n').hexdigest())
        self.assertFalse(receipt['kernel_verified'])
        self.assertEqual(receipt['policy_digest'], 'd' * 64)
        self.assertEqual(receipt['image_id'], 'sha256:' + 'f' * 64)
        self.assertTrue(receipt['cleanup']['domain_empty'] and receipt['cleanup']['enforcement_released'])
        self.assertEqual(set(receipt['objects']), set(launch.OBJECTS) | {'pilot-network-diagnostic', 'run-in-target.sh'})
        self.assertEqual(events.states(), ['provisioning', 'running', 'stopping'])
        self.assertEqual(events.kinds()[-1], 'receipt')
        logs = [item for item in events.items if item['event'] == 'log']
        self.assertEqual(base64.b64decode(logs[0]['data']), b'12\n')
        directory = self.launches / 'launch-1'
        self.assertEqual(json.loads((directory / 'state.json').read_text())['state'], 'stopped')
        self.assertEqual((directory / 'stdout.log').read_bytes(), b'12\n')
        self.assertEqual(oct((directory / 'receipt.json').stat().st_mode & 0o777), '0o600')
        self.assertEqual(host.audits[0]['launch_id'], 'launch-1')

    def test_a_broker_launch_joins_its_network_after_the_guard_and_gets_only_base_urls(self):
        value = broker_job()
        value['spec']['agent']['command'] = ['sh', '-c', 'printf "%s|" "$ANTHROPIC_BASE_URL"; env']
        receipt, host, _ = self.run_job(value)
        names = [step[0] for step in host.steps]
        self.assertEqual(names, ['precheck', 'stage_policy', 'resolve_image', 'check_image', 'stage_mounts',
                                 'start_target', 'start_guard', 'connect_broker', 'bind', 'teardown', 'collect'])
        self.assertEqual(host.steps[7], ('connect_broker', 'agentgate-launch-1-broker', '172.30.7.3'))
        # A broker launch has no taskboard, so its target never gets the bridge volume.
        self.assertEqual(host.steps[5][3], False)
        out = (self.launches / 'launch-1' / 'stdout.log').read_bytes().decode()
        self.assertTrue(out.startswith('http://172.30.7.2:8443/anthropic|'), out)
        self.assertNotIn('/run/agentgate/secrets', out)
        self.assertEqual(receipt['broker'], {'network': 'agentgate-launch-1-broker', 'address': BROKER_ADDRESS, 'port': 8443,
                                             'target_address': '172.30.7.3', 'env': ['ANTHROPIC_BASE_URL'],
                                             'target_joined': True})
        self.assertEqual((receipt['state'], receipt['reason']), ('stopped', 'exited'))

    def test_a_failed_broker_join_fails_closed_and_tears_down(self):
        host = self.host(fail={'connect_broker': launch.LaunchError('network connect refused')})
        receipt, host, _ = self.run_job(broker_job(), host=host)
        names = [step[0] for step in host.steps]
        self.assertNotIn('bind', names)
        self.assertIn('teardown', names)
        self.assertEqual((receipt['state'], receipt['reason']), ('failed', 'setup_failed'))
        self.assertFalse(receipt['broker']['target_joined'])

    def test_upload_evidence_keeps_the_socket_guard_state(self):
        host = self.host()
        host.guard_receipt_value['host'].update(sockets='connect-only', socket_lsm_guard=False)
        receipt, _, _ = self.run_job(job(), host=host)
        self.assertEqual(receipt['evidence']['host']['sockets'], 'connect-only')
        self.assertIs(receipt['evidence']['host']['socket_lsm_guard'], False)
        self.assertIsNone(receipt['broker'])

    def test_upload_evidence_is_bounded(self):
        receipt, _, _ = self.run_job(job())
        denials = receipt['evidence']['host']['filesystem']['denials']
        self.assertEqual(len(denials), launch.UPLOAD_DENIALS)
        self.assertEqual(receipt['evidence']['host']['filesystem']['denials_total_kept'], 300)
        self.assertEqual(len(receipt['guard_receipt_sha256']), 64)

    def test_nonzero_exit_is_reported(self):
        value = job()
        value['spec']['agent']['command'] = ['sh', '-c', 'exit 7']
        receipt, _, _ = self.run_job(value)
        self.assertEqual((receipt['state'], receipt['exit_code']), ('stopped', 7))

    def test_hostile_command_and_environment_reach_the_agent_verbatim(self):
        hostile = "$(touch /tmp/agentgate-pwned)`id`'\"; rm -rf / ; echo \\\n--"
        value = job()
        value['spec']['agent']['command'] = ['printf', '%s|', hostile, '-n', '--', '$HOME']
        value['spec']['agent']['env'] = {'EDITOR': "vi'; touch /tmp/agentgate-pwned2; '", 'LANG': '$(id)'}
        receipt, host, _ = self.run_job(value)
        out = (self.launches / 'launch-1' / 'stdout.log').read_bytes().decode()
        self.assertEqual(out, hostile + '|-n|--|$HOME|')
        self.assertFalse(Path('/tmp/agentgate-pwned').exists())
        self.assertFalse(Path('/tmp/agentgate-pwned2').exists())
        self.assertEqual(receipt['exit_code'], 0)

    def test_environment_values_are_set_and_home_defaults_to_the_workspace(self):
        value = job()
        value['spec']['agent']['command'] = ['sh', '-c', 'printf "%s %s" "$EDITOR" "$HOME"']
        self.run_job(value)
        self.assertEqual((self.launches / 'launch-1' / 'stdout.log').read_bytes(),
                         b'vi /var/lib/agentgate/workspace')

    def test_oversized_output_is_bounded_but_counted_and_hashed(self):
        value = job(log_limit=4096, upload=1000)
        value['spec']['agent']['command'] = ['python3', '-c',
                                             'import sys; sys.stdout.write("x" * 300000); sys.stdout.flush()']
        receipt, _, events = self.run_job(value)
        log = receipt['logs']['stdout']
        self.assertEqual((log['bytes'], log['kept_bytes'], log['truncated']), (300000, 4096, True))
        self.assertEqual(log['sha256'], hashlib.sha256(b'x' * 300000).hexdigest())
        self.assertEqual((self.launches / 'launch-1' / 'stdout.log').stat().st_size, 4096)
        uploaded = sum(len(base64.b64decode(item['data'])) for item in events.items if item['event'] == 'log')
        self.assertEqual(uploaded, 1000)
        self.assertTrue(log['upload_truncated'])
        self.assertEqual(receipt['state'], 'stopped')

    def test_lifetime_expiry_kills_the_agent_and_reports_expired(self):
        value = job(grace=0)
        value['spec']['agent']['command'] = ['sleep', '30']
        host = self.host(deadline_s=0.6)
        started = time.monotonic()
        receipt, _, _ = self.run_job(value, host)
        self.assertLess(time.monotonic() - started, 6)
        self.assertEqual((receipt['state'], receipt['reason'], receipt['exit_code']), ('expired', 'lifetime_expired', None))
        self.assertEqual((host.domain / 'cgroup.kill').read_text(), '1')

    def test_stop_request_is_graceful_then_kills(self):
        value = job(grace=2)
        value['spec']['mode'], value['spec']['lifetime_seconds'] = 'session', 600
        value['policy'].update(mode='session', duration_seconds=600)
        value['lifetime_seconds'] = 600
        value['spec']['agent']['command'] = ['sleep', '30']
        host = self.host(deadline_s=30)
        directory = self.launches / 'launch-1'

        def later():
            time.sleep(0.5)
            launch.write_private(directory / 'stop-request.json',
                                 launch.dump({'reason': 'stop_requested', 'grace_seconds': 0}))
        threading.Thread(target=later).start()
        started = time.monotonic()
        receipt, _, _ = self.run_job(value, host)
        self.assertLess(time.monotonic() - started, 8)
        self.assertEqual((receipt['state'], receipt['reason']), ('stopped', 'stop_requested'))

    def test_service_unreachable_stop_is_a_failure(self):
        value = job()
        value['spec']['agent']['command'] = ['sleep', '30']
        directory = self.launches / 'launch-1'

        def later():
            time.sleep(0.4)
            launch.write_private(directory / 'stop-request.json',
                                 launch.dump({'reason': 'service_unreachable', 'grace_seconds': 0}))
        threading.Thread(target=later).start()
        receipt, _, _ = self.run_job(value, self.host(deadline_s=20))
        self.assertEqual((receipt['state'], receipt['reason']), ('failed', 'service_unreachable'))

    def test_supervisor_loss_and_signal_fail_closed(self):
        value = job()
        value['spec']['agent']['command'] = ['sleep', '30']
        calls = []
        receipt, _, _ = self.run_job(value, self.host(deadline_s=20), alive=lambda: calls.append(1) or len(calls) < 4)
        self.assertEqual((receipt['state'], receipt['reason']), ('failed', 'supervisor_lost'))
        flag = threading.Event()
        threading.Timer(0.4, flag.set).start()
        receipt, _, _ = self.run_job(job(launch_id='launch-2', **{'agent': value['spec']['agent']}),
                                     self.host(deadline_s=20), signalled=flag.is_set)
        self.assertEqual((receipt['state'], receipt['reason']), ('failed', 'supervisor_stopped'))

    def test_guard_loss_mid_run_fails_closed(self):
        value = job()
        value['spec']['agent']['command'] = ['sleep', '30']
        calls = []
        receipt, host, _ = self.run_job(value, self.host(deadline_s=20, guard_ok=lambda: calls.append(1) or len(calls) < 4))
        self.assertEqual((receipt['state'], receipt['reason']), ('failed', 'guard_lost'))
        self.assertIn(('teardown', 4321), host.steps)

    def test_cleanup_failure_is_never_reported_stopped(self):
        receipt, _, _ = self.run_job(job(), self.host(cleanup_errors=['owned domain or guard pins remain']))
        self.assertEqual((receipt['state'], receipt['reason']), ('failed', 'cleanup_incomplete'))
        self.assertFalse(receipt['cleanup']['enforcement_released'])

    def test_setup_failure_still_tears_down_and_records(self):
        for step in ('precheck', 'resolve_image', 'check_image', 'start_target', 'start_guard', 'bind'):
            with self.subTest(step=step):
                launch_id = 'setup-' + step.replace('_', '-')
                host = self.host(fail={step: launch.LaunchError(step + ' refused')})
                receipt, host, events = self.run_job(job(launch_id=launch_id), host)
                self.assertEqual((receipt['state'], receipt['reason']), ('failed', 'setup_failed'))
                self.assertIn(step + ' refused', receipt['setup_error'])
                self.assertIn('teardown', [item[0] for item in host.steps])
                self.assertEqual(events.kinds()[-1], 'receipt')
                self.assertIsNone(receipt['exit_code'])

    def test_unexpected_error_also_fails_closed_with_a_receipt(self):
        receipt, host, _ = self.run_job(job(), self.host(fail={'start_guard': TypeError('surprise')}))
        self.assertEqual(receipt['reason'], 'setup_failed')
        self.assertIn('teardown', [item[0] for item in host.steps])

    def test_teardown_exception_is_recorded_not_lost(self):
        host = self.host()
        host.teardown = lambda pid: (_ for _ in ()).throw(OSError('cgroup gone'))
        receipt, _, _ = self.run_job(job(), host)
        self.assertEqual((receipt['state'], receipt['reason']), ('failed', 'cleanup_incomplete'))
        self.assertIn('cgroup gone', receipt['cleanup']['errors'][0])

    def test_stop_before_the_agent_starts(self):
        host = self.host()
        directory = self.launches / 'launch-1'
        original = host.check_image

        def slow(image_id, program):
            original(image_id, program)
            launch.write_private(directory / 'stop-request.json',
                                 launch.dump({'reason': 'stop_requested', 'grace_seconds': 0}))
        host.check_image = slow
        receipt, host, _ = self.run_job(job(), host)
        self.assertEqual((receipt['state'], receipt['reason']), ('stopped', 'stop_requested'))
        self.assertNotIn('start_target', [item[0] for item in host.steps])

    def test_policy_digest_mismatch_refuses_before_any_target(self):
        host = self.host()
        host.stage_policy = lambda policy: {'digest': '0' * 64, 'document': policy}
        receipt, host, _ = self.run_job(job(), host)
        self.assertEqual(receipt['reason'], 'setup_failed')
        self.assertIn('digest differs', receipt['setup_error'])
        self.assertNotIn('start_target', [item[0] for item in host.steps])

    def test_a_launch_id_runs_at_most_once(self):
        self.run_job(job())
        with self.assertRaises(FileExistsError):
            self.run_job(job())

    def test_invalid_job_is_refused_before_any_step(self):
        host = self.host()
        bad = job()
        bad['spec']['secrets'] = [{'ref': 'anthropic', 'expose': {'env': 'ANTHROPIC_BASE_URL'}}]
        with self.assertRaisesRegex(JobError, 'broker block'):
            self.run_job(bad, host)
        self.assertEqual(host.steps, [])
        self.assertFalse((self.launches / 'launch-1').exists())


class StopAndReconcileTest(LaunchTestCase):
    def make_running(self, launch_id='launch-1', state='running'):
        directory = self.launches / launch_id
        directory.mkdir(mode=0o700)
        launch.write_private(directory / 'job.json', raw(job(launch_id)))
        record = launch.Record(directory)
        record.update(state, launch_id=launch_id, started_at='2026-10-24T00:00:00Z',
                      command={'container_id': 'c' * 64, 'guard_pid': 4321, 'guard_start_ticks': 1, 'deadline_ns': 1})
        return directory

    def test_double_stop_returns_the_recorded_terminal_result(self):
        receipt, host, _ = self.run_job(job())
        directory = self.launches / 'launch-1'
        first = launch.request_stop(directory, host, 5, 'stop_requested', self.root)
        second = launch.request_stop(directory, host, 5, 'stop_requested', self.root)
        self.assertEqual(first, second)
        self.assertTrue(first['already_terminal'])
        self.assertEqual(first['state'], 'stopped')
        self.assertFalse((directory / 'stop-request.json').exists())

    def test_stop_with_a_dead_runtime_tears_down_and_fails(self):
        directory = self.make_running()
        host = self.host()
        result = launch.request_stop(directory, host, 3, 'stop_requested', self.root)
        self.assertEqual((result['state'], result['reason'], result['reconciled']), ('failed', 'launcher_lost', True))
        self.assertIn(('teardown', 4321), host.steps)
        receipt = json.loads((directory / 'receipt.json').read_text())
        self.assertTrue(receipt['reconciled'])
        self.assertFalse(receipt['kernel_verified'])
        again = launch.request_stop(directory, host, 3, 'stop_requested', self.root)
        self.assertTrue(again['already_terminal'])

    def test_stop_while_running_only_requests_and_never_double_tears_down(self):
        directory = self.make_running()
        host = self.host()
        fd = launch.acquire(self.root)
        try:
            result = launch.request_stop(directory, host, 3, 'stop_requested', self.root)
            again = launch.request_stop(directory, host, 9, 'stop_requested', self.root)
        finally:
            os.close(fd)
        self.assertEqual((result['state'], result['stop_requested']), ('running', True))
        self.assertTrue(again['stop_requested'])
        self.assertNotIn('teardown', [item[0] for item in host.steps])
        # The first request's grace stays: a repeat never changes it.
        self.assertEqual(json.loads((directory / 'stop-request.json').read_text())['grace_seconds'], 3)

    def test_stop_rejects_bad_reason_grace_and_ids(self):
        directory = self.make_running()
        for grace, reason in ((-1, 'stop_requested'), (31, 'stop_requested'), (1, 'because'), ('1', 'stop_requested')):
            with self.subTest(grace=grace, reason=reason), self.assertRaises(JobError):
                launch.request_stop(directory, self.host(), grace, reason, self.root)
        for bad in ('../x', '', 'a/b', '.', '-x', 'x' * 65):
            with self.subTest(bad=bad), self.assertRaises(JobError):
                launch.launch_directory(self.launches, bad)
        with self.assertRaises(JobError):
            launch.launch_directory(self.launches, 'absent')

    def test_reconcile_after_a_crash_mid_launch(self):
        self.make_running('launch-a')
        self.make_running('launch-b', 'provisioning')
        done = self.launches / 'launch-c'
        self.make_running('launch-c')
        launch.Record(done).update('stopped')
        host = self.host()
        host.instance = unittest.mock.Mock(empty_domain=lambda: True, pins_remain=lambda: False)
        out = launch.reconcile_all(self.root, host, 'host_restarted', wait_s=0)
        self.assertEqual(sorted(item['launch_id'] for item in out), ['launch-a', 'launch-b'])
        self.assertTrue(all(item['state'] == 'failed' and item['reason'] == 'host_restarted' for item in out))
        self.assertEqual(json.loads((done / 'state.json').read_text())['state'], 'stopped')
        self.assertEqual(launch.reconcile_all(self.root, host, 'host_restarted', wait_s=0), [])

    def test_reconcile_waits_for_the_lock_then_reports_busy(self):
        fd = launch.acquire(self.root)
        try:
            with self.assertRaises(launch.Busy):
                launch.reconcile_all(self.root, self.host(), 'host_restarted', wait_s=0.3)
        finally:
            os.close(fd)

    def test_reconcile_does_not_take_files_of_a_later_command(self):
        directory = self.make_running()
        host = self.host()
        host.command_identity = lambda: {'container_id': '9' * 64}
        collected = []
        host.collect_command_files = lambda destination, expected=None: collected.append(expected) or False
        receipt = launch.reconcile_launch(directory, host, 'host_restarted')
        self.assertEqual(receipt['evidence_missing'], 'command_files_superseded')


class LockAndCommandTest(LaunchTestCase):
    def test_one_launch_per_instance(self):
        fd = launch.acquire(self.root)
        try:
            with self.assertRaises(launch.Busy):
                launch.acquire(self.root)
        finally:
            os.close(fd)
        os.close(launch.acquire(self.root))

    def test_run_command_rejects_busy_and_duplicate_with_an_event(self):
        host = self.host()
        output = io.BytesIO()
        fd = launch.acquire(self.root)
        try:
            with self.assertRaises(launch.Busy):
                launch.main(['run'], host_factory=lambda root: host, root=self.root,
                            stdin=io.BytesIO(raw(job())), stdout=output)
        finally:
            os.close(fd)
        self.assertEqual(json.loads(output.getvalue())['reason'], 'busy')

    def test_logs_are_read_by_bounded_range(self):
        self.run_job(job())
        directory = self.launches / 'launch-1'
        self.assertEqual(launch.read_log(directory, 'stdout', 1, 10), b'2\n')
        for args in (('stdin', 0, 10), ('stdout', -1, 10), ('stdout', 0, 0), ('stdout', 0, launch.MAX_LOG_READ + 1),
                     ('../job.json', 0, 1)):
            with self.subTest(args=args), self.assertRaises(JobError):
                launch.read_log(directory, *args)

    def test_status_receipt_and_list_commands(self):
        self.run_job(job())
        host = self.host()
        for argv, check in ((['status', 'launch-1'], lambda data: data['state'] == 'stopped'),
                            (['receipt', 'launch-1'], lambda data: data['version'] == launch.RECEIPT_VERSION),
                            (['list'], lambda data: data[0]['launch_id'] == 'launch-1')):
            output = io.BytesIO()
            self.assertEqual(launch.main(argv, host_factory=lambda root: host, root=self.root, stdout=output), 0)
            self.assertTrue(check(json.loads(output.getvalue())), argv)
        with self.assertRaises(JobError):
            launch.main(['unknown'], host_factory=lambda root: host, root=self.root, stdout=io.BytesIO())


class BoundedLogTest(unittest.TestCase):
    def test_disk_errors_never_stop_counting(self):
        with tempfile.TemporaryDirectory() as directory:
            log = launch.BoundedLog(Path(directory) / 'x.log', 10)
            os.close(log.fd)
            log.fd = os.open('/dev/full', os.O_WRONLY)
            log(b'abc')
            log(b'def')
            summary = log.summary()
            self.assertEqual((summary['bytes'], summary['kept_bytes']), (6, 0))
            self.assertIn('No space', summary['write_error'])
            log.close()

    def test_refuses_an_existing_or_linked_log(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'x.log'
            path.symlink_to('/etc/passwd')
            with self.assertRaises(FileExistsError):
                launch.BoundedLog(path, 10)


class EmitterTest(unittest.TestCase):
    def test_a_stalled_supervisor_never_blocks_and_a_closed_one_is_detected(self):
        read, write = os.pipe()
        os.set_blocking(write, True)
        emitter = launch.Emitter(write, size=4)
        started = time.monotonic()
        for index in range(2000):
            emitter.emit({'event': 'log', 'data': 'x' * 4096}, droppable=True)
        self.assertLess(time.monotonic() - started, 3)
        self.assertGreater(emitter.dropped, 0)
        os.close(read)
        for index in range(20):
            emitter.emit({'event': 'heartbeat'}, droppable=True)
            if not emitter.healthy:
                break
            time.sleep(0.05)
        self.assertFalse(emitter.healthy)
        os.close(write)


class SnapshotIdentityTest(unittest.TestCase):
    def test_tree_digest_binds_content_names_and_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            share = Path(directory) / 'share'
            (share / 'sub').mkdir(parents=True)
            (share / 'a.txt').write_text('one')
            (share / 'sub' / 'b.txt').write_text('two')
            first = launch.tree_digest(share)
            self.assertEqual(first, launch.tree_digest(share))
            (share / 'a.txt').write_text('ONE')
            self.assertNotEqual(first, launch.tree_digest(share))
            (share / 'a.txt').write_text('one')
            (share / 'a.txt').chmod(0o755)
            self.assertNotEqual(first, launch.tree_digest(share))
            (share / 'a.txt').chmod(0o644)
            os.symlink('/etc/passwd', share / 'link')
            with self.assertRaises(launch.LaunchError):
                launch.tree_digest(share)


class RealHostTest(unittest.TestCase):
    """The real Host's Docker-facing steps, with Docker replaced by a recorder."""

    def host(self, responses):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        host = launch.Host.__new__(launch.Host)
        host.root = Path(directory.name)
        host.settings = {'source': 'a' * 40, 'name': 'ag-mvp-demo-target', 'domain': str(host.root / 'domain'),
                         'instance': 'demo', 'taskboard_url': 'http://10.10.10.10:8080/', 'task_id': 1}
        calls = []

        def run(args, **kwargs):
            calls.append(args)
            for prefix, done in responses:
                if args[:len(prefix)] == prefix:
                    return done
            return subprocess.CompletedProcess(args, 1, b'', b'Error: No such object')
        host.run = run
        return host, calls

    def image(self, labels, repo=()):
        item = [{'Id': 'sha256:' + 'f' * 64, 'RepoDigests': list(repo), 'Config': {'Labels': labels}}]
        return subprocess.CompletedProcess([], 0, json.dumps(item).encode(), b'')

    def test_images_are_never_pulled_and_bind_to_the_source(self):
        host, calls = self.host([(['/usr/bin/docker', 'image', 'inspect'],
                                  self.image({'org.opencontainers.image.revision': 'a' * 40},
                                             ['agentgate-coding@sha256:' + '1' * 64]))])
        self.assertEqual(host.resolve_image('sha256:' + 'f' * 64), 'sha256:' + 'f' * 64)
        self.assertEqual(host.resolve_image('agentgate-coding@sha256:' + '1' * 64), 'sha256:' + 'f' * 64)
        with self.assertRaisesRegex(launch.LaunchError, 'not this local image'):
            host.resolve_image('other@sha256:' + '2' * 64)
        self.assertFalse(any('pull' in call for call in calls))
        host, _ = self.host([(['/usr/bin/docker', 'image', 'inspect'],
                              self.image({'org.opencontainers.image.revision': 'b' * 40}))])
        with self.assertRaisesRegex(launch.LaunchError, 'source revision'):
            host.resolve_image('sha256:' + 'f' * 64)
        host, _ = self.host([])
        with self.assertRaisesRegex(launch.LaunchError, 'never pulled'):
            host.resolve_image('sha256:' + 'f' * 64)

    def test_script_failures_carry_a_bounded_message(self):
        host, calls = self.host([([], subprocess.CompletedProcess([], 3, b'', b'x' * 5000 + b'guard said no'))])
        with self.assertRaisesRegex(launch.LaunchError, 'exit 3.*guard said no'):
            host.start_guard()
        self.assertEqual(calls[0], [str(host.root / 'start-guard.sh')])
        host.root.joinpath('domain').mkdir()
        with self.assertRaises(launch.LaunchError):
            host.start_target('sha256:' + 'f' * 64, 400)
        self.assertEqual(calls[1], [str(host.root / 'restart-target.sh'), '--launch', 'sha256:' + 'f' * 64, '400'])
        with self.assertRaises(launch.LaunchError):
            host.start_target('sha256:' + 'f' * 64, 400, True)
        self.assertEqual(calls[2], [str(host.root / 'restart-target.sh'), '--launch', 'sha256:' + 'f' * 64, '400', '--taskboard-bridge'])

    def test_snapshot_mounts_require_an_installed_matching_share(self):
        host, _ = self.host([])
        value = launch_job.check_job(raw(job(**{'mounts': [{'name': 'repo', 'source': '/srv/repo', 'mode': 'snapshot'}]})),
                                     ['snapshots'])
        with self.assertRaisesRegex(launch.LaunchError, 'not installed'):
            host.stage_mounts(launch_job.mount_entries(value), value)
        (host.root / 'shares').mkdir()
        launch.write_private(host.root / 'shares' / '.repo.json', launch.dump({'source': '/srv/other'}))
        with self.assertRaisesRegex(launch.LaunchError, 'different folder'):
            host.stage_mounts(launch_job.mount_entries(value), value)
        launch.write_private(host.root / 'shares' / '.repo.json', launch.dump({'source': '/srv/repo'}))
        host.stage_mounts(launch_job.mount_entries(value), value)
        written = json.loads((host.root / 'launch-mounts.json').read_text())
        self.assertEqual(written['mounts'], [{'name': 'repo', 'kind': 'snapshot', 'read_only': True}])

    def test_capabilities_distinguish_appliance_and_docker_host(self):
        report = subprocess.CompletedProcess([], 0, b'{"ok": true, "kernel": "6.8.0-142-generic"}', b'')
        host, _ = self.host([([], report)])
        self.assertEqual(host.capabilities()['capabilities'], ['kernel-bpf-lsm', 'live-mounts', 'snapshots'])
        (host.root / 'appliance-installed').write_text('')
        caps = host.capabilities()
        self.assertEqual((caps['runtime'], caps['capabilities']), ('appliance', ['kernel-bpf-lsm', 'snapshots']))
        host, _ = self.host([([], subprocess.CompletedProcess([], 1, b'{"ok": false, "error": "refuse kernel load"}', b''))])
        caps = host.capabilities()
        self.assertNotIn('kernel-bpf-lsm', caps['capabilities'])
        self.assertEqual(caps['preflight']['error'], 'refuse kernel load')

    def test_collect_moves_only_the_command_files(self):
        host, _ = self.host([])
        for name in ('guard-receipt.json', 'config.json', 'policy.json'):
            (host.root / name).write_text('{"container_id": "c"}')
        self.assertFalse(host.collect_command_files(host.root / 'out', {'container_id': 'other'}))
        self.assertTrue(host.collect_command_files(host.root / 'out'))
        self.assertTrue((host.root / 'out' / 'guard-receipt.json').exists())
        self.assertTrue((host.root / 'policy.json').exists())


if __name__ == '__main__':
    unittest.main()


class ExpiryAndHostCommandsTest(LaunchTestCase):
    def test_the_signed_expiry_caps_the_host_deadline(self):
        value = job(grace=0)
        value['spec']['mode'], value['spec']['lifetime_seconds'] = 'session', 600
        value['policy'].update(mode='session', duration_seconds=600)
        value['lifetime_seconds'] = 600
        value['expires_at_ms'] = int(time.time() * 1000) + 700
        value['spec']['agent']['command'] = ['sleep', '30']
        started = time.monotonic()
        receipt, _, _ = self.run_job(value, self.host(deadline_s=600))
        self.assertLess(time.monotonic() - started, 6)
        self.assertEqual(receipt['state'], 'expired')

    def test_pull_takes_only_digest_references(self):
        host = self.host()
        calls = []
        host.run = lambda args, **kwargs: calls.append(args) or subprocess.CompletedProcess(args, 0, b'', b'')
        for bad in ('ubuntu:latest', 'ubuntu', 'sha256:' + 'a' * 64, '--help@sha256:' + 'a' * 64):
            with self.subTest(bad=bad), self.assertRaises(JobError):
                launch.pull_image(host, bad)
        launch.pull_image(host, 'agentgate-coding@sha256:' + 'a' * 64)
        self.assertEqual(calls, [['/usr/bin/docker', 'pull', '--quiet', 'agentgate-coding@sha256:' + 'a' * 64]])

    def test_stage_profile_validates_natively_and_changes_no_policy(self):
        host = self.host()
        good = subprocess.CompletedProcess([], 0, json.dumps({'digest': 'd' * 64, 'document': {'version': 'agentgate.poc.v2'}}).encode(), b'')
        host.run = lambda args, **kwargs: good
        result = launch.stage_profile(self.root, host, 'a' * 32, '3', raw(FULL_POLICY))
        self.assertEqual(result, {'policy_digest': 'd' * 64, 'version': 'agentgate.poc.v2', 'launchable': True})
        self.assertTrue((self.root / 'profiles' / ('a' * 32 + '-3.json')).exists())
        self.assertFalse((self.root / 'policy.json').exists())
        host.run = lambda args, **kwargs: subprocess.CompletedProcess([], 1, b'', b'duplicate JSON key')
        with self.assertRaisesRegex(JobError, 'duplicate JSON key'):
            launch.stage_profile(self.root, host, 'b' * 32, '1', b'{}')
        for profile_id, version in (('../x', '1'), ('a' * 32, 'x'), ('a' * 32, '0')):
            with self.assertRaises(JobError):
                launch.stage_profile(self.root, host, profile_id, version, b'{}')
