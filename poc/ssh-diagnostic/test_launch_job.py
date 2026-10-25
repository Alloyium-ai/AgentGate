# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Adversarial input tests for the launcher job validation."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import launch_job  # noqa: E402
from launch_job import JobError, check_job  # noqa: E402
from test_launch import BROKER_ADDRESS, broker_job, job, raw  # noqa: E402

CAPS = ['snapshots', 'live-mounts']


class LifetimeTest(unittest.TestCase):
    def test_boundaries_match_the_contract(self):
        for mode, seconds, ok in (('oneshot', 0, False), ('oneshot', 1, True), ('oneshot', 3600, True),
                                  ('oneshot', 3601, False), ('session', 59, False), ('session', 60, True),
                                  ('session', 86400, True), ('session', 86401, False), ('oneshot', True, False),
                                  ('oneshot', 30.0, False), ('oneshot', '30', False), ('daemon', 60, False)):
            value = job(mode=mode, lifetime_seconds=seconds)
            with self.subTest(mode=mode, seconds=seconds):
                if ok:
                    self.assertEqual(check_job(raw(value), CAPS)['lifetime_seconds'], seconds)
                else:
                    with self.assertRaises(JobError):
                        check_job(raw(value), CAPS)

    def test_effective_lifetime_never_exceeds_the_spec_or_the_mode_bounds(self):
        value = job(mode='session', lifetime_seconds=3600, lifetime=1800)
        self.assertEqual(check_job(raw(value), CAPS)['lifetime_seconds'], 1800)
        for lifetime in (3601, 59, 0):
            with self.subTest(lifetime=lifetime), self.assertRaises(JobError):
                check_job(raw(job(mode='session', lifetime_seconds=3600, lifetime=lifetime)), CAPS)
        value = job(mode='session', lifetime_seconds=3600, lifetime=1800)
        value['policy']['duration_seconds'] = 3600
        with self.assertRaises(JobError):
            check_job(raw(value), CAPS)

    def test_the_canonical_spec_may_carry_empty_optional_fields(self):
        value = job(target='', approval='', secrets=None)
        value['spec']['agent'].update(env={}, workdir='')
        value['spec']['mounts'] = None
        launch = check_job(raw(value), CAPS)
        self.assertEqual((launch['workdir'], launch['env']), ('/var/lib/agentgate/workspace', {}))

    def test_policy_must_carry_the_same_mode_and_lifetime(self):
        for change in ({'mode': 'session'}, {'duration_seconds': 25}, {'version': 'agentgate.network-poc.v1'}):
            value = job()
            value['policy'].update(change)
            with self.subTest(change=change), self.assertRaises(JobError):
                check_job(raw(value), CAPS)
        value = job()
        del value['policy']['filesystem']
        with self.assertRaises(JobError):
            check_job(raw(value), CAPS)


class InputTest(unittest.TestCase):
    def refuse(self, value, message=None):
        with self.assertRaises(JobError) as caught:
            check_job(value if isinstance(value, bytes) else raw(value), CAPS)
        if message:
            self.assertIn(message, str(caught.exception))

    def test_structure_is_exact(self):
        value = job()
        value['extra'] = 1
        self.refuse(value)
        value = job()
        del value['stop_grace_seconds']
        self.refuse(value)
        value = job()
        value['spec']['unknown'] = 1
        self.refuse(value)
        self.refuse(b'{"version": "agentgate.launcher-job.v1", "version": "x"}', 'duplicate')
        self.refuse(b'{"a": NaN}', 'non-JSON')
        self.refuse(b'[1]')
        self.refuse(b'x' * (launch_job.MAX_JOB_BYTES + 1), 'exceeds')
        self.refuse(b'\xff\xfe')

    def test_ids_and_digests(self):
        for key, bad in (('launch_id', '../x'), ('launch_id', 'a/b'), ('launch_id', ''), ('launch_id', 'x' * 65),
                         ('launch_id', '-x'), ('job_id', 'a b'), ('spec_digest', 'A' * 64), ('policy_digest', 'a' * 63),
                         ('profile_policy_digest', 1)):
            value = job()
            value[key] = bad
            with self.subTest(key=key, bad=bad):
                self.refuse(value)

    def test_host_knobs_are_bounded(self):
        for key, bad in (('stop_grace_seconds', 31), ('stop_grace_seconds', -1), ('log_limit_bytes', 10),
                         ('log_limit_bytes', 1 << 40), ('upload_limit_bytes', -1), ('upload_limit_bytes', 1 << 30)):
            value = job()
            value[key] = bad
            with self.subTest(key=key):
                self.refuse(value)

    def test_names_images_and_commands(self):
        for change in ({'name': 'Repo'}, {'name': '-x'}, {'name': 'a' * 41}, {'version': 'agentgate.launch.v2'}):
            value = job()
            value['spec'].update(change)
            with self.subTest(change=change):
                self.refuse(value)
        for image in ('agentgate-coding:latest', 'sha256:' + 'A' * 64, 'agentgate@sha256:' + 'a' * 63,
                      'sha256:' + 'a' * 64 + '\n', '--privileged', ''):
            value = job()
            value['spec']['agent']['image'] = image
            with self.subTest(image=image):
                self.refuse(value, 'immutable digest')
        for command in ([], ['-rf'], ['../bin/sh'], ['bin/sh'], ['/usr/bin/'], ['a\x00b'], [''], ['x'] * 65,
                        ['python3', 'x' * 4097], ['python3', 1], 'python3', ['py thon']):
            value = job()
            value['spec']['agent']['command'] = command
            with self.subTest(command=command):
                self.refuse(value)
        value = job()
        value['spec']['agent']['command'] = ['python3'] + ['y' * 4000] * 5
        self.refuse(value, 'exceed')

    def test_secret_and_reserved_environment_names(self):
        for name in ('API_KEY', 'GITHUB_TOKEN', 'AWS_SECRET', 'DB_PASSWORD', 'my_password_file', 'SSH_PRIVATE_KEY',
                     'KEY', 'token', 'PATH', 'LD_PRELOAD', 'ld_library_path', 'AGENTGATE_X', 'BASH_ENV', 'IFS',
                     '1ABC', 'A-B', 'A B', '', 'X' * 65, 'GCP_CREDENTIALS'):
            value = job()
            value['spec']['agent']['env'] = {name: 'v'}
            with self.subTest(name=name):
                self.refuse(value)
        value = job()
        value['spec']['agent']['env'] = {'EDITOR': 'a\x00b'}
        self.refuse(value)
        value['spec']['agent']['env'] = {'N%d' % index: 'v' for index in range(65)}
        self.refuse(value)
        value['spec']['agent']['env'] = {'KEYBOARD_LAYOUT': 'us', 'HOME': '/var/lib/agentgate/workspace'}
        self.assertEqual(check_job(raw(value), CAPS)['env']['KEYBOARD_LAYOUT'], 'us')

    def test_secrets_fail_closed_without_a_broker(self):
        value = job()
        value['spec']['secrets'] = [{'ref': 'anthropic', 'expose': {'env': 'ANTHROPIC_BASE_URL'}}]
        self.refuse(value, 'broker block')
        value['spec']['secrets'] = 'anthropic'
        self.refuse(value)

    def test_a_broker_block_gives_the_agent_only_base_urls(self):
        launch = check_job(raw(broker_job()), CAPS)
        self.assertEqual(launch['env']['ANTHROPIC_BASE_URL'], 'http://172.30.7.2:8443/anthropic')
        self.assertEqual(launch['env']['EDITOR'], 'vi')
        self.assertEqual(launch['broker']['network'], 'agentgate-launch-1-broker')
        self.assertNotIn('secret_refs', launch)
        script = launch_job.shell_command(launch)
        self.assertIn("export ANTHROPIC_BASE_URL=http://172.30.7.2:8443/anthropic", script)

    def test_broker_blocks_that_do_not_match_the_policy_or_spec_are_refused(self):
        def mutate(change):
            value = broker_job()
            change(value)
            return value
        cases = {
            'network': lambda v: v['broker'].update(network='agentgate-other-broker'),
            'subnet size': lambda v: v['broker'].update(subnet='172.30.7.0/28'),
            'subnet host bits': lambda v: v['broker'].update(subnet='172.30.7.1/29'),
            'public subnet': lambda v: v['broker'].update(subnet='8.8.8.0/29', address='8.8.8.2', target_address='8.8.8.3'),
            'broker not .2': lambda v: v['broker'].update(address='172.30.7.4'),
            'target not .3': lambda v: v['broker'].update(target_address='172.30.7.5'),
            'port': lambda v: v['broker'].update(port=80),
            'policy address': lambda v: v['policy']['broker'].update(address='172.30.7.10'),
            'policy port': lambda v: v['policy']['broker'].update(port=8444),
            'policy taskboard too': lambda v: v['policy'].update(taskboard={'address': '10.0.0.2', 'protocol': 'tcp', 'port': 8080, 'task_id': 1}),
            'url host': lambda v: v['broker']['env'].update(ANTHROPIC_BASE_URL='http://evil.example:8443/anthropic'),
            'url route': lambda v: v['broker']['env'].update(ANTHROPIC_BASE_URL='http://172.30.7.2:8443/other'),
            'url carries a value': lambda v: v['broker']['env'].update(ANTHROPIC_BASE_URL='sk-ant-FAKE'),
            'extra env': lambda v: v['broker']['env'].update(OTHER_URL='http://172.30.7.2:8443/anthropic'),
            'missing env': lambda v: v['broker'].update(env={}),
            'reserved env': lambda v: (v['spec']['secrets'][0]['expose'].update(env='LD_PRELOAD'),
                                       v['broker'].update(env={'LD_PRELOAD': 'http://172.30.7.2:8443/anthropic'})),
            'env clash': lambda v: v['spec']['agent']['env'].update(ANTHROPIC_BASE_URL='x'),
            'extra key': lambda v: v['broker'].update(secret_file='/run/agentgate/secrets/anthropic'),
            'secret value': lambda v: v['spec']['secrets'][0].update(value='sk-ant-FAKE'),
            'no secrets': lambda v: v['spec'].update(secrets=[]),
            'duplicate ref': lambda v: v['spec']['secrets'].append({'ref': 'anthropic', 'expose': {'env': 'OTHER_URL'}}),
        }
        for name, change in cases.items():
            with self.subTest(case=name):
                self.refuse(mutate(change))
        value = job()
        value['policy'].pop('taskboard')
        value['policy']['broker'] = {'address': BROKER_ADDRESS, 'protocol': 'tcp', 'port': 8443}
        self.refuse(value, 'no broker')

    def test_the_taskboard_bridge_is_mounted_only_when_the_launch_asks(self):
        # The policy keeps the taskboard endpoint and grants reading the bridge path.
        self.assertIs(check_job(raw(job()), CAPS)['taskboard_bridge'], True)
        # A broker launch has no taskboard: never the bridge, even if the path is readable.
        broker = broker_job()
        self.assertIn('/run/agentgate/taskboard', broker['policy']['filesystem']['read_only'])
        self.assertIs(check_job(raw(broker), CAPS)['taskboard_bridge'], False)
        # A policy that does not grant reading the bridge path does not get it.
        value = job()
        value['policy']['filesystem']['read_only'] = ['/etc', '/proc']
        self.assertIs(check_job(raw(value), CAPS)['taskboard_bridge'], False)
        # Nor does a policy without the taskboard endpoint.
        value = job()
        del value['policy']['taskboard']
        self.assertIs(check_job(raw(value), CAPS)['taskboard_bridge'], False)
        value = job()
        value['policy']['filesystem']['read_only'] = '/run/agentgate/taskboard'
        self.refuse(value, 'read_only')

    def test_mounts_need_the_matching_capability(self):
        live = {'name': 'repo', 'source': '/srv/repos/app', 'mode': 'read-only'}
        value = job(mounts=[live])
        self.assertEqual(check_job(raw(value), CAPS)['mounts'][0]['mode'], 'read-only')
        with self.assertRaisesRegex(JobError, 'live-mounts'):
            check_job(raw(value), ['snapshots'])
        value = job(mounts=[dict(live, mode='snapshot')])
        self.assertEqual(check_job(raw(value), ['snapshots'])['mounts'][0]['mode'], 'snapshot')
        for mounts in ([dict(live, mode='rw')], [dict(live, name='../x')], [live, live], [dict(live, extra=1)],
                       [live] * 9, 'repo', [dict(live, source='')]):
            with self.subTest(mounts=mounts):
                self.refuse(job(mounts=mounts))

    def test_resolved_mounts_must_be_exactly_the_requested_mounts(self):
        repo = {'name': 'repo', 'source': '/srv/repos/app', 'mode': 'read-only'}
        docs = {'name': 'docs', 'source': '/srv/docs', 'mode': 'snapshot'}

        def pair(requested, resolved):
            value = job(mounts=resolved)
            value['spec']['mounts'] = requested
            return value
        # The job mounts exactly what the spec (and so the approval) names: count, and in order name, mode and source.
        accepted = check_job(raw(pair([repo, docs], [repo, docs])), CAPS)
        self.assertEqual([m['source'] for m in accepted['mounts']], ['/srv/repos/app', '/srv/docs'])
        self.assertEqual(check_job(raw(pair(None, [])), CAPS)['mounts'], [])
        for requested, resolved in (([repo], [dict(repo, source='/srv/resolved/app')]), ([repo], [dict(repo, source='/srv/repos/app/sub')]),
                                    ([], [repo]), ([repo], []), ([repo], [dict(repo, mode='read-write')]),
                                    ([repo], [dict(repo, name='other')]), ([repo, docs], [docs, repo]),
                                    ([repo, docs], [repo]), ([dict(repo, extra=1)], [repo]), ('repo', [repo]),
                                    ([repo] * 9, [repo])):
            with self.subTest(requested=requested, resolved=resolved):
                self.refuse(pair(requested, resolved))

    def test_workdir_stays_in_the_workspace_or_a_mount(self):
        for workdir, ok in (('/var/lib/agentgate/workspace', True), ('/var/lib/agentgate/workspace/src', True),
                            ('/var/lib/agentgate/mounts/repo', True), ('/var/lib/agentgate/mounts/other', False),
                            ('/var/lib/agentgate/workspace/../../etc', False), ('/etc', False), ('relative', False),
                            ('/var/lib/agentgate/workspace/', False), ('/var/lib/agentgate/workspace//x', False),
                            ('/var/lib/agentgate/workspace/a b', False), ('/var/lib/agentgate/workspaces', False)):
            value = job(mounts=[{'name': 'repo', 'source': '/srv/repo', 'mode': 'read-only'}])
            value['spec']['agent']['workdir'] = workdir
            with self.subTest(workdir=workdir):
                if ok:
                    self.assertEqual(check_job(raw(value), CAPS)['workdir'], workdir)
                else:
                    self.refuse(value)


class ShellCommandTest(unittest.TestCase):
    def test_the_command_string_executes_exactly_the_argument_vector(self):
        hostile = ["printf", "%s|", "a'b", '"c"', '$(id)', '`id`', '; exit 3', '\n', '--', '*']
        launch = check_job(raw(job(**{'agent': {'image': 'sha256:' + 'a' * 64, 'command': hostile,
                                                 'env': {'X': "'; exit 4; '"}}})), CAPS)
        script = launch_job.shell_command(launch).replace('cd -- ', 'true -- ')
        done = subprocess.run(['/bin/sh', '-c', '--', script], capture_output=True, timeout=10, cwd='/')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.decode(), ''.join(item + '|' for item in hostile[2:]))

    def test_mount_entries_map_modes(self):
        launch = check_job(raw(job(mounts=[{'name': 'a', 'source': '/srv/a', 'mode': 'read-only'},
                                           {'name': 'b', 'source': '/srv/b', 'mode': 'read-write'},
                                           {'name': 'c', 'source': '/srv/c', 'mode': 'snapshot'}])), CAPS)
        self.assertEqual(launch_job.mount_entries(launch), [
            {'name': 'a', 'kind': 'bind', 'source': '/srv/a', 'read_only': True},
            {'name': 'b', 'kind': 'bind', 'source': '/srv/b', 'read_only': False},
            {'name': 'c', 'kind': 'snapshot', 'read_only': True}])


if __name__ == '__main__':
    unittest.main()
