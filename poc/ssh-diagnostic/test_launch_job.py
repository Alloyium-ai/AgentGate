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
from test_launch import job, raw  # noqa: E402

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
        self.refuse(value, 'credential broker')
        value['spec']['secrets'] = 'anthropic'
        self.refuse(value)

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
