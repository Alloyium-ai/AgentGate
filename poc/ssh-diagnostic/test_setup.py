# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Tests for the public diagnostic input boundary."""
from pathlib import Path
import unittest

from settings import validate_settings


class SettingsTest(unittest.TestCase):
    def fixture(self):
        return dict(instance='demo', source='a' * 40, policy_format='agentgate.network-poc.v1',
                    target_image='sha256:' + 'c' * 64, bridge_image='sha256:' + 'd' * 64,
                    taskboard_url='http://10.10.10.10:8080/', task_id=1,
                    ipv6_subnet='fd42:1234:5678::/64')

    def check(self, data):
        return validate_settings(data, Path('/var/lib/agentgate-poc-demo'))

    def test_values_derive_separate_owned_resources(self):
        result = self.check(self.fixture())
        self.assertEqual(result['name'], 'ag-mvp-demo-target')
        self.assertNotEqual(result['network'], result['bridge_network'])
        self.assertEqual(result['domain'], '/sys/fs/cgroup/ag-mvp-demo-domain')
        self.assertEqual(result['artifact'], '/run/agentgate/poc-demo/streams')

    def test_rejects_unknown_settings_and_path_changes(self):
        data = self.fixture()
        data['command'] = 'echo forbidden'
        with self.assertRaises(ValueError):
            self.check(data)
        with self.assertRaises(ValueError):
            validate_settings(self.fixture(), Path('/var/lib/other'))

    def test_rejects_mutable_images_and_invalid_revision(self):
        for key, value in [('source', 'main'), ('target_image', 'target:latest'),
                           ('bridge_image', 'bridge:latest'), ('policy_format', 'unknown')]:
            data = self.fixture()
            data[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(data)

    def test_rejects_private_public_address_and_shell_hostname(self):
        for key, value in [('instance', '../escape'), ('policy_format', 'kernel-policy.v2')]:
            data = self.fixture()
            data[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(data)

    def test_rejects_broad_upstream_and_invalid_task(self):
        for value in ('http://example.org:8080/', 'http://127.0.0.1:8080/',
                      'http://10.10.10.10:8080/api/', 'http://user@10.10.10.10:8080/'):
            data = self.fixture()
            data['taskboard_url'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.check(data)
        data = self.fixture()
        data['task_id'] = True
        with self.assertRaises(ValueError):
            self.check(data)


class ShellAssignmentTest(unittest.TestCase):
    def test_eval_restores_exact_values_and_runs_nothing(self):
        import subprocess
        import tempfile
        from settings import shell_assignments
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'ran'
            hostile = "x'; touch %s; echo '$(touch %s)`touch %s`\nnext" % (marker, marker, marker)
            text = shell_assignments({'value': hostile, 'digest': 'a' * 64, 'flag': '1'})
            done = subprocess.run(['/bin/sh', '-c', 'eval "$1"; printf %s "$value"', 'sh', text],
                                  capture_output=True, timeout=10)
            self.assertEqual(done.stdout.decode(), hostile)
            self.assertFalse(marker.exists())
        for key in ('Bad', 'a-b', 'x;y', '', '1a'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                shell_assignments({key: 'v'})


if __name__ == '__main__':
    unittest.main()
