# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""The appliance proxy for the launch runtime, with SSH and Docker replaced by recorders."""
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import appliance as cli


class GuestLaunchTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name) / 'state'
        self.state.mkdir(mode=0o700)
        binding = {'name': 'ag-poc-x', 'owner': 'x', 'port': 22365, 'images': {'appliance': 'sha256:' + 'a' * 64}}
        self.patches = [patch.object(cli, 'load', return_value=binding),
                        patch.object(cli, 'inspect_owned', return_value={'State': {'Running': True}})]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.calls = []

    def runner(self, args, **kwargs):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, 7, b'', b'')

    def test_commands_pass_through_quoted_with_keepalives(self):
        code = cli.guest_launch(['--state', str(self.state), '--', 'stop', 'a; rm -rf /', '--grace', '5'],
                                runner=self.runner, stdin=b'', stdout=None)
        self.assertEqual(code, 7)
        remote = self.calls[0][-1]
        self.assertEqual(shlex.split(remote), ['python3', '-I', cli.GUEST + '/launch.py', 'stop', 'a; rm -rf /', '--grace', '5'])
        self.assertIn('ServerAliveInterval=15', self.calls[0])
        self.assertIn('StrictHostKeyChecking=yes', self.calls[0])

    def test_unknown_commands_and_bad_arguments_are_refused(self):
        for argv in (['--state', str(self.state), '--', 'install-snapshot', 'a', 'b', 'c'],
                     ['--state', str(self.state), '--', 'rm'], ['--state', str(self.state), 'run'],
                     ['--state', str(self.state), '--', 'stop', 'x\nid']):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                cli.guest_launch(argv, runner=self.runner)
        self.assertEqual(self.calls, [])

    def test_a_stopped_appliance_is_reported(self):
        with patch.object(cli, 'inspect_owned', return_value=None), self.assertRaisesRegex(RuntimeError, 'not running'):
            cli.guest_launch(['--state', str(self.state), '--', 'capabilities'], runner=self.runner)

    def test_snapshot_is_built_here_and_installed_in_the_guest(self):
        folder = Path(tempfile.mkdtemp(dir='/srv' if Path('/srv').is_dir() else None))
        self.addCleanup(lambda: __import__('shutil').rmtree(folder, ignore_errors=True))
        (folder / 'a.txt').write_text('a')
        copies = []
        with patch.object(cli, 'copy_guest', lambda state, binding, source, destination: copies.append(
                (Path(source).stat().st_size, destination))), patch('pathlib.Path.home', return_value=Path('/nonexistent-home')):
            cli.guest_launch(['--state', str(self.state), '--', 'snapshot', 'repo', str(folder), '--max-bytes', '1000'],
                             runner=self.runner)
        self.assertEqual(copies[0][1], cli.GUEST + '/.share-repo.tar')
        self.assertIn('install-snapshot', self.calls[0][-1])
        with self.assertRaises(ValueError):
            cli.guest_launch(['--state', str(self.state), '--', 'snapshot', 'repo', '/etc'], runner=self.runner)


if __name__ == '__main__':
    unittest.main()
