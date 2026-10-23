# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""The grant command: validated, locked, atomic, recorded, and recoverable edits.

These tests build the real native validator with "go build" and need no root,
Docker, or VM. Without Go they skip with a clear message.
"""
import contextlib
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

import grants
import mounts

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parent.parent
V1_EXAMPLE = HERE / 'policy.example.json'
V2_EXAMPLE = HERE / 'policy.full.example.json'
VALIDATOR = None
BUILD = None


def setUpModule():
    global VALIDATOR, BUILD
    go = shutil.which('go')
    if not go:
        raise unittest.SkipTest('the grant tests need Go to build the native policy validator '
                                '(go build ./cmd/pilot-network-diagnostic); go is not on PATH')
    BUILD = tempfile.TemporaryDirectory()
    os.chmod(BUILD.name, 0o700)
    VALIDATOR = str(Path(BUILD.name) / 'pilot-network-diagnostic')
    subprocess.run([go, 'build', '-o', VALIDATOR, './cmd/pilot-network-diagnostic'], cwd=REPOSITORY,
                   check=True, timeout=600, env=dict(os.environ, CGO_ENABLED='0'))


def tearDownModule():
    if BUILD is not None:
        BUILD.cleanup()


def network_fields(document):
    return {key: document[key] for key in ('default', 'ipv6', 'dns', 'web', 'taskboard', 'duration_seconds')}


class GrantTestCase(unittest.TestCase):
    example = V2_EXAMPLE

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = Path(os.path.realpath(directory.name))
        self.dir.chmod(0o700)
        self.policy = self.dir / 'policy.json'
        shutil.copyfile(self.example, self.policy)
        self.policy.chmod(0o600)
        self.history = self.dir / 'policy.json.grants'

    def grant(self, *argv, policy=None, extra=()):
        out, err = io.StringIO(), io.StringIO()
        lines = []
        with contextlib.redirect_stderr(err), patch('sys.stdin', io.StringIO('')):
            code = grants.main(['--validator', VALIDATOR, '--policy', str(policy or self.policy)] + list(extra) +
                               list(argv), out=lines.append)
        return code, '\n'.join(lines), err.getvalue()

    def ok(self, *argv, **kwargs):
        code, out, err = self.grant(*argv, **kwargs)
        self.assertEqual(code, grants.OK, (argv, out, err))
        return out

    def document(self):
        return json.loads(self.policy.read_bytes())

    def validated(self, raw=None):
        result = subprocess.run([VALIDATOR, 'network-info', '/dev/stdin'], input=raw or self.policy.read_bytes(),
                                capture_output=True, check=True)
        return json.loads(result.stdout)

    def log(self):
        path = self.history / 'log.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


class FormatTest(unittest.TestCase):
    def test_examples_round_trip_byte_for_byte(self):
        for path in (V1_EXAMPLE, V2_EXAMPLE):
            raw = path.read_bytes()
            self.assertEqual(grants.render(grants.parse_policy(raw)), raw, path)

    def test_strict_parsing_fails_closed(self):
        for raw in (b'{"version": 1, "version": 2}', b'{"a": NaN}', b'[]', b'{', b'\xff',
                    b'{"pad": "' + b'x' * 16400 + b'"}'):
            with self.subTest(raw=raw[:30]), self.assertRaises(grants.GrantError) as caught:
                grants.parse_policy(raw)
            self.assertEqual(caught.exception.code, grants.REJECTED)

    def test_every_exit_code_is_documented(self):
        self.assertEqual(sorted(grants.EXIT_CODES), list(range(13)))
        readme = (HERE / 'README.md').read_text()
        for code in grants.EXIT_CODES:
            self.assertRegex(readme, r'\n\| %d \|' % code, 'README lacks exit code %d' % code)


class ShowTest(GrantTestCase):
    def test_show_reports_the_validated_digest_and_sections(self):
        out = self.ok('show')
        self.assertIn('digest: ' + self.validated()['digest'], out)
        self.assertIn('workspace (read/write, never executable): /var/lib/agentgate/workspace', out)
        self.assertIn('domains: not enforced', out)
        data = json.loads(self.ok('show', '--json'))
        self.assertEqual(data['digest'], self.validated()['digest'])
        self.assertEqual(data['host_folders'], [])

    def test_show_on_version_one_says_files_are_not_controlled(self):
        shutil.copyfile(V1_EXAMPLE, self.policy)
        out = self.ok('show')
        self.assertIn('filesystem: not controlled by a version one policy', out)


class RoundTripTest(GrantTestCase):
    def test_each_grant_and_its_revoke_restore_the_policy(self):
        original = self.document()
        pairs = [
            (['read', '/srv/data'], ['revoke', 'read', '/srv/data']),
            (['write', '/var/cache/agent'], ['revoke', 'write', '/var/cache/agent']),
            (['exec', '/opt/tools'], ['revoke', 'exec', '/opt/tools']),
            (['deny', '/etc/ssl/private'], ['revoke', 'deny', '/etc/ssl/private']),
            (['signal', 'quit'], ['revoke', 'signal', 'SIGQUIT']),
            (['anon-exec'], ['revoke', 'anon-exec']),
            (['deny-web', 'quic'], ['allow-web', 'quic']),
            (['dns', '1.1.1.1', '8.8.8.8'], ['revoke', 'dns', '8.8.8.8']),
        ]
        for grant, revoke in pairs:
            with self.subTest(grant=grant):
                self.ok(*grant)
                self.assertNotEqual(self.document(), original)
                self.validated()
                self.ok(*revoke)
                self.assertEqual(self.document(), original)
        self.assertEqual(len(self.log()), 2 * len(pairs))

    def test_grants_land_in_the_expected_lists(self):
        self.ok('read', '/srv/data/')
        self.ok('write', '/var/cache/agent')
        self.ok('exec', '/opt/tools')
        self.ok('deny', '/srv/data/secret')
        self.ok('signal', 'winch')
        self.ok('deny-web', 'all')
        fs = self.document()['filesystem']
        self.assertIn('/srv/data', fs['read_only'])
        self.assertIn('/var/cache/agent', fs['scratch'])
        self.assertIn('/opt/tools', fs['execute'])
        self.assertIn('/srv/data/secret', fs['deny'])
        self.assertIn('SIGWINCH', self.document()['process']['signals'])
        self.assertEqual(self.document()['web']['rules'], [])
        self.ok('allow-web', 'https')
        self.assertEqual(self.document()['web']['rules'], [{'protocol': 'tcp', 'port': 443}])

    def test_idempotent_grants_change_nothing(self):
        self.ok('read', '/srv/data')
        before = os.stat(self.policy)
        raw = self.policy.read_bytes()
        for argv in (['read', '/srv/data'], ['read', '/srv/data/sub'], ['read', '/usr/lib'], ['write', '/tmp/x'],
                     ['exec', '/usr/bin'], ['deny', '/etc/shadow'], ['signal', 'SIGTERM'], ['allow-web'],
                     ['revoke', 'read', '/never/granted'], ['preset', 'full-example']):
            if argv[0] == 'preset':
                self.ok('revoke', 'read', '/srv/data')
                raw, before = self.policy.read_bytes(), os.stat(self.policy)
            with self.subTest(argv=argv):
                out = self.ok(*argv)
                self.assertIn('unchanged=true', out)
                self.assertEqual(self.policy.read_bytes(), raw)
                self.assertEqual(os.stat(self.policy).st_ino, before.st_ino)

    def test_conflicts_name_the_entry(self):
        cases = {('write', '/usr/local'): '/usr', ('exec', '/tmp/bin'): '/tmp',
                 ('exec', '/var/lib/agentgate'): '/var/lib/agentgate/workspace',
                 ('read', '/etc/shadow'): '/etc/shadow', ('revoke', 'read', '/usr/bin'): '/usr',
                 ('revoke', 'write', '/var/lib/agentgate/workspace'): 'workspace is required'}
        raw = self.policy.read_bytes()
        for argv, named in cases.items():
            with self.subTest(argv=argv):
                code, _, err = self.grant(*argv)
                self.assertEqual(code, grants.CONFLICT, err)
                self.assertIn(named, err)
                self.assertEqual(self.policy.read_bytes(), raw)

    def test_bad_arguments_are_usage_errors(self):
        for argv in (['read', 'relative/path'], ['read', '/srv/../etc'], ['read', '/'], ['allow-web', 'gopher'],
                     ['preset', 'nonexistent'], ['rollback', '0'], ['nonexistent-command'], ['revoke', 'read']):
            with self.subTest(argv=argv):
                self.assertEqual(self.grant(*argv)[0], grants.USAGE)


class ValidatorTest(GrantTestCase):
    def test_rejections_are_verbatim_and_never_written(self):
        raw = self.policy.read_bytes()
        for argv, message in [(['write', '/proc/self'], '/proc/self may not be writable: it overlaps protected tree /proc'),
                              (['dns', '10.0.0.1'], 'DNS resolver must be a unique public IPv4 address'),
                              (['dns', '1.1.1.1', '8.8.8.8', '9.9.9.9', '8.8.4.4'], 'DNS requires 1..3 public IPv4'),
                              (['signal', 'SIGSEGV'], 'process.signals supports only unique names')]:
            with self.subTest(argv=argv):
                code, _, err = self.grant(*argv)
                self.assertEqual(code, grants.REJECTED, err)
                self.assertIn('pilot-network-diagnostic network-info:\n' + message, err)
                self.assertEqual(self.policy.read_bytes(), raw)
        self.assertEqual(self.log(), [])

    def test_missing_or_untrusted_validator(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err), patch.dict(os.environ, {'AGENTGATE_VALIDATOR': ''}):
            code = grants.main(['--policy', str(self.policy), 'read', '/srv'], out=out.write)
        self.assertEqual(code, grants.NO_VALIDATOR)
        self.assertIn('go build', err.getvalue())
        loose = self.dir / 'validator'
        shutil.copyfile(VALIDATOR, loose)
        loose.chmod(0o777)
        self.assertEqual(self.grant('show', extra=['--validator', str(loose)])[0], grants.UNSAFE)

    def test_only_the_validators_own_refusal_counts_as_rejected(self):
        # Exit 1 is a rejection; Docker's 125-127, a crash, or a signal mean "not judged".
        for status, expected in ((1, grants.REJECTED), (2, grants.NO_VALIDATOR), (125, grants.NO_VALIDATOR),
                                 (127, grants.NO_VALIDATOR)):
            fake = self.dir / ('validator-%d' % status)
            fake.write_text('#!/bin/sh\necho "validator says %d" >&2\nexit %d\n' % (status, status))
            fake.chmod(0o700)
            with self.subTest(status=status):
                code, _, err = self.grant('read', '/srv', extra=['--validator', str(fake)])
                self.assertEqual(code, expected, err)
                self.assertIn('validator says %d' % status, err)
        self.assertEqual(self.policy.read_bytes(), V2_EXAMPLE.read_bytes())

    def test_invalid_current_policy_refuses_edits_but_not_rollback(self):
        self.ok('read', '/srv/data')
        document = self.document()
        document['duration_seconds'] = 31
        self.policy.write_text(json.dumps(document))
        code, _, err = self.grant('read', '/srv/other')
        self.assertEqual(code, grants.REJECTED)
        self.assertIn('current policy is invalid', err)
        self.ok('rollback')
        self.assertEqual(self.policy.read_bytes(), V2_EXAMPLE.read_bytes())


class DryRunTest(GrantTestCase):
    def test_dry_run_prints_a_diff_and_writes_nothing(self):
        raw = self.policy.read_bytes()
        out = self.ok('--dry-run', 'read', '/srv/data')
        self.assertIn('--- a/policy.json', out)
        self.assertIn('+      "/srv/data"', out)
        self.assertIn('dry_run=true valid=true', out)
        self.assertEqual(self.policy.read_bytes(), raw)
        self.assertFalse(self.history.exists())
        self.assertEqual(sorted(path.name for path in self.dir.iterdir()), ['policy.json'])

    def test_invalid_dry_run_reports_the_rejection(self):
        code, _, err = self.grant('write', '/proc/x', '--dry-run')
        self.assertEqual(code, grants.REJECTED)
        self.assertIn('overlaps protected tree /proc', err)


class CustodyTest(GrantTestCase):
    def test_unsafe_files_and_directories_are_refused(self):
        link = self.dir / 'link.json'
        link.symlink_to(self.policy)
        self.assertEqual(self.grant('show', policy=link)[0], grants.UNSAFE)
        linked_dir = self.dir / 'via'
        linked_dir.symlink_to(self.dir)
        self.assertEqual(self.grant('show', policy=linked_dir / 'policy.json')[0], grants.UNSAFE)
        self.policy.chmod(0o644)
        code, _, err = self.grant('read', '/srv')
        self.assertEqual(code, grants.UNSAFE)
        self.assertIn('chmod 600', err)
        self.policy.chmod(0o600)
        self.dir.chmod(0o777)
        self.assertEqual(self.grant('read', '/srv')[0], grants.UNSAFE)
        self.dir.chmod(0o700)
        self.history.mkdir(mode=0o755)
        self.history.chmod(0o755)
        self.assertEqual(self.grant('read', '/srv')[0], grants.UNSAFE)
        self.history.rmdir()
        elsewhere = self.dir / 'elsewhere'
        elsewhere.mkdir(mode=0o700)
        self.history.symlink_to(elsewhere)
        self.assertEqual(self.grant('read', '/srv')[0], grants.UNSAFE)
        self.assertEqual(list(elsewhere.iterdir()), [])
        self.history.unlink()
        self.ok('read', '/srv')
        self.assertEqual(stat.S_IMODE(self.history.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.policy.stat().st_mode), 0o600)

    def test_read_only_policy_keeps_its_mode(self):
        self.policy.chmod(0o400)
        self.ok('read', '/srv')
        self.assertEqual(stat.S_IMODE(self.policy.stat().st_mode), 0o400)


class UpgradeTest(GrantTestCase):
    example = V1_EXAMPLE

    def test_version_one_needs_an_explicit_upgrade(self):
        raw = self.policy.read_bytes()
        for argv in (['read', '/srv'], ['preset', 'python-dev'], ['signal', 'SIGQUIT'], ['anon-exec']):
            code, _, err = self.grant(*argv)
            self.assertEqual(code, grants.UPGRADE, argv)
            self.assertIn('--upgrade-to-v2', err)
            self.assertEqual(self.policy.read_bytes(), raw)
        # Network grants keep version one exactly as before.
        self.ok('deny-web', 'quic')
        self.assertEqual(self.document()['version'], grants.V1)
        self.assertNotIn('filesystem', self.document())

    def test_upgrade_preserves_the_network_section(self):
        before = self.validated()['document']
        self.ok('read', '/srv/data', '--upgrade-to-v2')
        after = self.validated()['document']
        self.assertEqual(after['version'], grants.V2)
        self.assertEqual(network_fields(after), network_fields(before))
        example = json.loads(V2_EXAMPLE.read_bytes())
        expected = dict(example['filesystem'], read_only=example['filesystem']['read_only'] + ['/srv/data'])
        self.assertEqual(self.document()['filesystem'], expected)
        self.assertEqual(self.document()['process'], example['process'])
        self.assertEqual(list(self.document())[-1], 'duration_seconds')

    def test_version_one_revokes_of_file_rights_are_no_ops(self):
        out = self.ok('revoke', 'read', '/srv')
        self.assertIn('unchanged=true', out)


class PresetTest(GrantTestCase):
    def test_presets_validate_and_keep_network_identity(self):
        presets = grants.load_presets()
        self.assertEqual(set(presets), {'locked-down', 'python-dev', 'web-readonly', 'full-example'})
        self.ok('dns', '8.8.8.8')
        for name, preset in presets.items():
            with self.subTest(preset=name):
                self.ok('preset', name)
                document = self.validated()['document']
                self.assertEqual(document['dns']['resolvers'], ['8.8.8.8'])
                self.assertEqual(document['taskboard'], json.loads(V2_EXAMPLE.read_bytes())['taskboard'])
                self.assertEqual(grants.current_web(document), set(preset['web']))
                self.assertEqual(self.document()['filesystem'], preset['filesystem'])
        self.assertEqual(presets['locked-down']['web'], [])
        self.assertEqual(presets['locked-down']['filesystem']['scratch'], [])

    def test_full_example_preset_is_the_shipped_example(self):
        self.ok('preset', 'locked-down')
        self.ok('preset', 'full-example')
        self.assertEqual(self.policy.read_bytes(), V2_EXAMPLE.read_bytes())

    def test_presets_listing(self):
        out = self.ok('presets')
        for name in ('locked-down', 'python-dev', 'web-readonly', 'full-example'):
            self.assertIn(name + ':', out)


class HistoryTest(GrantTestCase):
    def test_rollback_restores_and_is_itself_undoable(self):
        states = [self.policy.read_bytes()]
        for argv in (['read', '/srv/a'], ['read', '/srv/b'], ['deny-web', 'all']):
            self.ok(*argv)
            states.append(self.policy.read_bytes())
        out = self.ok('history')
        self.assertIn('read /srv/a', out)
        self.ok('rollback')
        self.assertEqual(self.policy.read_bytes(), states[2])
        self.ok('rollback')
        self.assertEqual(self.policy.read_bytes(), states[3])
        # Five recorded changes now; the oldest one's backup is the original policy.
        self.ok('rollback', '5')
        self.assertEqual(self.policy.read_bytes(), states[0])
        entries = self.log()
        self.assertEqual([item['seq'] for item in entries], [1, 2, 3, 4, 5, 6])
        self.assertEqual(entries[-1]['action'], 'rollback')
        self.assertEqual(self.grant('rollback', '7')[0], grants.NO_HISTORY)

    def test_backups_are_bounded_and_verified(self):
        for index in range(grants.BACKUPS_KEPT + 3):
            self.ok('deny-web' if index % 2 == 0 else 'allow-web', 'quic')
        backups = sorted((self.history / 'backups').iterdir())
        self.assertEqual(len(backups), grants.BACKUPS_KEPT)
        for item in backups:
            self.assertEqual(stat.S_IMODE(item.stat().st_mode), 0o600)
        code, _, err = self.grant('rollback', str(grants.BACKUPS_KEPT + 2))
        self.assertEqual(code, grants.NO_HISTORY)
        self.assertIn('pruned', err)
        backups[-1].write_text('{}')
        code, _, err = self.grant('rollback')
        self.assertEqual(code, grants.NO_HISTORY)
        self.assertIn('damaged', err)


def helper_script(body):
    return textwrap.dedent('''
        import os, signal, sys
        sys.path.insert(0, %r)
        import grants
    ''' % str(HERE)) + textwrap.dedent(body)


class ConcurrencyTest(GrantTestCase):
    def test_two_processes_serialize_and_both_changes_land(self):
        # Each process holds the lock for a while; an unlocked edit would lose one change.
        script = helper_script('''
            import time
            original = grants.NativeValidator.__call__
            def slow(self, raw):
                time.sleep(0.4)
                return original(self, raw)
            grants.NativeValidator.__call__ = slow
            sys.exit(grants.main(sys.argv[1:]))
        ''')
        processes = [subprocess.Popen([sys.executable, '-c', script, '--validator', VALIDATOR, '--policy',
                                       str(self.policy), 'read', path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                     for path in ('/srv/first', '/srv/second')]
        for process in processes:
            out, err = process.communicate(timeout=60)
            self.assertEqual(process.returncode, 0, err)
        read_only = self.document()['filesystem']['read_only']
        self.assertIn('/srv/first', read_only)
        self.assertIn('/srv/second', read_only)
        self.assertEqual(sorted(item['seq'] for item in self.log()), [1, 2])

    def test_a_held_lock_reports_busy(self):
        fd = os.open(self.dir / '.agentgate-grant.lock', os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            code, _, err = self.grant('read', '/srv', extra=['--wait', '0.2'])
        finally:
            os.close(fd)
        self.assertEqual(code, grants.BUSY)
        self.assertIn('retry', err)
        self.ok('read', '/srv')


class CrashTest(GrantTestCase):
    def crash(self, body, *argv):
        script = helper_script(textwrap.dedent(body) + '\nsys.exit(grants.main(sys.argv[1:]))\n')
        return subprocess.run([sys.executable, '-c', script, '--validator', VALIDATOR, '--policy', str(self.policy)] +
                              list(argv), capture_output=True, timeout=60)

    def test_kill_between_temporary_write_and_rename_keeps_the_original(self):
        raw = self.policy.read_bytes()
        done = self.crash('''
            real = os.replace
            def replace(source, destination):
                if str(destination).endswith('/policy.json'):
                    os.kill(os.getpid(), signal.SIGKILL)
                return real(source, destination)
            os.replace = replace
        ''', 'read', '/srv/data')
        self.assertEqual(done.returncode, -signal.SIGKILL)
        self.assertEqual(self.policy.read_bytes(), raw)
        self.assertTrue(list(self.dir.glob('.policy.json.grant-*.tmp')), 'the fixture did not reach the rename')
        self.assertTrue((self.history / 'intent.json').exists())
        self.assertIn('interrupted change', self.ok('show'))
        out = self.ok('read', '/srv/other')
        self.assertIn('discarded interrupted change 1', out)
        self.assertEqual(list(self.dir.glob('.policy.json.grant-*.tmp')), [])
        self.assertFalse((self.history / 'intent.json').exists())
        self.assertNotIn('/srv/data', self.document()['filesystem']['read_only'])
        self.assertIn('/srv/other', self.document()['filesystem']['read_only'])
        self.validated()

    def test_kill_after_rename_before_the_log_is_completed_next_time(self):
        done = self.crash('''
            def die(self, entry):
                os.kill(os.getpid(), signal.SIGKILL)
            grants.Context.append_log = die
        ''', 'read', '/srv/data')
        self.assertEqual(done.returncode, -signal.SIGKILL)
        self.assertIn('/srv/data', self.document()['filesystem']['read_only'])
        self.assertEqual(self.log(), [])
        out = self.ok('read', '/srv/other')
        self.assertIn('completed change 1', out)
        entries = self.log()
        self.assertEqual([(item['seq'], item.get('recovered', False)) for item in entries], [(1, True), (2, False)])
        self.ok('rollback', '2')
        self.assertEqual(self.policy.read_bytes(), V2_EXAMPLE.read_bytes())

    def test_outside_edit_after_an_interruption_is_inconsistent(self):
        self.crash('''
            real = os.replace
            def replace(source, destination):
                if str(destination).endswith('/policy.json'):
                    os.kill(os.getpid(), signal.SIGKILL)
                return real(source, destination)
            os.replace = replace
        ''', 'read', '/srv/data')
        document = self.document()
        document['filesystem']['read_only'].append('/hand/edit')
        self.policy.write_text(json.dumps(document, indent=2) + '\n')
        code, _, err = self.grant('read', '/srv/x')
        self.assertEqual(code, grants.INCONSISTENT)
        self.assertIn('intent', err)


class MountGrantTest(GrantTestCase):
    def setUp(self):
        super().setUp()
        share = tempfile.TemporaryDirectory()
        self.addCleanup(share.cleanup)
        self.share = Path(os.path.realpath(share.name)) / 'project'
        self.share.mkdir()
        self.share.chmod(0o755)
        self.mounts = self.dir / 'mounts.json'

    def entries(self):
        return mounts.parse_document(self.mounts.read_bytes())

    def test_read_only_and_read_write_mounts(self):
        self.ok('mount', str(self.share), '--as', '/var/lib/agentgate/mounts/project')
        self.assertEqual(self.entries(), [{'name': 'project', 'kind': 'bind', 'source': str(self.share), 'read_only': True}])
        self.assertIn('/var/lib/agentgate/mounts/project', self.document()['filesystem']['read_only'])
        self.assertEqual(stat.S_IMODE(self.mounts.stat().st_mode), 0o600)
        self.assertIn('/var/lib/agentgate/mounts/project', self.ok('show'))
        self.assertIn('unchanged=true', self.ok('mount', str(self.share), '--as', 'project'))
        self.assertEqual(self.grant('mount', str(self.share), '--as', 'project', '--read-write')[0], grants.CONFLICT)
        self.ok('unmount', 'project')
        self.assertEqual(self.entries(), [])
        self.assertNotIn('/var/lib/agentgate/mounts/project', self.document()['filesystem']['read_only'])
        self.ok('mount', str(self.share), '--read-write')
        self.assertIn('/var/lib/agentgate/mounts/project', self.document()['filesystem']['scratch'])
        self.assertEqual(self.entries()[0]['read_only'], False)
        self.validated()

    def test_a_writable_mount_never_becomes_executable(self):
        self.ok('mount', str(self.share), '--as', 'out', '--read-write')
        for argv in (['exec', '/var/lib/agentgate/mounts/out'], ['exec', '/var/lib/agentgate/mounts'],
                     ['exec', '/var/lib/agentgate/mounts/out/bin']):
            code, _, err = self.grant(*argv)
            self.assertEqual(code, grants.CONFLICT, argv)
            self.assertIn('never run code', err)
        self.ok('unmount', 'out')
        self.ok('mount', str(self.share), '--as', 'tools')
        self.ok('exec', '/var/lib/agentgate/mounts/tools')
        self.ok('unmount', 'tools')
        self.ok('exec', '/var/lib/agentgate/mounts/tools')
        code, _, err = self.grant('mount', str(self.share), '--as', 'tools', '--read-write')
        self.assertEqual(code, grants.CONFLICT)
        self.assertEqual(self.entries(), [])

    def test_unsafe_sources_are_refused(self):
        link = self.share.parent / 'link'
        link.symlink_to(self.share)
        home = self.share.parent / 'home'
        (home / '.ssh').mkdir(parents=True)
        cases = {'/': grants.UNSAFE, '/etc': grants.UNSAFE, '/proc': grants.UNSAFE, '/var/run': grants.UNSAFE,
                 '/root': grants.UNSAFE, str(link): grants.UNSAFE, str(self.dir): grants.UNSAFE,
                 str(self.history): grants.UNSAFE, str(home): grants.UNSAFE, str(home / '.ssh'): grants.UNSAFE,
                 str(self.share / 'missing'): grants.USAGE}
        self.ok('read', '/srv/created-history')
        raw = self.policy.read_bytes()
        with patch.dict(os.environ, {'HOME': str(home)}):
            for source, expected in cases.items():
                with self.subTest(source=source):
                    self.assertEqual(self.grant('mount', source, '--as', 'x')[0], expected)
        self.assertEqual(self.policy.read_bytes(), raw)
        self.assertFalse(self.mounts.exists())
        self.assertEqual(len(self.log()), 1)
        spaced = self.share.parent / 'my project'
        spaced.mkdir()
        self.assertEqual(self.grant('mount', str(spaced), '--as', 'x')[0], grants.UNSAFE)
        self.assertEqual(self.grant('mount', str(self.share), '--as', '../x')[0], grants.USAGE)

    def test_mount_limits_overlap_and_version_one(self):
        for index in range(mounts.MAX_MOUNTS):
            folder = self.share / ('m%d' % index)
            folder.mkdir()
            self.ok('mount', str(folder), '--as', 'm%d' % index)
        extra = self.share.parent / 'extra'
        extra.mkdir()
        self.assertEqual(self.grant('mount', str(extra), '--as', 'extra')[0], grants.CONFLICT)
        self.ok('unmount', 'm0')
        self.assertEqual(self.grant('mount', str(self.share), '--as', 'parent')[0], grants.CONFLICT)
        shutil.copyfile(V1_EXAMPLE, self.policy)
        self.mounts.unlink()
        self.assertEqual(self.grant('mount', str(extra), '--as', 'extra')[0], grants.UPGRADE)
        self.assertFalse(self.mounts.exists())

    def test_presets_and_rollback_keep_mounts_coherent(self):
        self.ok('mount', str(self.share), '--as', 'project')
        self.ok('preset', 'locked-down')
        self.assertIn('/var/lib/agentgate/mounts/project', self.document()['filesystem']['read_only'])
        out = self.ok('rollback', '2')
        self.assertIn('no access entry', out)
        self.assertIn('[no access entry: inaccessible]', self.ok('show'))

    def test_dry_run_mount_writes_nothing(self):
        out = self.ok('--dry-run', 'mount', str(self.share), '--as', 'project')
        self.assertIn('would list', out)
        self.assertFalse(self.mounts.exists())
        self.assertEqual(self.policy.read_bytes(), V2_EXAMPLE.read_bytes())


class DomainTest(GrantTestCase):
    def test_domain_allowlist_is_honestly_unavailable(self):
        code, _, err = self.grant('allow-domain', 'github.com')
        self.assertEqual(code, grants.NOT_IMPLEMENTED)
        self.assertIn('not implemented', err)
        self.assertEqual(self.policy.read_bytes(), V2_EXAMPLE.read_bytes())


class WizardTest(GrantTestCase):
    example = V1_EXAMPLE

    def wizard(self, answers):
        lines = []
        args = grants.parser('grant').parse_args(['--validator', VALIDATOR, '--policy', str(self.policy), 'wizard'])
        replies = iter(answers)
        with contextlib.redirect_stderr(io.StringIO()):
            code = grants.do_wizard(args, 'grant', ask=lambda prompt: next(replies), out=lines.append,
                                    run=lambda argv: grants.main(argv, 'grant', out=lines.append))
        return code, '\n'.join(lines)

    def test_wizard_prints_and_runs_the_exact_commands(self):
        code, out = self.wizard(['python-dev', 'none', '', '/srv/docs', '', 'yes', 'yes'])
        self.assertEqual(code, grants.OK, out)
        for step in ('preset python-dev --upgrade-to-v2', 'deny-web all', 'read /srv/docs'):
            self.assertIn('ran: grant --policy %s --validator %s %s' % (self.policy, VALIDATOR, step), out)
        document = self.document()
        self.assertEqual(document['version'], grants.V2)
        self.assertEqual(document['web']['rules'], [])
        self.assertIn('/srv/docs', document['filesystem']['read_only'])

    def test_declining_changes_nothing(self):
        raw = self.policy.read_bytes()
        code, out = self.wizard(['keep', 'none', '', '/srv/docs', '', 'no', 'no'])
        self.assertEqual(code, grants.OK)
        self.assertIn('dropped the file and folder steps', out)
        self.assertIn('Nothing changed.', out)
        self.assertEqual(self.policy.read_bytes(), raw)


class ApplianceGrantTest(unittest.TestCase):
    """State-directory mode with the guest and Docker replaced by recorders."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(os.path.realpath(directory.name)) / 'state'
        self.state.mkdir(mode=0o700)
        raw = V2_EXAMPLE.read_bytes()
        (self.state / 'policy.json').write_bytes(raw)
        (self.state / 'policy.json').chmod(0o600)
        info = json.loads(subprocess.run([VALIDATOR, 'network-info', '/dev/stdin'], input=raw,
                                         capture_output=True, check=True).stdout)
        self.binding = {'name': 'ag-poc-test', 'owner': 'test', 'images': {'artifacts': 'sha256:' + 'a' * 64},
                        'policy_sha256': hashlib.sha256(raw).hexdigest(), 'policy_digest': info['digest']}
        self.write_binding(self.binding)
        self.installed = []
        self.running = True
        self.failure = None
        patches = [patch('appliance_common.inspect_owned', lambda binding: {'State': {'Running': self.running}}),
                   patch('appliance_guest.install_policy', self.install)]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def write_binding(self, binding):
        path = self.state / 'binding.json'
        path.write_text(json.dumps(binding))
        path.chmod(0o600)

    def binding_now(self):
        return json.loads((self.state / 'binding.json').read_text())

    def install(self, state, binding, path):
        if self.failure:
            raise self.failure
        self.installed.append(Path(path).read_bytes())

    def grant(self, *argv):
        err = io.StringIO()
        lines = []
        with contextlib.redirect_stderr(err):
            code = grants.main(['--validator', VALIDATOR, '--state', str(self.state)] + list(argv), out=lines.append)
        return code, '\n'.join(lines), err.getvalue()

    def test_running_appliance_receives_the_exact_bytes_first(self):
        code, out, err = self.grant('read', '/srv/data')
        self.assertEqual(code, grants.OK, err)
        self.assertIn('appliance=applied', out)
        raw = (self.state / 'policy.json').read_bytes()
        self.assertEqual(self.installed, [raw])
        binding = self.binding_now()
        self.assertEqual(binding['policy_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertNotIn('policy_pending', binding)
        self.assertFalse((self.state / 'policy.pending.json').exists())

    def test_stopped_appliance_marks_the_change_pending_and_start_applies_it(self):
        self.running = False
        code, out, _ = self.grant('read', '/srv/data')
        self.assertEqual(code, grants.OK)
        self.assertIn('appliance=pending', out)
        self.assertEqual(self.installed, [])
        binding = self.binding_now()
        self.assertTrue(binding['policy_pending'])
        self.running = True
        with contextlib.redirect_stdout(io.StringIO()), patch.dict(os.environ, {'AGENTGATE_VALIDATOR': VALIDATOR}):
            grants.start_sync(self.state, binding)
        self.assertEqual(self.installed, [(self.state / 'policy.json').read_bytes()])
        self.assertNotIn('policy_pending', self.binding_now())

    def test_busy_guest_changes_nothing(self):
        import appliance_guest
        before = (self.state / 'policy.json').read_bytes()
        self.failure = appliance_guest.GuestBusy('a guarded command is running in the appliance')
        code, _, err = self.grant('read', '/srv/data')
        self.assertEqual(code, grants.BUSY)
        self.assertEqual((self.state / 'policy.json').read_bytes(), before)
        self.assertEqual(self.binding_now(), self.binding)
        self.assertFalse((self.state / 'grants' / 'intent.json').exists())

    def test_failed_transfer_keeps_the_policy_and_resynchronizes(self):
        before = (self.state / 'policy.json').read_bytes()
        self.failure = subprocess.CalledProcessError(255, ['ssh'])
        code, _, err = self.grant('read', '/srv/data')
        self.assertEqual(code, grants.APPLY)
        self.assertEqual((self.state / 'policy.json').read_bytes(), before)
        self.assertTrue(self.binding_now()['policy_pending'])
        self.failure = None
        code, out, _ = self.grant('sync')
        self.assertEqual(code, grants.OK)
        self.assertEqual(self.installed, [before])
        self.assertNotIn('policy_pending', self.binding_now())

    def test_hand_edited_state_policy_is_inconsistent(self):
        path = self.state / 'policy.json'
        path.write_bytes(path.read_bytes().replace(b'"/tmp"', b'"/srv"'))
        self.assertEqual(self.grant('read', '/srv/data')[0], grants.INCONSISTENT)

    def test_policy_command_uses_the_same_engine_and_keeps_its_output(self):
        incoming = self.state.parent / 'next.json'
        document = json.loads(V2_EXAMPLE.read_bytes())
        document['web']['rules'] = []
        incoming.write_text(json.dumps(document))
        incoming.chmod(0o600)
        with contextlib.redirect_stdout(io.StringIO()) as printed, patch.dict(os.environ, {'AGENTGATE_VALIDATOR': VALIDATOR}):
            grants.apply_file(self.state, self.binding_now(), incoming)
        self.assertIn('policy_applied=true next_command=true digest=', printed.getvalue())
        self.assertEqual(self.installed, [incoming.read_bytes()])
        self.assertEqual(json.loads((self.state / 'grants' / 'log.jsonl').read_text())['action'], 'policy-file')
        document['taskboard']['port'] = 9090
        incoming.write_text(json.dumps(document))
        with self.assertRaises(grants.GrantError) as caught, patch.dict(os.environ, {'AGENTGATE_VALIDATOR': VALIDATOR}):
            grants.apply_file(self.state, self.binding_now(), incoming)
        self.assertEqual(caught.exception.code, grants.CONFLICT)

    def test_appliance_mounts_are_read_only_snapshots(self):
        share = self.state.parent / 'project'
        share.mkdir()
        code, _, err = self.grant('mount', str(share), '--read-write')
        self.assertEqual(code, grants.NOT_IMPLEMENTED)
        self.assertIn('read-only', err)
        self.assertEqual(self.grant('mount', str(self.state))[0], grants.UNSAFE)
        self.running = False
        code, _, err = self.grant('mount', str(share))
        self.assertEqual(code, grants.APPLY)
        self.assertIn('start the appliance', err)

    def test_snapshot_mount_copies_then_grants(self):
        share = self.state.parent / 'project'
        share.mkdir()
        (share / 'README').write_text('hello\n')
        copied, commands = [], []
        with patch('appliance_common.copy_guest', lambda state, binding, source, destination:
                   copied.append((Path(source).read_bytes()[:0], destination))), \
             patch('appliance_guest.admin', lambda state, binding, command, timeout=30: commands.append(command) or ''):
            code, out, err = self.grant('mount', str(share), '--as', 'project')
        self.assertEqual(code, grants.OK, err)
        self.assertEqual(copied[0][1], '/root/agentgate-share-project.tar')
        self.assertIn('mounts.py install-snapshot /var/lib/agentgate-poc-demo project', commands[0])
        self.assertIn('flock -n -E 75', commands[0])
        self.assertIn('/var/lib/agentgate/mounts/project', json.loads(self.installed[-1])['filesystem']['read_only'])
        shares = json.loads((self.state / 'shares.json').read_text())
        self.assertEqual((shares['project']['source'], shares['project']['files']), (str(share), 1))
        self.assertFalse(list(self.state.glob('share-*.tar')))
        nested = share / 'docs'
        nested.mkdir()
        self.assertEqual(self.grant('mount', str(nested), '--as', 'docs')[0], grants.CONFLICT)


if __name__ == '__main__':
    unittest.main()
