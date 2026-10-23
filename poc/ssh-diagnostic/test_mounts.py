# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Host folder mount validation, runtime arguments, and snapshot shares."""
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import mounts

V2_FILESYSTEM = {'workspace': '/var/lib/agentgate/workspace', 'scratch': ['/tmp'], 'read_only': ['/etc'],
                 'execute': ['/usr', '/bin'], 'devices': [], 'deny': [], 'memory': {'anonymous_execute': False}}


def document(entries):
    return json.dumps({'version': mounts.MOUNTS_VERSION, 'mounts': entries}).encode()


class MountsDocumentTest(unittest.TestCase):
    def test_valid_document_round_trips(self):
        entries = [{'name': 'repo', 'kind': 'bind', 'source': '/srv/repo', 'read_only': True},
                   {'name': 'data', 'kind': 'snapshot', 'read_only': True}]
        self.assertEqual(mounts.parse_document(document(entries)), entries)
        self.assertEqual(mounts.parse_document(mounts.render_document(entries)), entries)

    def test_invalid_documents_fail_closed(self):
        bind = {'name': 'repo', 'kind': 'bind', 'source': '/srv/repo', 'read_only': True}
        cases = {
            'not json': b'{',
            'duplicate key': b'{"version": "agentgate.poc-mounts.v1", "version": "x", "mounts": []}',
            'nan': b'{"version": "agentgate.poc-mounts.v1", "mounts": [NaN]}',
            'other version': json.dumps({'version': 'v0', 'mounts': []}).encode(),
            'extra top-level': json.dumps({'version': mounts.MOUNTS_VERSION, 'mounts': [], 'x': 1}).encode(),
            'unknown field': document([dict(bind, mode='rw')]),
            'missing field': document([{'name': 'repo', 'kind': 'bind', 'source': '/srv/repo'}]),
            'unknown kind': document([dict(bind, kind='volume')]),
            'string flag': document([dict(bind, read_only='yes')]),
            'bad name': document([dict(bind, name='../etc')]),
            'upper name': document([dict(bind, name='Repo')]),
            'repeated name': document([bind, dict(bind, source='/srv/other')]),
            'overlapping sources': document([bind, dict(bind, name='sub', source='/srv/repo/sub')]),
            'writable snapshot': document([{'name': 'data', 'kind': 'snapshot', 'read_only': False}]),
            'snapshot source': document([{'name': 'data', 'kind': 'snapshot', 'read_only': True, 'source': '/x'}]),
            'protected source': document([dict(bind, source='/etc')]),
            'too many': document([dict(bind, name='m%d' % i, source='/srv/m%d' % i) for i in range(9)]),
        }
        for name, raw in cases.items():
            with self.subTest(name=name), self.assertRaises(mounts.MountError):
                mounts.parse_document(raw)


class SourceRulesTest(unittest.TestCase):
    def test_forbidden_trees_secrets_and_homes(self):
        home = '/home/alice'
        refused = ['/', '/etc', '/etc/ssl', '/root/project', '/proc/1', '/sys/fs', '/dev', '/var/run',
                   '/run/user/1000', '/var', '/var/lib', '/var/lib/docker/volumes', '/usr/local/src',
                   '/var/lib/agentgate-poc-demo', '/var/lib/agentgate-poc-demo/shares/x',
                   '/home', home, home + '/.ssh', home + '/.ssh/keys', home + '/.config/gh',
                   home + '/.local/share/agentgate/poc', '/srv/../etc', 'relative/path', '/srv/repo/']
        for source in refused:
            with self.subTest(source=source), self.assertRaises(mounts.MountError):
                mounts.check_source_rules(source, home=home)
        for source in ('/srv/repo', home + '/src/project', '/data/cache', '/opt/work'):
            self.assertEqual(mounts.check_source_rules(source, home=home), source)
        with self.assertRaises(mounts.MountError):
            mounts.check_source_rules('/srv/state/sub', forbidden=('/srv/state',))
        with self.assertRaises(mounts.MountError):
            mounts.check_source_rules('/srv', forbidden=('/srv/state',))

    def test_live_bind_sources_need_csv_safe_characters(self):
        self.assertEqual(mounts.check_bind_source('/srv/my-repo_1.2@x+y'), '/srv/my-repo_1.2@x+y')
        for source in ('/srv/my repo', '/srv/a,b', '/srv/"q"', "/srv/it's", '/srv/a\nb', '/srv/é'):
            with self.subTest(source=source), self.assertRaises(mounts.MountError):
                mounts.check_bind_source(source)

    def test_live_directory_refuses_symlinks_files_and_submounts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(os.path.realpath(directory))
            real = root / 'real'
            real.mkdir()
            (root / 'link').symlink_to(real)
            (root / 'file').write_text('x')
            info = root / 'mountinfo'
            info.write_text('36 35 98:0 / / rw - ext4 /dev/root rw\n')
            mounts.check_live_directory(str(real), str(info))
            with self.assertRaisesRegex(mounts.MountError, 'symbolic link'):
                mounts.check_live_directory(str(root / 'link'), str(info))
            with self.assertRaisesRegex(mounts.MountError, 'not a directory'):
                mounts.check_live_directory(str(root / 'file'), str(info))
            escaped = str(real).replace(' ', '\\040')
            info.write_text('36 35 98:0 / / rw - ext4 /dev/root rw\n'
                            '50 36 0:9 / ' + escaped + '/inner rw - tmpfs tmpfs rw\n')
            with self.assertRaisesRegex(mounts.MountError, 'further mounts'):
                mounts.check_live_directory(str(real), str(info))
            # A sibling with a shared prefix is not below the folder.
            info.write_text('50 36 0:9 / ' + escaped + '-other rw - tmpfs tmpfs rw\n')
            mounts.check_live_directory(str(real), str(info))


class PolicyCoherenceTest(unittest.TestCase):
    def test_mounts_need_filesystem_policy_and_writable_mounts_never_run(self):
        ro = {'name': 'repo', 'kind': 'bind', 'source': '/srv/repo', 'read_only': True}
        rw = {'name': 'out', 'kind': 'bind', 'source': '/srv/out', 'read_only': False}
        mounts.check_policy_coherence([], None)
        with self.assertRaisesRegex(mounts.MountError, 'version two'):
            mounts.check_policy_coherence([ro], None)
        mounts.check_policy_coherence([ro, rw], V2_FILESYSTEM)
        executable = dict(V2_FILESYSTEM, execute=['/usr', '/var/lib/agentgate/mounts/repo'])
        mounts.check_policy_coherence([ro, rw], executable)
        for tree in ('/var/lib/agentgate/mounts/out', '/var/lib/agentgate/mounts', '/var/lib/agentgate/mounts/out/bin'):
            with self.subTest(tree=tree), self.assertRaisesRegex(mounts.MountError, 'never run code'):
                mounts.check_policy_coherence([rw], dict(V2_FILESYSTEM, execute=[tree]))

    def test_docker_arguments_derive_only_from_validated_fields(self):
        self.assertEqual(mounts.docker_argument('/srv/repo', {'name': 'repo', 'read_only': True}),
                         '--mount=type=bind,source=/srv/repo,target=/var/lib/agentgate/mounts/repo,readonly')
        self.assertEqual(mounts.docker_argument('/srv/out', {'name': 'out', 'read_only': False}),
                         '--mount=type=bind,source=/srv/out,target=/var/lib/agentgate/mounts/out')
        with self.assertRaises(mounts.MountError):
            mounts.docker_argument('/srv/a,readonly=false', {'name': 'x', 'read_only': True})


class PrepareTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        base = Path(os.path.realpath(directory.name))
        self.root = base / 'instance'
        self.root.mkdir(mode=0o700)
        self.share = base / 'share'
        self.share.mkdir()

    def write_mounts(self, entries):
        mounts.write_private(self.root / 'mounts.json', document(entries))

    def prepare(self, filesystem):
        info = {'document': {'filesystem': filesystem}}
        empty = self.root / 'mountinfo'
        empty.write_text('')
        real = mounts.submounts
        with patch('settings.effective_policy', return_value=info), patch('settings.load_settings'), \
             patch.object(mounts, 'submounts', lambda source, mountinfo=None: real(source, str(empty))):
            return mounts.prepare(self.root)

    def test_no_mounts_file_means_no_mounts(self):
        self.assertEqual(self.prepare(None), [])
        self.assertEqual(json.loads((self.root / 'mounts-active.json').read_bytes()), [])
        self.assertEqual(stat.S_IMODE((self.root / 'mounts-active.json').stat().st_mode), 0o600)

    def test_bind_mounts_produce_arguments_and_the_binding(self):
        self.write_mounts([{'name': 'repo', 'kind': 'bind', 'source': str(self.share), 'read_only': True}])
        arguments = self.prepare(V2_FILESYSTEM)
        self.assertEqual(arguments, ['--mount=type=bind,source=%s,target=/var/lib/agentgate/mounts/repo,readonly' % self.share])
        self.assertEqual(json.loads((self.root / 'mounts-active.json').read_bytes()),
                         [{'path': '/var/lib/agentgate/mounts/repo', 'source': str(self.share), 'read_only': True}])

    def test_refusals_never_drop_a_mount_silently(self):
        inside = self.root / 'inside'
        inside.mkdir()
        self.write_mounts([{'name': 'repo', 'kind': 'bind', 'source': str(inside), 'read_only': True}])
        with self.assertRaisesRegex(mounts.MountError, 'protected path'):
            self.prepare(V2_FILESYSTEM)
        self.write_mounts([{'name': 'repo', 'kind': 'bind', 'source': str(self.share), 'read_only': True}])
        with self.assertRaisesRegex(mounts.MountError, 'version two'):
            self.prepare(None)
        self.write_mounts([{'name': 'repo', 'kind': 'bind', 'source': str(self.share), 'read_only': False}])
        with self.assertRaisesRegex(mounts.MountError, 'never run code'):
            self.prepare(dict(V2_FILESYSTEM, execute=['/var/lib/agentgate/mounts']))
        self.write_mounts([{'name': 'repo', 'kind': 'bind', 'source': str(self.share), 'read_only': True}])
        self.share.rmdir()
        with self.assertRaises(OSError):
            self.prepare(V2_FILESYSTEM)
        self.share.mkdir()
        (self.root / 'mounts.json').chmod(0o644)
        with self.assertRaisesRegex(mounts.MountError, 'mode 0600'):
            self.prepare(V2_FILESYSTEM)
        (self.root / 'mounts.json').unlink()
        (self.root / 'mounts.json').symlink_to(self.root / 'elsewhere.json')
        with self.assertRaises(OSError):
            self.prepare(V2_FILESYSTEM)


class SnapshotTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(os.path.realpath(directory.name))
        self.source = self.base / 'project'
        (self.source / 'src').mkdir(parents=True)
        (self.source / 'README').write_text('hello\n')
        (self.source / 'src' / 'tool.sh').write_text('#!/bin/sh\n')
        (self.source / 'src' / 'tool.sh').chmod(0o4777)
        (self.source / 'link').symlink_to('/etc/passwd')
        os.mkfifo(self.source / 'pipe')
        self.root = self.base / 'instance'
        self.root.mkdir(mode=0o700)

    def build(self, **limits):
        archive = self.base / 'share.tar'
        archive.unlink(missing_ok=True)
        return archive, mounts.build_snapshot(self.source, archive, **limits)

    def test_snapshot_round_trip_normalizes_and_skips_special_files(self):
        archive, stats = self.build()
        self.assertEqual((stats['files'], stats['directories'], stats['skipped']), (2, 1, 2))
        mounts.install_snapshot(self.root, 'project', archive)
        share = self.root / 'shares' / 'project'
        self.assertEqual((share / 'README').read_text(), 'hello\n')
        self.assertFalse((share / 'link').exists() or (share / 'link').is_symlink())
        self.assertFalse((share / 'pipe').exists())
        self.assertEqual(stat.S_IMODE((share / 'src' / 'tool.sh').stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((share / 'README').stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(share.stat().st_mode), 0o755)
        self.assertEqual(mounts.load_entries(self.root), [{'name': 'project', 'kind': 'snapshot', 'read_only': True}])
        # A refresh replaces the whole share; removed files disappear.
        (self.source / 'README').unlink()
        archive, _ = self.build()
        mounts.install_snapshot(self.root, 'project', archive)
        self.assertFalse((share / 'README').exists())
        self.assertEqual(sorted(path.name for path in (self.root / 'shares').iterdir()), ['project'])
        self.assertTrue(mounts.remove(self.root, 'project'))
        self.assertFalse(share.exists())
        self.assertEqual(mounts.load_entries(self.root), [])

    def test_snapshot_limits(self):
        with self.assertRaisesRegex(mounts.MountError, 'MiB'):
            self.build(max_bytes=3)
        with self.assertRaisesRegex(mounts.MountError, 'entry'):
            self.build(max_entries=2)

    def test_hostile_archives_are_refused_before_replacing_the_share(self):
        def archive_with(member, data=b''):
            path = self.base / 'bad.tar'
            with tarfile.open(path, 'w') as archive:
                member.size = len(data) if member.isreg() else 0
                archive.addfile(member, io.BytesIO(data) if member.isreg() else None)
            return path
        good, _ = self.build()
        mounts.install_snapshot(self.root, 'project', good)
        link = tarfile.TarInfo('evil')
        link.type, link.linkname = tarfile.SYMTYPE, '/etc'
        device = tarfile.TarInfo('dev')
        device.type = tarfile.CHRTYPE
        for member in (tarfile.TarInfo('../escape'), tarfile.TarInfo('/abs'), tarfile.TarInfo('a/../../b'),
                       link, device):
            with self.subTest(name=member.name), self.assertRaises(mounts.MountError):
                mounts.install_snapshot(self.root, 'project', archive_with(member, b'x'))
            self.assertEqual((self.root / 'shares' / 'project' / 'README').read_text(), 'hello\n')
        self.assertFalse((self.base / 'escape').exists())


if __name__ == '__main__':
    unittest.main()
