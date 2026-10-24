#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Validate the protected host folder mounts for the next guarded target.

A mount grants nothing by itself. The command's version two filesystem policy
decides what a path below /var/lib/agentgate/mounts may do, so every mount is
refused for a policy without that section. The root-owned mounts.json in the
instance directory is data, never shell: this module derives each Docker
argument from validated fields only.
"""
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile

MOUNTS_VERSION = 'agentgate.poc-mounts.v1'
MOUNT_ROOT = '/var/lib/agentgate/mounts'
MAX_MOUNTS = 8
NAME = re.compile(r'[a-z0-9][a-z0-9_-]{0,31}')
# Docker parses --mount as CSV. A bind source keeps to characters that need no quoting.
BIND_SOURCE = re.compile(r'/[A-Za-z0-9._@+/-]{1,4095}')
# Host trees that may never be shared or contain a shared tree.
PROTECTED = ('/proc', '/sys', '/dev', '/run', '/var/run', '/etc', '/root', '/boot', '/usr', '/bin',
             '/sbin', '/lib', '/lib32', '/lib64', '/libx32', '/var/lib/docker', '/var/lib/containerd',
             '/var/lib/cloud', '/var/lib/kubelet', '/snap')
INSTANCE_PREFIX = '/var/lib/agentgate-poc-'
# Per-user secret stores below a home directory.
SECRET_NAMES = ('.ssh', '.gnupg', '.aws', '.azure', '.config', '.docker', '.kube', '.netrc',
                '.git-credentials', '.local/share/agentgate', '.password-store', '.vault-token')
SNAPSHOT_MAX_BYTES = 256 << 20
SNAPSHOT_MAX_ENTRIES = 20000


class MountError(ValueError):
    """A mount request or mounts file that must be refused."""


def overlaps(a, b):
    a, b = a.rstrip('/') or '/', b.rstrip('/') or '/'
    if a == '/' or b == '/':
        return True
    return a == b or a.startswith(b + '/') or b.startswith(a + '/')


def mount_path(name):
    return MOUNT_ROOT + '/' + name


def check_name(name):
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise MountError('a mount name needs 1..32 of a-z 0-9 _ - and must start with a letter or digit: ' + repr(name))
    return name


def name_from_path(value):
    """Accept NAME or /var/lib/agentgate/mounts/NAME and return NAME."""
    if isinstance(value, str) and value.startswith(MOUNT_ROOT + '/'):
        value = value[len(MOUNT_ROOT) + 1:]
    return check_name(value)


def default_name(source):
    base = re.sub(r'[^a-z0-9_-]+', '-', Path(source).name.lower()).strip('-_')[:32]
    return base if base and NAME.fullmatch(base) else 'share'


def _duplicate_free(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise MountError('duplicate JSON key in the mounts file: ' + key)
        out[key] = value
    return out


def _no_constant(value):
    raise MountError('the mounts file contains the non-JSON number ' + value)


def parse_document(raw):
    """Return the validated mount entries of one mounts.json document."""
    try:
        document = json.loads(raw, object_pairs_hook=_duplicate_free, parse_constant=_no_constant)
    except MountError:
        raise
    except (ValueError, UnicodeDecodeError) as error:
        raise MountError('the mounts file is not valid JSON: ' + str(error)) from None
    if not isinstance(document, dict) or set(document) != {'version', 'mounts'} or \
       document['version'] != MOUNTS_VERSION or not isinstance(document['mounts'], list):
        raise MountError('the mounts file requires exactly {"version": "' + MOUNTS_VERSION + '", "mounts": [...]}')
    entries = document['mounts']
    if len(entries) > MAX_MOUNTS:
        raise MountError('at most %d host folder mounts are allowed' % MAX_MOUNTS)
    names, sources = set(), []
    for entry in entries:
        if not isinstance(entry, dict) or entry.get('kind') not in ('bind', 'snapshot'):
            raise MountError('each mount needs kind "bind" or "snapshot"')
        wanted = {'name', 'kind', 'read_only'} | ({'source'} if entry['kind'] == 'bind' else set())
        if set(entry) != wanted or not isinstance(entry['read_only'], bool):
            raise MountError('mount fields differ for %s: expected %s' % (entry.get('name'), sorted(wanted)))
        check_name(entry['name'])
        if entry['name'] in names:
            raise MountError('mount name repeats: ' + entry['name'])
        names.add(entry['name'])
        if entry['kind'] == 'snapshot' and not entry['read_only']:
            raise MountError('a snapshot share is always read-only')
        if entry['kind'] == 'bind':
            check_bind_source(entry['source'])
            if any(overlaps(entry['source'], other) for other in sources):
                raise MountError('host folder sources overlap: ' + entry['source'])
            sources.append(entry['source'])
    return entries


def render_document(entries):
    return (json.dumps({'version': MOUNTS_VERSION, 'mounts': entries}, indent=2) + '\n').encode()


def secret_paths(home):
    if not home:
        return []
    return [str(Path(home) / name) for name in SECRET_NAMES]


def check_source_rules(source, forbidden=(), home=None):
    """Static rules shared by live binds and snapshot shares."""
    if not isinstance(source, str) or not source.startswith('/') or os.path.normpath(source) != source or \
       '\x00' in source or source == '/':
        raise MountError('a host folder must be a canonical absolute directory other than /: ' + repr(source))
    for protected in PROTECTED:
        if overlaps(source, protected):
            raise MountError('%s overlaps protected host tree %s' % (source, protected))
    if source.startswith(INSTANCE_PREFIX) or INSTANCE_PREFIX.startswith(source.rstrip('/') + '/'):
        raise MountError('%s overlaps an AgentGate instance directory' % source)
    # The same rules the guard applies without knowing $HOME (dockerplacement
    # protectedSource): no home directory itself, no credential store anywhere.
    parts = source.strip('/').split('/')
    if parts[0] == 'home' and len(parts) <= 2:
        raise MountError('%s is a home directory or contains one; share a project folder below it' % source)
    for name in SECRET_NAMES:
        if ('/' + name + '/') in (source + '/'):
            raise MountError('%s passes through the credential store %s' % (source, name))
    if home:
        home = os.path.normpath(home)
        if source == home or home.startswith(source.rstrip('/') + '/'):
            raise MountError('%s is a home directory or contains one; share a project folder below it' % source)
    for secret in secret_paths(home):
        if overlaps(source, secret):
            raise MountError('%s overlaps the secret store %s' % (source, secret))
    for item in forbidden:
        if item and overlaps(source, str(item)):
            raise MountError('%s overlaps protected path %s' % (source, item))
    return source


def check_bind_source(source, forbidden=(), home=None):
    check_source_rules(source, forbidden, home)
    if not BIND_SOURCE.fullmatch(source):
        raise MountError('a live host folder path may use only letters, digits, and . _ @ + - /: ' + source)
    return source


def submounts(source, mountinfo='/proc/self/mountinfo'):
    """Return mount points strictly below source; a bind must not carry them."""
    found = []
    with open(mountinfo, encoding='utf-8', errors='surrogateescape') as lines:
        for line in lines:
            fields = line.split()
            if len(fields) < 5:
                continue
            point = re.sub(r'\\([0-7]{3})', lambda match: chr(int(match.group(1), 8)), fields[4])
            if point.startswith(source.rstrip('/') + '/'):
                found.append(point)
    return found


def check_live_directory(source, mountinfo='/proc/self/mountinfo'):
    """Filesystem checks at grant time and again before every target starts."""
    if os.path.realpath(source) != source:
        raise MountError('%s contains a symbolic link; use its real path %s' % (source, os.path.realpath(source)))
    meta = os.lstat(source)
    if not stat.S_ISDIR(meta.st_mode):
        raise MountError('%s is not a directory' % source)
    nested = submounts(source, mountinfo)
    if nested:
        raise MountError('%s contains further mounts (%s); share a folder without them' % (source, nested[0]))
    return meta


def snapshot_source(root, name):
    return Path(root) / 'shares' / check_name(name)


def check_policy_coherence(entries, filesystem):
    """A mount needs the v2 filesystem policy, and a writable mount never runs code."""
    if not entries:
        return
    if filesystem is None:
        raise MountError('host folder mounts require a version two policy with a filesystem section; '
                         'a version one policy does not control file access')
    for entry in entries:
        if entry['read_only']:
            continue
        for tree in filesystem.get('execute', []):
            if overlaps(tree, mount_path(entry['name'])):
                raise MountError('writable mount %s overlaps executable tree %s; writable trees never run code'
                                 % (mount_path(entry['name']), tree))


def docker_argument(source, entry):
    if not BIND_SOURCE.fullmatch(str(source)):
        raise MountError('unsupported mount source path: ' + str(source))
    value = 'type=bind,source=%s,target=%s' % (source, mount_path(entry['name']))
    return '--mount=' + value + (',readonly' if entry['read_only'] else '')


LAUNCH_MOUNTS = 'launch-mounts.json'


def prepare(root, entries=None):
    """Validate the mounts for the next target and record the approved set.

    Prints one Docker argument per line and writes mounts-active.json for the
    target binding. Any doubt refuses the target instead of dropping a mount.
    A launch passes its own validated entries; the SSH path reads mounts.json.
    """
    from settings import effective_policy, load_settings
    root = Path(root)
    if entries is None:
        entries = load_entries(root)
    active = []
    arguments = []
    if entries:
        info = effective_policy(root, load_settings(root / 'settings.json'))
        check_policy_coherence(entries, info['document'].get('filesystem'))
    for entry in entries:
        if entry['kind'] == 'bind':
            source = check_bind_source(entry['source'], forbidden=(str(root),))
            check_live_directory(source)
        else:
            source = str(snapshot_source(root, entry['name']))
            meta = os.lstat(source)
            if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_mode & 0o022 or \
               os.path.realpath(source) != source:
                raise MountError('snapshot share custody differs: ' + source)
        active.append({'path': mount_path(entry['name']), 'source': source, 'read_only': entry['read_only']})
        arguments.append(docker_argument(source, entry))
    write_private(root / 'mounts-active.json', json.dumps(active, sort_keys=True).encode())
    return arguments


def write_private(path, raw, mode=0o600):
    """Atomically and durably replace one private file."""
    path = Path(path)
    temporary = path.with_name('.' + path.name + '.mounts-new')
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def build_snapshot(source, output, max_bytes=SNAPSHOT_MAX_BYTES, max_entries=SNAPSHOT_MAX_ENTRIES):
    """Write a normalized tar of a directory: directories and regular files only.

    Symbolic links, devices, sockets, FIFOs and other file systems are skipped
    and counted. Owners become root, modes 0755/0644, and no file is followed.
    """
    source = Path(source)
    origin = os.lstat(source)
    stats = {'files': 0, 'directories': 0, 'bytes': 0, 'skipped': 0}
    with tarfile.open(output, 'w', format=tarfile.PAX_FORMAT) as archive:
        def add(path, meta, arcname):
            info = tarfile.TarInfo(arcname)
            info.uid = info.gid = 0
            info.uname = info.gname = 'root'
            info.mtime = int(meta.st_mtime)
            if stat.S_ISDIR(meta.st_mode):
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(info)
                stats['directories'] += 1
                return
            info.mode = 0o755 if meta.st_mode & 0o111 else 0o644
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            with os.fdopen(fd, 'rb') as handle:
                current = os.fstat(handle.fileno())
                if not stat.S_ISREG(current.st_mode) or current.st_ino != meta.st_ino:
                    raise MountError('a file changed while the share was read: ' + str(path))
                info.size = current.st_size
                stats['bytes'] += info.size
                if stats['bytes'] > max_bytes:
                    raise MountError('the folder exceeds the %d MiB snapshot limit' % (max_bytes >> 20))
                archive.addfile(info, handle)
            stats['files'] += 1

        def walk(directory, prefix):
            with os.scandir(directory) as items:
                for item in sorted(items, key=lambda entry: entry.name):
                    meta = item.stat(follow_symlinks=False)
                    if stats['files'] + stats['directories'] + 1 > max_entries:
                        raise MountError('the folder exceeds the %d entry snapshot limit' % max_entries)
                    if meta.st_dev != origin.st_dev or not (stat.S_ISDIR(meta.st_mode) or stat.S_ISREG(meta.st_mode)):
                        stats['skipped'] += 1
                        continue
                    name = prefix + item.name
                    add(item.path, meta, name)
                    if stat.S_ISDIR(meta.st_mode):
                        walk(item.path, name + '/')
        walk(source, '')
    return stats


def install_snapshot(root, name, archive_path, max_bytes=SNAPSHOT_MAX_BYTES, max_entries=SNAPSHOT_MAX_ENTRIES,
                     record=True):
    """Replace one read-only share from a snapshot archive. Run on the Docker host."""
    if not hasattr(tarfile, 'data_filter'):
        raise MountError('Python with tarfile extraction filters (3.12 or later) is required')
    root = Path(root)
    target = snapshot_source(root, name)
    shares = target.parent
    shares.mkdir(mode=0o700, exist_ok=True)
    if shares.is_symlink() or not shares.is_dir():
        raise MountError('the share directory custody differs')
    staging, previous = shares / ('.' + name + '.new'), shares / ('.' + name + '.old')
    for leftover in (staging, previous):
        if leftover.is_symlink() or leftover.is_file():
            leftover.unlink()
        elif leftover.exists():
            shutil.rmtree(leftover)
    staging.mkdir(mode=0o755)
    total, count = 0, 0
    with tarfile.open(archive_path, 'r:') as archive:
        members = []
        for member in archive:
            count += 1
            total += member.size
            parts = member.name.split('/')
            if count > max_entries or total > max_bytes or not (member.isdir() or member.isreg()) or \
               member.name.startswith('/') or '..' in parts or '' in parts or '.' in parts:
                raise MountError('the snapshot archive holds an unsupported entry: ' + member.name)
            members.append(member)
        archive.extractall(staging, members=members, filter='data')
    for directory, folders, files in os.walk(staging):
        os.chmod(directory, 0o755)
        for item in files:
            path = os.path.join(directory, item)
            meta = os.lstat(path)
            if not stat.S_ISREG(meta.st_mode):
                raise MountError('the snapshot holds an unsupported file: ' + path)
            os.chmod(path, 0o755 if meta.st_mode & 0o111 else 0o644)
    if target.exists() or target.is_symlink():
        os.replace(target, previous)
    os.replace(staging, target)
    if previous.exists():
        shutil.rmtree(previous)
    if record:
        # A launch names its snapshots itself; only an operator share enters mounts.json.
        record_entry(root, {'name': name, 'kind': 'snapshot', 'read_only': True})
    return {'files': sum(len(files) for _, _, files in os.walk(target)), 'bytes': total}


def read_private(path, limit=65536):
    """Read one file owned by this user (root on the Docker host), mode 0600 or tighter."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_mode & 0o077:
            raise MountError('the mounts file must be a regular file owned by this user, mode 0600: ' + str(path))
        raw = os.read(fd, limit + 1)
        if len(raw) > limit:
            raise MountError('the mounts file exceeds %d bytes' % limit)
        return raw
    finally:
        os.close(fd)


def load_entries(root):
    path = Path(root) / 'mounts.json'
    if not (path.exists() or path.is_symlink()):
        return []
    return parse_document(read_private(path))


def record_entry(root, entry):
    entries = [item for item in load_entries(root) if item['name'] != entry['name']] + [entry]
    parse_document(render_document(entries))
    write_private(Path(root) / 'mounts.json', render_document(entries))


def remove(root, name):
    """Remove one mount entry and, for a snapshot, its share directory."""
    root = Path(root)
    check_name(name)
    entries = load_entries(root)
    kept = [item for item in entries if item['name'] != name]
    if len(kept) != len(entries):
        write_private(root / 'mounts.json', render_document(kept))
    share = snapshot_source(root, name)
    if share.is_symlink():
        share.unlink()
    elif share.exists():
        shutil.rmtree(share)
    return len(kept) != len(entries)


def main(argv):
    if os.geteuid() != 0:
        raise MountError('the mount helper runs as root on the Docker host')
    if len(argv) == 1:
        lines = prepare(argv[0])
        sys.stdout.write(''.join(line + '\n' for line in lines))
        return 0
    if len(argv) == 2 and argv[0] == 'launch':
        # The launch runtime writes this root-owned list; it is validated again here.
        entries = parse_document(read_private(Path(argv[1]) / LAUNCH_MOUNTS))
        sys.stdout.write(''.join(line + '\n' for line in prepare(argv[1], entries)))
        return 0
    if len(argv) == 4 and argv[0] == 'install-snapshot':
        result = install_snapshot(argv[1], argv[2], argv[3])
        print(json.dumps(result, sort_keys=True))
        return 0
    if len(argv) == 3 and argv[0] == 'remove':
        print(json.dumps({'removed': remove(argv[1], argv[2])}))
        return 0
    raise MountError('usage: mounts.py ROOT | launch ROOT | install-snapshot ROOT NAME ARCHIVE | remove ROOT NAME')


if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, tarfile.TarError) as error:
        print('agentgate-mounts-error: ' + str(error), file=sys.stderr)
        sys.exit(1)
