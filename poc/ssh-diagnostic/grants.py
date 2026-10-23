#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Grant or revoke what the guarded agent may reach.

Every change is one locked, validated, atomic, and recorded edit of the
operator's policy. The native validator (pilot-network-diagnostic
network-info) that the runtime uses decides validity; a rejected policy is
never written. Exit codes are documented in README.md ("Exit codes").
"""
import argparse
import contextlib
import datetime
import difflib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import posixpath
import secrets
import shlex
import stat
import subprocess
import sys
import time

import mounts as mountlib

HERE = Path(__file__).resolve().parent
PRESETS_PATH = HERE / 'presets.json'
FULL_EXAMPLE = HERE / 'policy.full.example.json'
V1 = 'agentgate.network-poc.v1'
V2 = 'agentgate.poc.v2'
MAX_POLICY_BYTES = 16384
BACKUPS_KEPT = 20
LOG_KEPT = 200
WEB = {'http': ('tcp', 80), 'https': ('tcp', 443), 'quic': ('udp', 443)}
WEB_ORDER = ('http', 'https', 'quic')
DEFAULT_STATE = Path.home() / '.local/share/agentgate/poc'
DEFAULT_WAIT = 30
WRITABLE_MOUNT = '/var/lib/agentgate/workspace'

OK, FAILURE, USAGE, UNSAFE, REJECTED, NO_VALIDATOR, UPGRADE, BUSY, APPLY, NOT_IMPLEMENTED, \
    INCONSISTENT, NO_HISTORY, CONFLICT = range(13)
EXIT_CODES = {
    OK: 'success, including an unchanged no-op and a dry run that would apply',
    FAILURE: 'unexpected error',
    USAGE: 'invalid command line or argument value',
    UNSAFE: 'unsafe policy, state, or history file or directory (symlink, owner, or mode)',
    REJECTED: 'the policy validator rejected the result (its message is shown verbatim)',
    NO_VALIDATOR: 'no policy validator is available, or it failed to run',
    UPGRADE: 'the change needs a version two policy; rerun with --upgrade-to-v2',
    BUSY: 'another grant or appliance command, or a guarded command, holds the lock',
    APPLY: 'the appliance could not apply the change; the local policy is unchanged',
    NOT_IMPLEMENTED: 'the requested capability is not implemented (see README)',
    INCONSISTENT: 'the policy changed outside grant, or an interrupted change needs attention',
    NO_HISTORY: 'the requested history entry or backup is unavailable',
    CONFLICT: 'the request conflicts with the current policy (the message names the entry)',
}
# Changes that need the version two filesystem and process sections.
V2_ACTIONS = {'read', 'write', 'exec', 'deny', 'signal', 'anon-exec', 'mount', 'preset'}


class GrantError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


# ----------------------------------------------------------------------------
# Strict JSON


def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise GrantError(REJECTED, 'the policy repeats the JSON key "%s"' % key)
        out[key] = value
    return out


def _no_constant(value):
    raise GrantError(REJECTED, 'the policy contains the non-JSON number ' + value)


def parse_policy(raw):
    if len(raw) > MAX_POLICY_BYTES:
        raise GrantError(REJECTED, 'the policy exceeds %d bytes, the validator limit' % MAX_POLICY_BYTES)
    try:
        document = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique, parse_constant=_no_constant)
    except GrantError:
        raise
    except (UnicodeDecodeError, ValueError) as error:
        raise GrantError(REJECTED, 'the policy is not valid JSON: %s' % error) from None
    if not isinstance(document, dict):
        raise GrantError(REJECTED, 'the policy must be one JSON object')
    return document


def render(document):
    return (json.dumps(document, indent=2, ensure_ascii=False) + '\n').encode()


def clone(document):
    return json.loads(json.dumps(document))


# ----------------------------------------------------------------------------
# Validators: the same native network-info command the runtime runs.


class NativeValidator:
    def __init__(self, path):
        self.path = Path(path)

    def run(self, raw):
        try:
            return subprocess.run([str(self.path), 'network-info', '/dev/stdin'], input=raw,
                                  capture_output=True, timeout=20)
        except (OSError, subprocess.SubprocessError) as error:
            raise GrantError(NO_VALIDATOR, 'the policy validator %s could not run: %s' % (self.path, error)) from None

    def __call__(self, raw):
        result = self.run(raw)
        message = result.stderr.decode(errors='replace').strip()
        # The validator exits 1 for a rejected policy. Anything else (a crash, or a
        # Docker or exec failure) means the policy was never judged.
        if result.returncode == 1:
            raise GrantError(REJECTED, 'policy rejected by pilot-network-diagnostic network-info:\n' + message)
        if result.returncode != 0:
            raise GrantError(NO_VALIDATOR, 'the policy validator failed to run (exit %d): %s' %
                             (result.returncode, message))
        try:
            info = json.loads(result.stdout)
        except ValueError:
            info = None
        if not isinstance(info, dict) or not isinstance(info.get('digest'), str) or \
           not isinstance(info.get('document'), dict):
            raise GrantError(NO_VALIDATOR, 'the policy validator returned no digest and document')
        return info


class ContainerValidator(NativeValidator):
    """Run the instance's validator in the same bounded container appliance.py uses."""

    def __init__(self, image):
        self.image = image
        self.path = image

    def run(self, raw):
        args = ['docker', 'run', '--rm', '-i', '--network', 'none', '--read-only', '--cpus', '1',
                '--memory', '128m', '--pids-limit', '32', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges',
                '--user', str(os.getuid()) + ':' + str(os.getgid()),
                self.image, '/pilot-network-diagnostic', 'network-info', '/dev/stdin']
        try:
            return subprocess.run(args, input=raw, capture_output=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as error:
            raise GrantError(NO_VALIDATOR, 'the containerized policy validator could not run: %s' % error) from None


def trusted_executable(path):
    meta = os.stat(path)
    return stat.S_ISREG(meta.st_mode) and meta.st_uid in (0, os.getuid()) and not meta.st_mode & 0o022 \
        and os.access(path, os.X_OK)


def native_validator(explicit, near=None):
    candidate = explicit or os.environ.get('AGENTGATE_VALIDATOR')
    if not candidate and near is not None and (near / 'pilot-network-diagnostic').exists():
        candidate = near / 'pilot-network-diagnostic'
    if not candidate:
        return None
    try:
        if not trusted_executable(candidate):
            raise GrantError(UNSAFE, 'the validator %s must be an executable owned by you or root and not '
                                     'group- or world-writable' % candidate)
    except OSError as error:
        raise GrantError(NO_VALIDATOR, 'the validator %s is unavailable: %s' % (candidate, error)) from None
    return NativeValidator(candidate)


NO_VALIDATOR_HINT = ('no policy validator: pass --validator PATH or set AGENTGATE_VALIDATOR. Build one with:\n'
                     '  go build -o ./pilot-network-diagnostic ./cmd/pilot-network-diagnostic')


# ----------------------------------------------------------------------------
# Files: custody checks, locking, atomic replacement


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def check_private_directory(path, label, allow_root_owner=False):
    try:
        meta = os.lstat(path)
    except FileNotFoundError:
        raise GrantError(UNSAFE, '%s %s does not exist' % (label, path)) from None
    owners = (os.getuid(), 0) if allow_root_owner else (os.getuid(),)
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISDIR(meta.st_mode):
        raise GrantError(UNSAFE, '%s %s must be a real directory, not a symlink' % (label, path))
    if meta.st_uid not in owners:
        raise GrantError(UNSAFE, '%s %s must be owned by you' % (label, path))
    return meta


def check_no_symlinks(path, label):
    absolute = Path(os.path.abspath(path))
    if Path(os.path.realpath(absolute)) != absolute:
        raise GrantError(UNSAFE, '%s %s contains a symlink; use its real path %s' %
                         (label, path, os.path.realpath(absolute)))
    return absolute


def check_private_file(path, label):
    try:
        meta = os.lstat(path)
    except FileNotFoundError:
        raise GrantError(UNSAFE, '%s %s does not exist' % (label, path)) from None
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode):
        raise GrantError(UNSAFE, '%s %s must be a regular file, not a symlink' % (label, path))
    if meta.st_uid != os.getuid() or meta.st_mode & 0o077:
        raise GrantError(UNSAFE, '%s %s must be owned by you with mode 0600 (chmod 600 %s)' %
                         (label, path, shlex.quote(str(path))))
    return meta


def read_private(path, label, limit=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077:
            raise GrantError(UNSAFE, '%s %s must be owned by you with mode 0600' % (label, path))
        raw = b''
        while len(raw) <= limit:
            chunk = os.read(fd, limit + 1 - len(raw))
            if not chunk:
                break
            raw += chunk
        if len(raw) > limit:
            raise GrantError(UNSAFE, '%s %s exceeds %d bytes' % (label, path, limit))
        return raw
    finally:
        os.close(fd)


def ensure_history(path):
    """Create or check the private history directory (mode 0700, no symlink)."""
    try:
        os.mkdir(path, 0o700)
        os.chmod(path, 0o700)
    except FileExistsError:
        pass
    meta = check_private_directory(path, 'history directory')
    if meta.st_mode & 0o077:
        raise GrantError(UNSAFE, 'history directory %s must have mode 0700' % path)
    backups = Path(path) / 'backups'
    try:
        os.mkdir(backups, 0o700)
        os.chmod(backups, 0o700)
    except FileExistsError:
        pass
    meta = check_private_directory(backups, 'backup directory')
    if meta.st_mode & 0o077:
        raise GrantError(UNSAFE, 'backup directory %s must have mode 0700' % backups)


def atomic_write(path, raw, mode=0o600):
    """Write a sibling temporary file, fsync it, rename it over path, fsync the directory."""
    path = Path(path)
    temporary = path.parent / ('.%s.grant-%d-%s.tmp' % (path.name, os.getpid(), secrets.token_hex(4)))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    os.replace(temporary, path)
    fsync_directory(path.parent)


def remove_stale_temporaries(directory):
    """Remove temporaries an interrupted grant left in one directory.

    Only called under the lock that every grant writing there holds.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return
    for item in directory.glob('.*.grant-*.tmp'):
        meta = os.lstat(item)
        if stat.S_ISREG(meta.st_mode) and meta.st_uid == os.getuid():
            item.unlink()


@contextlib.contextmanager
def locked(path, wait):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid():
            raise GrantError(UNSAFE, 'lock file %s must be a regular file owned by you' % path)
        deadline = time.monotonic() + max(0, wait)
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise GrantError(BUSY, 'another grant or appliance command holds %s; retry when it finishes '
                                           'or raise --wait' % path) from None
                time.sleep(0.05)
        yield
    finally:
        os.close(fd)


# ----------------------------------------------------------------------------
# Policy edits


def within(parent, child):
    return child == parent or child.startswith(parent.rstrip('/') + '/')


def container_path(value):
    """A canonical absolute path inside the agent's container."""
    if not isinstance(value, str) or not value.startswith('/') or '\x00' in value or '\n' in value:
        raise GrantError(USAGE, 'a path inside the agent must be absolute: %r' % value)
    stripped = value.rstrip('/') or '/'
    parts = stripped.split('/')[1:]
    if stripped == '/' or any(part in ('', '.', '..') for part in parts) or posixpath.normpath(stripped) != stripped:
        raise GrantError(USAGE, 'use a canonical absolute path other than / (no ., .., or //): %r' % value)
    if len(stripped) > 160:
        raise GrantError(USAGE, 'a policy path is limited to 160 bytes: %r' % value)
    return stripped


def web_protocols(names):
    chosen = set()
    for name in names or ['all']:
        if name == 'all':
            chosen.update(WEB)
        elif name in WEB:
            chosen.add(name)
        else:
            raise GrantError(USAGE, 'web protocol must be http, https, quic, or all: %r' % name)
    return chosen


def current_web(document):
    names = set()
    for rule in document.get('web', {}).get('rules', []) or []:
        for name, (protocol, port) in WEB.items():
            if rule == {'protocol': protocol, 'port': port}:
                names.add(name)
    return names


def set_web(document, names):
    document.setdefault('web', {'destination': 'public-ipv4', 'rules': []})
    document['web']['rules'] = [{'protocol': WEB[name][0], 'port': WEB[name][1]} for name in WEB_ORDER if name in names]


def signal_name(value):
    name = value.upper()
    return name if name.startswith('SIG') else 'SIG' + name


def load_presets():
    raw = PRESETS_PATH.read_bytes()
    data = json.loads(raw, object_pairs_hook=_unique)
    if set(data) != {'version', 'presets'} or data['version'] != 'agentgate.poc-presets.v1':
        raise GrantError(FAILURE, 'presets.json has an unknown format')
    presets = {}
    for name, item in data['presets'].items():
        if set(item) == {'description', 'from_example'}:
            example = parse_policy((HERE / item['from_example']).read_bytes())
            item = {'description': item['description'], 'web': sorted(current_web(example), key=WEB_ORDER.index),
                    'filesystem': example['filesystem'], 'process': example['process']}
        if set(item) != {'description', 'web', 'filesystem', 'process'}:
            raise GrantError(FAILURE, 'preset %s has unknown fields' % name)
        web_protocols(item['web'])
        presets[name] = item
    return presets


def upgrade_document(document):
    """Version one to two: keep every network field, add the example's host controls."""
    example = parse_policy(FULL_EXAMPLE.read_bytes())
    out = {}
    for key, value in document.items():
        if key == 'duration_seconds':
            out['filesystem'] = clone(example['filesystem'])
            out['process'] = clone(example['process'])
        out[key] = value
    if 'filesystem' not in out:
        out['filesystem'] = clone(example['filesystem'])
        out['process'] = clone(example['process'])
    out['version'] = V2
    return out


# ----------------------------------------------------------------------------
# Contexts: a bare policy file, or an appliance state directory.


class Context:
    mode = 'file'

    def __init__(self, policy, history, lock, mounts_path, validator, wait):
        self.policy = Path(policy)
        self.history = Path(history)
        self.lock_path = Path(lock)
        self.mounts_path = Path(mounts_path) if mounts_path else None
        self.validator = validator
        self.wait = wait
        self.notices = []

    # -- reading
    def read(self):
        check_private_file(self.policy, 'policy file')
        raw = read_private(self.policy, 'policy file', MAX_POLICY_BYTES + 1)
        return raw, parse_policy(raw)

    def validate(self, raw):
        if self.validator is None:
            raise GrantError(NO_VALIDATOR, NO_VALIDATOR_HINT)
        return self.validator(raw)

    def mount_entries(self):
        if self.mounts_path is None or not (self.mounts_path.exists() or self.mounts_path.is_symlink()):
            return []
        check_private_file(self.mounts_path, 'mounts file')
        try:
            return mountlib.parse_document(read_private(self.mounts_path, 'mounts file'))
        except mountlib.MountError as error:
            raise GrantError(INCONSISTENT, str(error)) from None

    def mount_view(self):
        """(name, origin, read_only, kind) for display."""
        return [(item['name'], item.get('source', '(snapshot)'), item['read_only'], item['kind'])
                for item in self.mount_entries()]

    # -- change hooks
    def prepare(self):
        pass

    def before_replace(self, raw, info, current_info):
        pass

    def after_failure(self, error):
        pass

    def after_replace(self, raw, info, recovered=False):
        pass

    def describe_target(self):
        return 'policy=' + str(self.policy)

    # -- history
    def log_entries(self):
        path = self.history / 'log.jsonl'
        if not path.exists():
            return []
        raw = read_private(path, 'history log', 4 << 20)
        entries = []
        for line in raw.split(b'\n'):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except ValueError:
                self.notices.append('ignored a damaged history line')
                continue
            if isinstance(item, dict) and isinstance(item.get('seq'), int):
                entries.append(item)
        return entries

    def append_log(self, entry):
        path = self.history / 'log.jsonl'
        entries = self.log_entries() + [entry]
        if len(entries) > 2 * LOG_KEPT:
            atomic_write(path, b''.join(json.dumps(item, sort_keys=True).encode() + b'\n'
                                        for item in entries[-LOG_KEPT:]))
            return
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, json.dumps(entry, sort_keys=True).encode() + b'\n')
            os.fsync(fd)
        finally:
            os.close(fd)

    def next_seq(self):
        seqs = [item['seq'] for item in self.log_entries()]
        for item in (self.history / 'backups').glob('*.json'):
            head = item.name.split('-', 1)[0]
            if head.isdigit():
                seqs.append(int(head))
        return max(seqs, default=0) + 1

    def prune_backups(self):
        backups = sorted((self.history / 'backups').glob('*.json'))
        for item in backups[:-BACKUPS_KEPT]:
            item.unlink()

    # -- recovery
    def reconcile(self):
        """Finish or discard a change a crash interrupted. Runs under the lock."""
        # The lock covers these directories only; a --mounts file elsewhere is left alone.
        for directory in (self.policy.parent, self.history, self.history / 'backups'):
            remove_stale_temporaries(directory)
        intent_path = self.history / 'intent.json'
        if not intent_path.exists():
            return
        intent = json.loads(read_private(intent_path, 'change intent'))
        current = sha256(read_private(self.policy, 'policy file', MAX_POLICY_BYTES + 1))
        if current == intent['after_sha256']:
            info = self.validate(read_private(self.policy, 'policy file', MAX_POLICY_BYTES + 1))
            self.after_replace(None, info, recovered=True)
            entry = dict(intent, recovered=True)
            self.append_log(entry)
            self.notices.append('completed change %d (%s) that an interruption left unrecorded' %
                                (intent['seq'], intent['action']))
        elif current == intent['before_sha256']:
            self.discard_interrupted(intent)
            self.notices.append('discarded interrupted change %d (%s); the policy is unchanged' %
                                (intent['seq'], intent['action']))
        else:
            raise GrantError(INCONSISTENT, 'the policy changed outside grant after change %d was interrupted; '
                                           'inspect %s and the backups, then remove the intent file' %
                             (intent['seq'], intent_path))
        intent_path.unlink()
        fsync_directory(self.history)

    def discard_interrupted(self, intent):
        pass


class FileContext(Context):
    def __init__(self, policy, mounts_path, validator_path, wait):
        policy = check_no_symlinks(policy, 'policy file')
        meta = check_private_directory(policy.parent, 'policy directory', allow_root_owner=True)
        if meta.st_mode & 0o022:
            raise GrantError(UNSAFE, 'policy directory %s must not be group- or world-writable' % policy.parent)
        check_private_file(policy, 'policy file')
        history = policy.parent / (policy.name + '.grants')
        mounts_path = check_no_symlinks(mounts_path, 'mounts file') if mounts_path else policy.parent / 'mounts.json'
        validator = native_validator(validator_path, policy.parent)
        # One lock per directory: policies in one directory share its mounts.json.
        super().__init__(policy, history, policy.parent / '.agentgate-grant.lock', mounts_path, validator, wait)

    def instance_paths(self):
        return (str(self.policy.parent), str(self.history))


class ApplianceContext(Context):
    mode = 'appliance'

    def __init__(self, state, validator_path, wait, binding=None, held_lock=False):
        import appliance_common
        try:
            state = appliance_common.state_directory(state, create=False)
        except FileNotFoundError:
            raise GrantError(UNSAFE, 'no appliance state at %s; start the appliance first, or edit a file '
                                     'directly with --policy FILE' % state) from None
        except ValueError as error:
            raise GrantError(UNSAFE, str(error)) from None
        self.state = state
        self.binding = binding
        self.held_lock = held_lock
        validator = native_validator(validator_path)
        super().__init__(state / 'policy.json', state / 'grants', state / 'control.lock', None, validator, wait)
        self.applied = False
        self.load_binding()

    def load_binding(self):
        if self.binding is None:
            import appliance_common
            try:
                self.binding = appliance_common.load(self.state)
            except ValueError as error:
                raise GrantError(UNSAFE, str(error)) from None
        if self.validator is None and self.binding.get('images', {}).get('artifacts'):
            self.validator = ContainerValidator(self.binding['images']['artifacts'])
        return self.binding

    def shares(self):
        path = self.state / 'shares.json'
        if not path.exists():
            return {}
        return json.loads(read_private(path, 'share record'))

    def mount_entries(self):
        return [{'name': name, 'kind': 'snapshot', 'read_only': True} for name in sorted(self.shares())]

    def mount_view(self):
        return [(name, item['source'] + ' (snapshot ' + item['imported'] + ')', True, 'snapshot')
                for name, item in sorted(self.shares().items())]

    def running(self):
        import appliance_common
        try:
            item = appliance_common.inspect_owned(self.load_binding())
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
            raise GrantError(APPLY, 'cannot inspect the appliance container: %s' % error) from None
        return bool(item and item['State']['Running'])

    def push(self, raw):
        """Install exactly these bytes on the running guest."""
        import appliance_guest
        pending = self.state / 'policy.pending.json'
        atomic_write(pending, raw)
        try:
            appliance_guest.install_policy(self.state, self.binding, pending)
        except appliance_guest.GuestBusy as error:
            raise GrantError(BUSY, str(error)) from None
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
            raise GrantError(APPLY, 'the appliance did not accept the policy: %s' % error) from None
        finally:
            pending.unlink(missing_ok=True)

    def prepare(self):
        binding = self.load_binding()
        current = read_private(self.policy, 'policy file', MAX_POLICY_BYTES + 1)
        if sha256(current) != binding.get('policy_sha256'):
            raise GrantError(INCONSISTENT, 'state policy.json differs from the applied binding; it was edited '
                                           'outside grant. Restore it, or apply a file with appliance.py policy')

    def after_failure(self, error):
        if isinstance(error, GrantError) and error.code == APPLY:
            self.discard_interrupted(None)

    def before_replace(self, raw, info, current_info):
        if info['document'].get('taskboard') != current_info['document'].get('taskboard'):
            raise GrantError(CONFLICT, 'taskboard fields are bound to this instance; use a new state directory')
        self.applied = False
        if self.running():
            self.push(raw)
            self.applied = True

    def after_replace(self, raw, info, recovered=False):
        import appliance_common
        binding = self.load_binding()
        raw = read_private(self.policy, 'policy file', MAX_POLICY_BYTES + 1)
        binding['policy_sha256'] = sha256(raw)
        binding['policy_digest'] = info['digest']
        if self.applied and not recovered:
            binding.pop('policy_pending', None)
        else:
            binding['policy_pending'] = True
        appliance_common.write(self.state / 'binding.json', json.dumps(binding, sort_keys=True).encode())

    def discard_interrupted(self, intent):
        # The guest may already hold the discarded bytes; resynchronize before use.
        import appliance_common
        binding = self.load_binding()
        binding['policy_pending'] = True
        appliance_common.write(self.state / 'binding.json', json.dumps(binding, sort_keys=True).encode())

    def sync(self, quiet=False):
        binding = self.load_binding()
        if not self.running():
            if binding.get('policy_pending'):
                self.notices.append('the appliance is stopped; the policy applies at the next start')
            return False
        raw = read_private(self.policy, 'policy file', MAX_POLICY_BYTES + 1)
        info = self.validate(raw)
        self.push(raw)
        import appliance_common
        binding['policy_sha256'] = sha256(raw)
        binding['policy_digest'] = info['digest']
        binding.pop('policy_pending', None)
        appliance_common.write(self.state / 'binding.json', json.dumps(binding, sort_keys=True).encode())
        if not quiet:
            self.notices.append('the appliance now uses policy digest ' + info['digest'])
        return True

    def describe_target(self):
        if self.applied:
            return 'appliance=applied applies=next_command'
        return 'appliance=pending applies=next_start'

    def instance_paths(self):
        return (str(self.state),)


# ----------------------------------------------------------------------------
# The change engine


class Change:
    """One requested edit: a new document or exact bytes, and what it did."""

    def __init__(self, action, argv, document=None, raw=None, message=''):
        self.action = action
        self.argv = argv
        self.document = document
        self.raw = raw
        self.message = message


def check_mount_coherence(ctx, document):
    entries = ctx.mount_entries()
    try:
        mountlib.check_policy_coherence(entries, document.get('filesystem'))
    except mountlib.MountError as error:
        raise GrantError(CONFLICT, str(error)) from None


def commit(ctx, change, current_raw, current_document, current_info, dry_run=False, out=print):
    new_raw = change.raw if change.raw is not None else render(change.document)
    new_document = parse_policy(new_raw)
    if new_document == current_document:
        if change.message:
            out(change.message)
        out('unchanged=true digest=%s' % current_info['digest'])
        return OK, current_info
    check_mount_coherence(ctx, new_document)
    if dry_run:
        diff = difflib.unified_diff(current_raw.decode().splitlines(True), new_raw.decode().splitlines(True),
                                    'a/' + ctx.policy.name, 'b/' + ctx.policy.name)
        out(''.join(diff).rstrip('\n'))
        info = ctx.validate(new_raw)
        out('dry_run=true valid=true digest=%s' % info['digest'])
        return OK, info
    info = ctx.validate(new_raw)
    seq = ctx.next_seq()
    stamp = now_utc()
    backup = '%06d-%s.json' % (seq, stamp.strftime('%Y%m%dT%H%M%SZ'))
    atomic_write(ctx.history / 'backups' / backup, current_raw)
    intent = {'seq': seq, 'time': stamp.strftime('%Y-%m-%dT%H:%M:%SZ'), 'action': change.action,
              'argv': change.argv, 'before_sha256': sha256(current_raw), 'after_sha256': sha256(new_raw),
              'before_digest': current_info['digest'], 'after_digest': info['digest'], 'backup': backup}
    atomic_write(ctx.history / 'intent.json', json.dumps(intent, sort_keys=True).encode())
    try:
        ctx.before_replace(new_raw, info, current_info)
    except BaseException as error:
        # Nothing changed locally. A failed transfer may still have reached the guest.
        (ctx.history / 'intent.json').unlink(missing_ok=True)
        (ctx.history / 'backups' / backup).unlink(missing_ok=True)
        ctx.after_failure(error)
        raise
    mode = stat.S_IMODE(os.lstat(ctx.policy).st_mode) & 0o600 or 0o600
    atomic_write(ctx.policy, new_raw, mode)
    ctx.after_replace(new_raw, info)
    ctx.append_log(intent)
    (ctx.history / 'intent.json').unlink()
    fsync_directory(ctx.history)
    ctx.prune_backups()
    if change.message:
        out(change.message)
    out('grant_applied=true seq=%d digest=%s %s' % (seq, info['digest'], ctx.describe_target()))
    return OK, info


# ----------------------------------------------------------------------------
# Operations: each returns a Change built from the current document.


def needs_v2(ctx, document, args, action):
    if document.get('version') == V2:
        return document
    if document.get('version') != V1:
        raise GrantError(REJECTED, 'unknown policy version %r' % document.get('version'))
    if getattr(args, 'upgrade_to_v2', False):
        ctx.notices.append('upgraded the policy to version two; the network section is unchanged')
        return upgrade_document(document)
    explanation = ('"%s" needs a version two policy (filesystem and process controls). Upgrading keeps every '
                   'network field and adds the conservative host controls of policy.full.example.json. The BPF '
                   'LSM filesystem and process components have not been exercised on a BPF LSM kernel; the first '
                   'command may fail closed.' % action)
    if getattr(args, 'interactive', False) and sys.stdin.isatty() and not getattr(args, 'dry_run', False):
        answer = input(explanation + '\nUpgrade to version two now? [y/N]: ').strip().lower()
        if answer in ('y', 'yes'):
            ctx.notices.append('upgraded the policy to version two; the network section is unchanged')
            return upgrade_document(document)
        raise GrantError(UPGRADE, 'not upgraded; nothing changed')
    raise GrantError(UPGRADE, explanation + ' Rerun with --upgrade-to-v2.')


def covering(entries, path):
    for entry in entries:
        if within(entry, path):
            return entry
    return None


def op_web(ctx, document, args, allow):
    names = web_protocols(args.protocols)
    document = clone(document)
    present = current_web(document)
    wanted = present | names if allow else present - names
    set_web(document, wanted)
    verb = 'allowed' if allow else 'denied'
    label = ', '.join(name for name in WEB_ORDER if name in names)
    return Change('allow-web' if allow else 'deny-web', [args.command] + list(args.protocols or []), document,
                  message='public web: %s %s' % (verb, label))


def op_dns(ctx, document, args):
    document = clone(document)
    resolvers = []
    for value in args.resolvers:
        if value not in resolvers:
            resolvers.append(value)
    document['dns']['resolvers'] = resolvers
    return Change('dns', ['dns'] + args.resolvers, document, message='dns resolvers: ' + ', '.join(resolvers))


def op_path(ctx, document, args, kind):
    path = container_path(args.path)
    document = needs_v2(ctx, clone(document), args, kind)
    fs = document['filesystem']
    writable = [fs['workspace']] + fs['scratch']
    rw_mounts = [mountlib.mount_path(item['name']) for item in ctx.mount_entries() if not item['read_only']]
    denied = covering(fs['deny'], path)
    if kind != 'deny' and denied:
        raise GrantError(CONFLICT, '%s is denied by the deny entry %s; run "grant revoke deny %s" first' %
                         (path, denied, denied))
    message = ''
    if kind == 'read':
        holder = covering(fs['read_only'] + fs['execute'] + writable, path)
        if holder:
            message = '%s is already readable through %s' % (path, holder)
        else:
            fs['read_only'].append(path)
            message = 'read-only: added ' + path
    elif kind == 'write':
        holder = covering(writable, path)
        clash = next((tree for tree in fs['execute'] if within(tree, path) or within(path, tree)), None)
        if holder:
            message = '%s is already writable through %s' % (path, holder)
        elif clash:
            raise GrantError(CONFLICT, '%s overlaps the executable tree %s; writable trees never run code' % (path, clash))
        else:
            fs['scratch'].append(path)
            message = 'writable (never executable): added ' + path
            mounted = [WRITABLE_MOUNT, '/tmp'] + rw_mounts
            if not any(within(tree, path) for tree in mounted):
                ctx.notices.append('the container root is read-only: %s is writable only below a writable mount '
                                   '(the workspace, /tmp, or a read-write host folder)' % path)
    elif kind == 'exec':
        clash = next((tree for tree in writable + rw_mounts if within(tree, path) or within(path, tree)), None)
        holder = covering(fs['execute'], path)
        if clash:
            raise GrantError(CONFLICT, '%s overlaps the writable tree %s; writable trees never run code' % (path, clash))
        if holder:
            message = '%s is already executable through %s' % (path, holder)
        else:
            fs['execute'].append(path)
            message = 'executable: added ' + path
    elif kind == 'deny':
        holder = covering(fs['deny'], path)
        if holder:
            message = '%s is already denied through %s' % (path, holder)
        else:
            fs['deny'].append(path)
            message = 'denied: added ' + path
    return Change(kind, [kind, path], document, message=message)


def op_signal(ctx, document, args):
    document = needs_v2(ctx, clone(document), args, 'signal')
    signals = document['process']['signals']
    added = []
    for value in args.signals:
        name = signal_name(value)
        if name not in signals:
            signals.append(name)
            added.append(name)
    return Change('signal', ['signal'] + args.signals, document,
                  message=('signals: added ' + ', '.join(added)) if added else 'signals: already allowed')


def op_anon_exec(ctx, document, args, enable=True):
    if not enable and document.get('version') != V2:
        return Change('revoke', ['revoke', 'anon-exec'], clone(document), message='anonymous execute: not granted')
    document = needs_v2(ctx, clone(document), args, 'anon-exec')
    document['filesystem']['memory']['anonymous_execute'] = enable
    return Change('anon-exec' if enable else 'revoke', ['anon-exec'] if enable else ['revoke', 'anon-exec'],
                  document, message='executable anonymous memory: ' + ('on (weakens W^X)' if enable else 'off'))


def apply_mount_entries(ctx, document):
    """Re-add the access entry each existing mount had, after a preset."""
    fs = document['filesystem']
    for item in ctx.mount_entries():
        path = mountlib.mount_path(item['name'])
        target = fs['read_only'] if item['read_only'] else fs['scratch']
        if path not in target:
            target.append(path)
    return document


def op_preset(ctx, document, args):
    presets = load_presets()
    if args.name not in presets:
        raise GrantError(USAGE, 'unknown preset %r; choose one of: %s' % (args.name, ', '.join(presets)))
    preset = presets[args.name]
    document = needs_v2(ctx, clone(document), args, 'preset')
    document['filesystem'] = clone(preset['filesystem'])
    document['process'] = clone(preset['process'])
    set_web(document, set(preset['web']))
    apply_mount_entries(ctx, document)
    return Change('preset', ['preset', args.name], document, message='preset: ' + args.name)


def op_revoke(ctx, document, args):
    kind, values = args.kind, args.values
    document = clone(document)
    if kind == 'web':
        args.protocols = values
        change = op_web(ctx, document, args, allow=False)
        change.action, change.argv = 'revoke', ['revoke', 'web'] + values
        return change
    if kind == 'anon-exec':
        return op_anon_exec(ctx, document, args, enable=False)
    if not values:
        raise GrantError(USAGE, 'revoke %s needs a value' % kind)
    if kind == 'dns':
        kept = [ip for ip in document['dns']['resolvers'] if ip not in values]
        document['dns']['resolvers'] = kept
        return Change('revoke', ['revoke', 'dns'] + values, document, message='dns resolvers: ' + ', '.join(kept))
    if kind == 'signal':
        if document.get('version') != V2:
            return Change('revoke', ['revoke', kind] + values, document, message='signals: not granted')
        names = [signal_name(value) for value in values]
        document['process']['signals'] = [name for name in document['process']['signals'] if name not in names]
        return Change('revoke', ['revoke', kind] + values, document, message='signals: removed ' + ', '.join(names))
    if len(values) != 1:
        raise GrantError(USAGE, 'revoke %s takes exactly one path' % kind)
    path = container_path(values[0])
    if document.get('version') != V2:
        return Change('revoke', ['revoke', kind, path], document, message='%s: not granted (version one policy)' % kind)
    fs = document['filesystem']
    lists = {'read': ['read_only'], 'write': ['scratch'], 'exec': ['execute'], 'deny': ['deny']}[kind]
    if kind == 'write' and path == fs['workspace']:
        raise GrantError(CONFLICT, 'the workspace is required; use "grant deny PATH" to hide a subtree of it')
    removed = False
    for name in lists:
        if path in fs[name]:
            fs[name].remove(path)
            removed = True
    if removed:
        return Change('revoke', ['revoke', kind, path], document, message='%s: removed %s' % (kind, path))
    if kind != 'deny':
        holders = {'read': fs['read_only'] + fs['execute'] + [fs['workspace']] + fs['scratch'],
                   'write': [fs['workspace']] + fs['scratch'], 'exec': fs['execute']}[kind]
        holder = covering(holders, path)
        if holder:
            raise GrantError(CONFLICT, '%s is not a separate entry; it stays %s through %s. Revoke %s, or add '
                                       '"grant deny %s"' % (path, {'read': 'readable', 'write': 'writable',
                                                                   'exec': 'executable'}[kind], holder, holder, path))
    return Change('revoke', ['revoke', kind, path], document, message='%s: %s was not granted' % (kind, path))


# ----------------------------------------------------------------------------
# Mounts


def mount_source(value, ctx):
    source = os.path.abspath(os.path.expanduser(value))
    if os.path.realpath(source) != source:
        raise GrantError(UNSAFE, '%s contains a symlink; use its real path %s' % (value, os.path.realpath(source)))
    if not os.path.isdir(source):
        raise GrantError(USAGE, '%s is not a directory' % value)
    home = os.environ.get('HOME') or str(Path.home())
    try:
        mountlib.check_source_rules(source, forbidden=ctx.instance_paths(), home=home)
    except mountlib.MountError as error:
        raise GrantError(UNSAFE, str(error)) from None
    return source


def mount_name(args, source):
    try:
        return mountlib.name_from_path(args.name) if args.name else mountlib.default_name(source)
    except mountlib.MountError as error:
        raise GrantError(USAGE, str(error)) from None


def access_warning(source, read_only):
    meta = os.stat(source)
    if read_only and (meta.st_mode & 0o005) != 0o005:
        return ('warning: %s is not readable and searchable by others; the agent runs as uid 65534 and '
                'will see permission errors' % source)
    if not read_only and meta.st_uid != 65534 and (meta.st_mode & 0o007) != 0o007:
        return 'warning: %s is not writable by uid 65534, the agent user' % source
    return None


def mount_policy(ctx, document, args, path, read_only):
    document = needs_v2(ctx, clone(document), args, 'mount')
    fs = document['filesystem']
    if not read_only:
        clash = next((tree for tree in fs['execute'] if within(tree, path) or within(path, tree)), None)
        if clash:
            raise GrantError(CONFLICT, 'a writable mount at %s overlaps the executable tree %s' % (path, clash))
    other = fs['scratch'] if read_only else fs['read_only']
    if path in other:
        other.remove(path)
    target = fs['read_only'] if read_only else fs['scratch']
    if path not in target:
        target.append(path)
    return document


def unmount_policy(document, path):
    document = clone(document)
    if document.get('version') == V2:
        for name in ('read_only', 'scratch', 'execute'):
            if path in document['filesystem'][name]:
                document['filesystem'][name].remove(path)
    return document


# ----------------------------------------------------------------------------
# Display


def summarize(ctx, info):
    document = info['document']
    fs = document.get('filesystem')
    web = current_web(document)
    lines = ['policy: %s' % ctx.policy,
             'version: %s%s' % (document['version'], '' if fs is None else
                                ' (filesystem and process controls: implemented, not yet exercised on a BPF LSM kernel)'),
             'digest: %s' % info['digest'],
             'network (everything else denied, IPv6 denied):',
             '  dns resolvers: %s (udp and tcp port 53)' % ', '.join(document['dns']['resolvers']),
             '  public IPv4 web: %s' % (', '.join('%s (%s/%d)' % (name, WEB[name][0], WEB[name][1])
                                                  for name in WEB_ORDER if name in web) or 'none'),
             '  taskboard: %s tcp/%d task %d (fixed for this instance)' % (
                 document['taskboard']['address'], document['taskboard']['port'], document['taskboard']['task_id']),
             '  domains: not enforced; rules match addresses and ports, not hostnames']
    if fs is None:
        lines += ['filesystem: not controlled by a version one policy (read-only root, the workspace volume, and',
                  '  Unix permissions apply). Any read/write/exec/deny/mount grant offers --upgrade-to-v2.',
                  'processes: not controlled by a version one policy']
    else:
        lines += ['filesystem (everything else denied):',
                  '  workspace (read/write, never executable): %s' % fs['workspace'],
                  '  writable scratch (never executable): %s' % (', '.join(fs['scratch']) or 'none'),
                  '  read-only: %s' % (', '.join(fs['read_only']) or 'none'),
                  '  executable (read and run): %s' % (', '.join(fs['execute']) or 'none'),
                  '  devices: %s' % (', '.join(fs['devices']) or 'none'),
                  '  denied: %s' % (', '.join(fs['deny']) or 'none'),
                  '  executable anonymous memory: %s' % ('on' if fs['memory']['anonymous_execute'] else 'off'),
                  'processes:',
                  '  signals (own process tree only): %s' % (', '.join(document['process']['signals']) or 'none'),
                  '  tracing: always denied']
    view = ctx.mount_view()
    lines.append('host folders: %s' % ('none' if not view else ''))
    for name, origin, read_only, kind in view:
        path = mountlib.mount_path(name)
        granted = fs is not None and (path in fs['read_only'] if read_only else path in fs['scratch'])
        lines.append('  %s -> %s (%s, %s)%s' % (origin, path, 'read-only' if read_only else 'read-write', kind,
                                                '' if granted else ' [no access entry: inaccessible]'))
    lines.append('command cutoff: %d seconds' % document['duration_seconds'])
    if ctx.mode == 'appliance' and ctx.load_binding().get('policy_pending'):
        lines.append('appliance: a policy change is pending; it applies at the next start or "grant sync"')
    return '\n'.join(line.rstrip() for line in lines)


def show_json(ctx, info):
    return json.dumps({'policy': str(ctx.policy), 'digest': info['digest'], 'document': info['document'],
                       'host_folders': [{'name': name, 'origin': origin, 'read_only': read_only, 'kind': kind,
                                         'path': mountlib.mount_path(name)}
                                        for name, origin, read_only, kind in ctx.mount_view()]},
                      indent=2, sort_keys=True)


def presets_text():
    lines = []
    for name, preset in load_presets().items():
        fs = preset['filesystem']
        lines += ['%s: %s' % (name, preset['description']),
                  '  web: %s; writable: %s; read-only: %s; executable: %s' % (
                      ', '.join(preset['web']) or 'none', ', '.join([fs['workspace']] + fs['scratch']),
                      ', '.join(fs['read_only']) or 'none', ', '.join(fs['execute']) or 'none')]
    lines.append('Presets keep DNS resolvers, the taskboard, and existing host folder access entries.')
    return '\n'.join(lines)


# ----------------------------------------------------------------------------
# Command line


def parser(prog):
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--state', default=argparse.SUPPRESS,
                        help='appliance state directory (default ~/.local/share/agentgate/poc)')
    common.add_argument('--policy', default=argparse.SUPPRESS, help='edit this policy file instead of an appliance')
    common.add_argument('--mounts', default=argparse.SUPPRESS,
                        help='mounts file for --policy mode (default mounts.json next to the policy)')
    common.add_argument('--validator', default=argparse.SUPPRESS,
                        help='pilot-network-diagnostic binary that validates policies')
    common.add_argument('--wait', type=float, default=argparse.SUPPRESS,
                        help='seconds to wait for the lock (default %d)' % DEFAULT_WAIT)
    common.add_argument('--dry-run', action='store_true', default=argparse.SUPPRESS,
                        help='print the unified diff and validation result; write nothing')
    common.add_argument('--upgrade-to-v2', action='store_true', default=argparse.SUPPRESS,
                        help='allow upgrading a version one policy to version two')
    common.add_argument('--json', action='store_true', default=argparse.SUPPRESS, help='machine-readable show')
    top = argparse.ArgumentParser(prog=prog, parents=[common], description=__doc__.split('\n')[0],
                                  epilog='Exit codes: ' + '; '.join('%d %s' % item for item in EXIT_CODES.items()))
    commands = top.add_subparsers(dest='command', metavar='COMMAND')
    commands.required = True

    def add(name, text):
        return commands.add_parser(name, parents=[common], help=text, description=text)
    add('show', 'summarize what the agent can access now')
    add('presets', 'list the available presets')
    add('history', 'list recorded changes')
    for name, text in (('allow-web', 'allow public IPv4 web protocols'), ('deny-web', 'deny public IPv4 web protocols')):
        item = add(name, text + ' (http=tcp/80, https=tcp/443, quic=udp/443; default all)')
        item.add_argument('protocols', nargs='*', metavar='PROTOCOL')
    add('dns', 'set the one to three public IPv4 DNS resolvers').add_argument('resolvers', nargs='+', metavar='IP')
    for name, text in (('read', 'allow reading a tree'), ('write', 'allow writing a tree (never executable)'),
                       ('exec', 'allow reading and running programs in a tree'),
                       ('deny', 'deny every operation in a tree, overriding allowances')):
        add(name, text).add_argument('path', metavar='PATH')
    add('signal', 'allow sending signals within the command tree').add_argument('signals', nargs='+', metavar='NAME')
    add('anon-exec', 'allow executable anonymous memory (JIT, libffi closures)')
    mount = add('mount', 'share a host folder at /var/lib/agentgate/mounts/NAME')
    mount.add_argument('source', metavar='HOST_PATH')
    mount.add_argument('--as', dest='name', metavar='NAME', help='NAME or /var/lib/agentgate/mounts/NAME')
    mode = mount.add_mutually_exclusive_group()
    mode.add_argument('--read-only', dest='read_write', action='store_false', default=False)
    mode.add_argument('--read-write', dest='read_write', action='store_true')
    add('unmount', 'remove a host folder and its access entry').add_argument('name', metavar='NAME')
    revoke = add('revoke', 'undo a grant: web, dns, read, write, exec, deny, signal, anon-exec, or mount')
    revoke.add_argument('kind', choices=('web', 'dns', 'read', 'write', 'exec', 'deny', 'signal', 'anon-exec', 'mount'))
    revoke.add_argument('values', nargs='*', metavar='VALUE')
    add('preset', 'apply a preset').add_argument('name', metavar='NAME')
    add('rollback', 'restore the policy as it was before the last N recorded changes').add_argument(
        'steps', nargs='?', type=int, default=1, metavar='N')
    add('sync', 'apply the local policy to the running appliance')
    add('allow-domain', 'not implemented: hostname allowlists (see README)').add_argument('domain', metavar='NAME')
    add('wizard', 'answer a few questions; prints and runs the equivalent commands')
    return top


def option(args, name, default=None):
    return getattr(args, name, default)


def make_context(args, binding=None, held_lock=False):
    wait = option(args, 'wait', DEFAULT_WAIT)
    if option(args, 'policy') and option(args, 'state'):
        raise GrantError(USAGE, 'use either --policy FILE or --state DIR, not both')
    if option(args, 'policy'):
        return FileContext(args.policy, option(args, 'mounts'), option(args, 'validator'), wait)
    if option(args, 'mounts'):
        raise GrantError(USAGE, '--mounts applies only with --policy FILE')
    return ApplianceContext(option(args, 'state', str(DEFAULT_STATE)), option(args, 'validator'), wait,
                            binding, held_lock)


@contextlib.contextmanager
def mutation(ctx, dry_run=False):
    """Hold the lock, recover an interrupted change, and check custody.

    A dry run writes nothing: it neither creates history nor recovers.
    """
    if dry_run:
        if (ctx.history / 'intent.json').exists():
            ctx.notices.append('an interrupted change is recorded; the next real change finishes or discards it')
        ctx.prepare()
        yield
        return
    ensure_history(ctx.history)
    lock = contextlib.nullcontext() if getattr(ctx, 'held_lock', False) else locked(ctx.lock_path, ctx.wait)
    with lock:
        ctx.reconcile()
        ctx.prepare()
        yield


def emit_notices(ctx, out):
    for notice in ctx.notices:
        out('note: ' + notice)
    ctx.notices = []


def current_state(ctx):
    raw, document = ctx.read()
    try:
        info = ctx.validate(raw)
    except GrantError as error:
        if error.code == REJECTED:
            raise GrantError(REJECTED, 'the current policy is invalid; fix it or run "grant rollback":\n' +
                             str(error)) from None
        raise
    return raw, document, info


def run_change(ctx, args, build, out):
    with mutation(ctx, option(args, 'dry_run', False)):
        raw, document, info = current_state(ctx)
        change = build(document)
        emit_notices(ctx, out)
        code, _ = commit(ctx, change, raw, document, info, option(args, 'dry_run', False), out)
        if ctx.mode == 'appliance' and not option(args, 'dry_run', False) and \
           ctx.load_binding().get('policy_pending') and ctx.running():
            ctx.sync()
        emit_notices(ctx, out)
        return code


def do_rollback(ctx, args, out):
    if args.steps < 1:
        raise GrantError(USAGE, 'rollback N needs N of 1 or more')
    with mutation(ctx, option(args, 'dry_run', False)):
        raw, document = ctx.read()
        try:
            info = ctx.validate(raw)
        except GrantError as error:
            if error.code != REJECTED:
                raise
            info = {'digest': '(invalid)', 'document': document}
        entries = ctx.log_entries()
        if args.steps > len(entries):
            raise GrantError(NO_HISTORY, 'only %d recorded change(s) to roll back' % len(entries))
        entry = entries[-args.steps]
        path = ctx.history / 'backups' / entry.get('backup', '')
        if not entry.get('backup') or '/' in entry['backup'] or not path.exists():
            raise GrantError(NO_HISTORY, 'the backup for change %d was pruned (the last %d are kept)' %
                             (entry['seq'], BACKUPS_KEPT))
        restored = read_private(path, 'backup', MAX_POLICY_BYTES + 1)
        if sha256(restored) != entry['before_sha256']:
            raise GrantError(NO_HISTORY, 'the backup for change %d is damaged' % entry['seq'])
        change = Change('rollback', ['rollback', str(args.steps)], raw=restored,
                        message='rollback: restored the policy from before change %d (%s)' % (entry['seq'], entry['action']))
        code, new_info = commit(ctx, change, raw, document, info, option(args, 'dry_run', False), out)
        for name, _, read_only, _ in ctx.mount_view():
            fs = new_info['document'].get('filesystem')
            path = mountlib.mount_path(name)
            if fs is None or path not in (fs['read_only'] if read_only else fs['scratch']):
                out('note: host folder %s has no access entry in the restored policy; it is inaccessible' % path)
        emit_notices(ctx, out)
        return code


def do_mount(ctx, args, out):
    read_only = not args.read_write
    source = mount_source(args.source, ctx)
    name = mount_name(args, source)
    path = mountlib.mount_path(name)
    if ctx.mode == 'appliance':
        if not read_only:
            raise GrantError(NOT_IMPLEMENTED, 'read-write host folders are not available with the appliance: the '
                                              'agent runs inside a VM that cannot write back to this machine. Share '
                                              'it read-only (a snapshot), or exchange files through the workspace.')
        return mount_snapshot(ctx, args, source, name, out)
    try:
        mountlib.check_bind_source(source, forbidden=ctx.instance_paths(), home=os.environ.get('HOME'))
        mountlib.check_live_directory(source)
    except mountlib.MountError as error:
        raise GrantError(UNSAFE, str(error)) from None
    with mutation(ctx, option(args, 'dry_run', False)):
        raw, document, info = current_state(ctx)
        entries = ctx.mount_entries()
        entry = {'name': name, 'kind': 'bind', 'source': source, 'read_only': read_only}
        existing = next((item for item in entries if item['name'] == name), None)
        if existing and existing != entry:
            raise GrantError(CONFLICT, '%s is already mounted from %s; run "grant unmount %s" first' %
                             (path, existing.get('source', '(snapshot)'), name))
        if not existing:
            if len(entries) >= mountlib.MAX_MOUNTS:
                raise GrantError(CONFLICT, 'at most %d host folders can be mounted' % mountlib.MAX_MOUNTS)
            clash = next((item for item in entries if item['kind'] == 'bind' and mountlib.overlaps(item['source'], source)), None)
            if clash:
                raise GrantError(CONFLICT, '%s overlaps the mounted folder %s (%s)' % (source, clash['source'], clash['name']))
        new_document = mount_policy(ctx, document, args, path, read_only)
        emit_notices(ctx, out)
        change = Change('mount', ['mount', source, '--as', name, '--read-only' if read_only else '--read-write'],
                        new_document, message='host folder: %s -> %s (%s)' % (
                            source, path, 'read-only' if read_only else 'read-write, never executable'))
        mounts_raw = mountlib.render_document([item for item in entries if item['name'] != name] + [entry])
        if option(args, 'dry_run', False):
            commit(ctx, change, raw, document, info, True, out)
            out('mounts file %s would list: %s' % (ctx.mounts_path, json.dumps(entry, sort_keys=True)))
            return OK
        # The access entry lands first: a crash leaves an entry for an absent mount, never the reverse.
        with mounts_mutation_guard(ctx, mounts_raw, document, new_document):
            code, _ = commit(ctx, change, raw, document, info, False, out)
        warning = access_warning(source, read_only)
        if warning:
            out(warning)
        out('host folder %s applies to the next command target' % path)
        return code


@contextlib.contextmanager
def mounts_mutation_guard(ctx, mounts_raw, document, new_document):
    """Write the mounts file after the policy commit and check them together."""
    try:
        mountlib.check_policy_coherence(mountlib.parse_document(mounts_raw), new_document.get('filesystem'))
    except mountlib.MountError as error:
        raise GrantError(CONFLICT, str(error)) from None
    original = ctx.mount_entries
    ctx.mount_entries = lambda: mountlib.parse_document(mounts_raw)
    try:
        yield
    finally:
        ctx.mount_entries = original
    atomic_write(ctx.mounts_path, mounts_raw)


def mount_snapshot(ctx, args, source, name, out):
    import appliance_common
    import appliance_guest
    path = mountlib.mount_path(name)
    with mutation(ctx, option(args, 'dry_run', False)):
        raw, document, info = current_state(ctx)
        shares = ctx.shares()
        if name not in shares and len(shares) >= mountlib.MAX_MOUNTS:
            raise GrantError(CONFLICT, 'at most %d host folders can be shared' % mountlib.MAX_MOUNTS)
        if name in shares and shares[name]['source'] != source:
            raise GrantError(CONFLICT, '%s is already shared from %s; run "grant unmount %s" first' %
                             (path, shares[name]['source'], name))
        clash = next((other for other, item in shares.items()
                      if other != name and mountlib.overlaps(item['source'], source)), None)
        if clash:
            raise GrantError(CONFLICT, '%s overlaps the shared folder %s (%s)' % (source, shares[clash]['source'], clash))
        new_document = mount_policy(ctx, document, args, path, True)
        emit_notices(ctx, out)
        change = Change('mount', ['mount', source, '--as', name, '--read-only'], new_document,
                        message='host folder: %s -> %s (read-only snapshot)' % (source, path))
        if option(args, 'dry_run', False):
            commit(ctx, change, raw, document, info, True, out)
            out('dry_run=true: would copy a read-only snapshot of %s into the appliance' % source)
            return OK
        if not ctx.running():
            raise GrantError(APPLY, 'start the appliance first; a snapshot share is copied into the running VM')
        ctx.validate(render(new_document))
        archive = ctx.state / ('share-' + name + '.tar')
        archive.unlink(missing_ok=True)
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        try:
            try:
                stats = mountlib.build_snapshot(source, archive)
            except mountlib.MountError as error:
                raise GrantError(CONFLICT, str(error)) from None
            remote = '/root/agentgate-share-' + name + '.tar'
            try:
                appliance_common.copy_guest(ctx.state, ctx.binding, archive, remote)
                # The name is validated, so every word here is fixed or [a-z0-9_-].
                appliance_guest.admin_locked(ctx.state, ctx.binding, 'trap "rm -f ' + remote + '" EXIT; python3 ' +
                                             appliance_guest.GUEST + '/mounts.py install-snapshot ' +
                                             appliance_guest.GUEST + ' ' + name + ' ' + remote, timeout=300)
            except appliance_guest.GuestBusy as error:
                raise GrantError(BUSY, str(error)) from None
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
                raise GrantError(APPLY, 'the appliance did not accept the share: %s' % error) from None
        finally:
            archive.unlink(missing_ok=True)
        shares[name] = {'source': source, 'imported': now_utc().strftime('%Y-%m-%dT%H:%M:%SZ'),
                        'files': stats['files'], 'bytes': stats['bytes'], 'skipped': stats['skipped']}
        appliance_common.write(ctx.state / 'shares.json', json.dumps(shares, sort_keys=True).encode())
        code, _ = commit(ctx, change, raw, document, info, False, out)
        out('snapshot: %d files, %d bytes; skipped %d symlinks, special files, or other file systems. Rerun this '
            'command to refresh it.' % (stats['files'], stats['bytes'], stats['skipped']))
        return code


def do_unmount(ctx, args, out):
    try:
        name = mountlib.name_from_path(args.name)
    except mountlib.MountError as error:
        raise GrantError(USAGE, str(error)) from None
    path = mountlib.mount_path(name)
    with mutation(ctx, option(args, 'dry_run', False)):
        raw, document, info = current_state(ctx)
        change = Change('unmount', ['unmount', name], unmount_policy(document, path),
                        message='host folder %s removed' % path)
        if option(args, 'dry_run', False):
            return commit(ctx, change, raw, document, info, True, out)[0]
        if ctx.mode == 'appliance':
            import appliance_common
            import appliance_guest
            shares = ctx.shares()
            if name in shares or ctx.running():
                if not ctx.running():
                    raise GrantError(APPLY, 'start the appliance first to remove the shared snapshot')
                try:
                    appliance_guest.admin_locked(ctx.state, ctx.binding, 'python3 ' + appliance_guest.GUEST +
                                                 '/mounts.py remove ' + appliance_guest.GUEST + ' ' + name)
                except appliance_guest.GuestBusy as error:
                    raise GrantError(BUSY, str(error)) from None
                except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
                    raise GrantError(APPLY, 'the appliance did not remove the share: %s' % error) from None
                shares.pop(name, None)
                appliance_common.write(ctx.state / 'shares.json', json.dumps(shares, sort_keys=True).encode())
        else:
            entries = ctx.mount_entries()
            kept = [item for item in entries if item['name'] != name]
            if len(kept) != len(entries):
                # The mount goes first: a crash leaves an access entry for an absent mount.
                atomic_write(ctx.mounts_path, mountlib.render_document(kept))
        return commit(ctx, change, raw, document, info, False, out)[0]


def do_wizard(args, prog, ask=input, out=print, run=None):
    """Plain prompts; prints and then runs the exact equivalent commands."""
    run = run or (lambda argv: main(argv, prog))
    ctx = make_context(args)
    raw, document, info = current_state(ctx)
    out(summarize(ctx, info))
    out('')
    out('Answer each question; press Enter for the default in brackets. Nothing changes until you confirm.')
    globals_ = []
    for name in ('state', 'policy', 'mounts', 'validator'):
        if option(args, name):
            globals_ += ['--' + name, str(option(args, name))]

    def choose(question, choices, default):
        for _ in range(3):
            answer = (ask('%s [%s] (%s): ' % (question, '/'.join(choices), default)).strip() or default).lower()
            if answer in choices:
                return answer
            out('please answer one of: ' + ', '.join(choices))
        raise GrantError(USAGE, 'no valid answer')
    plan = []
    presets = list(load_presets())
    preset = choose('Start from a preset?', ['keep'] + presets, 'keep')
    if preset != 'keep':
        plan.append(['preset', preset])
    web = choose('Public web access?', ['keep', 'all', 'https', 'none'], 'keep')
    if web == 'all':
        plan.append(['allow-web', 'all'])
    elif web == 'https':
        plan += [['deny-web', 'http', 'quic'], ['allow-web', 'https']]
    elif web == 'none':
        plan.append(['deny-web', 'all'])
    folder = ask('Share a host folder? Enter its path, or press Enter to skip: ').strip()
    if folder:
        name = ask('Name inside the agent (%s): ' % mountlib.default_name(folder)).strip() or mountlib.default_name(folder)
        writable = choose('Should the agent be able to change it?', ['no', 'yes'], 'no') == 'yes'
        plan.append(['mount', folder, '--as', name, '--read-write' if writable else '--read-only'])
    for kind, question in (('read', 'Extra read-only paths inside the agent (space separated, Enter to skip): '),
                           ('write', 'Extra writable paths inside the agent (space separated, Enter to skip): ')):
        for path in ask(question).split():
            plan.append([kind, path])
    if not plan:
        out('Nothing to change.')
        return OK
    if document.get('version') == V1 and any(step[0] in V2_ACTIONS for step in plan):
        out('Your policy is version one (network only). These changes need version two, which adds filesystem and '
            'process controls that are implemented but not yet exercised on a BPF LSM kernel.')
        if choose('Upgrade to version two?', ['no', 'yes'], 'no') != 'yes':
            plan = [step for step in plan if step[0] not in V2_ACTIONS]
            out('Keeping version one; dropped the file and folder steps.')
        else:
            first = next(step for step in plan if step[0] in V2_ACTIONS)
            first.append('--upgrade-to-v2')
    if not plan:
        out('Nothing to change.')
        return OK
    out('Planned commands:')
    for step in plan:
        out('  ' + prog + ' ' + shlex.join(globals_ + step))
    if choose('Run these %d command(s)?' % len(plan), ['no', 'yes'], 'no') != 'yes':
        out('Nothing changed.')
        return OK
    for step in plan:
        out('ran: ' + prog + ' ' + shlex.join(globals_ + step))
        code = run(globals_ + step)
        if code != OK:
            out('stopped: that command exited %d; later commands were not run' % code)
            return code
    return OK


def dispatch(args, prog, out):
    command = args.command
    if command == 'presets':
        out(presets_text())
        return OK
    if command == 'allow-domain':
        raise GrantError(NOT_IMPLEMENTED, 'domain allowlists are not implemented. The network guard enforces IPv4 '
                                          'addresses and ports, not hostnames, and an allowed address can serve any '
                                          'hostname. See README "Domain allowlist: design and open work". Use '
                                          '"grant allow-web" or "grant deny-web".')
    if command == 'wizard':
        return do_wizard(args, prog, out=out)
    ctx = make_context(args)
    if command == 'show':
        if (ctx.history / 'intent.json').exists():
            out('note: an interrupted change is recorded; the next change finishes or discards it')
        raw, document, info = current_state(ctx)
        out(show_json(ctx, info) if option(args, 'json', False) else summarize(ctx, info))
        return OK
    if command == 'history':
        entries = ctx.log_entries() if ctx.history.exists() else []
        if option(args, 'json', False):
            out(json.dumps(entries, indent=2, sort_keys=True))
            return OK
        if not entries:
            out('no recorded changes')
        for item in entries:
            out('%5d  %s  %-40s  %s -> %s%s' % (item['seq'], item['time'], shlex.join(item['argv']),
                                               item['before_digest'][:12], item['after_digest'][:12],
                                               '  (recovered)' if item.get('recovered') else ''))
        if entries:
            out('rollback N restores the policy from before the Nth most recent change; backups kept: %d' % BACKUPS_KEPT)
        return OK
    if command == 'sync':
        if ctx.mode != 'appliance':
            out('nothing to sync: --policy edits a file directly')
            return OK
        with mutation(ctx):
            synced = ctx.sync()
            emit_notices(ctx, out)
            out('synced=%s' % ('true' if synced else 'false'))
        return OK
    if command == 'rollback':
        return do_rollback(ctx, args, out)
    if command == 'mount':
        return do_mount(ctx, args, out)
    if command == 'unmount' or (command == 'revoke' and args.kind == 'mount'):
        if command == 'revoke':
            if len(args.values) != 1:
                raise GrantError(USAGE, 'revoke mount takes exactly one NAME')
            args.name = args.values[0]
        return do_unmount(ctx, args, out)
    builders = {
        'allow-web': lambda document: op_web(ctx, document, args, allow=True),
        'deny-web': lambda document: op_web(ctx, document, args, allow=False),
        'dns': lambda document: op_dns(ctx, document, args),
        'read': lambda document: op_path(ctx, document, args, 'read'),
        'write': lambda document: op_path(ctx, document, args, 'write'),
        'exec': lambda document: op_path(ctx, document, args, 'exec'),
        'deny': lambda document: op_path(ctx, document, args, 'deny'),
        'signal': lambda document: op_signal(ctx, document, args),
        'anon-exec': lambda document: op_anon_exec(ctx, document, args),
        'preset': lambda document: op_preset(ctx, document, args),
        'revoke': lambda document: op_revoke(ctx, document, args),
    }
    return run_change(ctx, args, builders[command], out)


def main(argv, prog='grant', out=print):
    try:
        args = parser(prog).parse_args(argv)
    except SystemExit as exit_:
        return USAGE if exit_.code not in (0, None) else OK
    args.interactive = True
    try:
        return dispatch(args, prog, out)
    except GrantError as error:
        print('agentgate-grant-error: ' + str(error), file=sys.stderr)
        return error.code
    except mountlib.MountError as error:
        print('agentgate-grant-error: ' + str(error), file=sys.stderr)
        return CONFLICT
    except KeyboardInterrupt:
        print('agentgate-grant-error: interrupted; an unfinished change is finished or discarded next time',
              file=sys.stderr)
        return FAILURE
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print('agentgate-grant-error: %s: %s' % (type(error).__name__, error), file=sys.stderr)
        return FAILURE


def apply_file(state, binding, file):
    """appliance.py policy --policy FILE: the same engine, holding the caller's lock."""
    import appliance_common
    ctx = ApplianceContext(state, None, 0, binding=binding, held_lock=True)
    ctx.load_binding()
    incoming = appliance_common.protected(Path(file).absolute())
    with mutation(ctx):
        raw, document, info = current_state(ctx)
        change = Change('policy-file', ['policy', '--policy', str(Path(file).absolute())], raw=incoming)
        if not ctx.running():
            raise GrantError(APPLY, 'start the appliance before applying policy')
        code, new_info = commit(ctx, change, raw, document, info, out=lambda line: None)
        if binding.get('policy_pending'):
            ctx.sync(quiet=True)
        print('policy_applied=true next_command=true digest=' + new_info['digest'])
        return code


def start_sync(state, binding, guest=True):
    """Called by appliance.py start under its lock.

    Before the VM is up (guest=False) it only finishes or discards an interrupted
    change. Once the guest is configured it applies a pending policy.
    """
    ctx = ApplianceContext(state, None, 0, binding=binding, held_lock=True)
    ensure_history(ctx.history)
    ctx.reconcile()
    if guest and binding.get('policy_pending'):
        if not ctx.sync(quiet=True):
            raise GrantError(APPLY, 'the pending policy could not be applied; the appliance is not running')
    for notice in ctx.notices:
        print('note: ' + notice)


if __name__ == '__main__':
    sys.path.insert(0, str(HERE))
    sys.exit(main(sys.argv[1:], 'python3 ' + shlex.quote(sys.argv[0])))
