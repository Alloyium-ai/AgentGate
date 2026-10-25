#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Launch runtime: run one verified agent launch in a fresh guarded target.

agentgate-hostd verifies a launch job from the service and hands it to this
program on standard input. A launch uses exactly the SSH command path of this
instance: a fresh Docker target (restart-target.sh), the BPF guard attached
before anything runs (start-guard.sh), and the late-join runner
(run-in-target.sh). Only the lifetime, the image, the mounts and the command
differ, and each is validated again here.

Concurrency: one guarded command or launch per instance at a time. The
instance's single-job.lock is held for the whole launch, so an SSH command
or a second launch is refused as busy until this one has torn down.

Commands (exit 0 success, 1 failure, 2 invalid input, 75 busy):
  run                      read a launcher job on stdin and run it in the foreground;
                           progress, bounded log chunks and the receipt go to stdout as JSON lines
  stop ID [--grace S] [--reason R] [--wait S]
  status ID | receipt ID | list
  logs ID stdout|stderr OFFSET LIMIT
  reconcile [--reason R]   tear down every launch whose runtime is gone
  capabilities
  stage-profile ID VERSION read a profile document on stdin; validate it natively and stage a copy
  pull NAME@sha256:DIGEST  pull one digest-pinned image
  snapshot NAME SOURCE [--max-bytes N] [--max-entries N]
                           snapshot a local folder for snapshot mounts (Docker host only)
  install-snapshot NAME SOURCE ARCHIVE
"""
import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import queue
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import launch_job  # noqa: E402
from launch_job import JobError  # noqa: E402

TERMINAL = ('stopped', 'expired', 'failed')
LOCK = 'single-job.lock'
BUSY = 75
# The guard writes its receipt after SIGTERM; its own launch bound is 60 s.
LAUNCH_GUARD_WAIT_S = 20
HEARTBEAT_S = 5
KEEPALIVE_MARGIN_S = 300
EXPIRY_GRACE_S = 5
OBJECTS = ('network_policy.bpf.o', 'fs_access.bpf.o', 'process_guard.bpf.o')
MAX_GUARD_RECEIPT = 16 << 20
UPLOAD_DENIALS = 100
UPLOAD_CHUNK = 4 << 10
MAX_LOG_READ = 1 << 20
EVENT_QUEUE = 512
RECEIPT_VERSION = 'agentgate.launch-receipt.v1'
STOP_REASONS = ('stop_requested', 'service_unreachable', 'lost_host', 'host_shutdown', 'deadline')


class LaunchError(RuntimeError):
    """A launch step failed; the launch fails closed and tears down."""


class Busy(RuntimeError):
    """Another guarded command or launch holds the instance."""


class StopDuringSetup(LaunchError):
    """A stop request or signal arrived before the agent started."""


def utc_now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def write_private(path, raw, mode=0o600):
    """Atomically and durably replace one private file (temporary, fsync, rename, directory fsync)."""
    path = Path(path)
    temporary = path.with_name('.' + path.name + '.new')
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


def read_private(path, limit):
    """Read one regular file owned by this user, mode 0600 or tighter, without following a link."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_mode & 0o077:
            raise LaunchError('untrusted launch file: ' + str(path))
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(1 << 20, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise LaunchError('launch file exceeds %d bytes: %s' % (limit, path))
        return b''.join(chunks)
    finally:
        os.close(fd)


def dump(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def process_start_ticks(pid):
    raw = Path(f'/proc/{pid}/stat').read_text()
    return int(raw.rsplit(')', 1)[1].split()[19])


def process_alive(pid, ticks):
    try:
        state = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0]
        return state not in ('Z', 'X') and process_start_ticks(pid) == ticks
    except (OSError, ValueError, IndexError):
        return False


class BoundedLog:
    """One stream's host log: at most limit bytes kept, every byte counted and hashed."""

    def __init__(self, path, limit, upload_limit=0, upload=None, name='stdout'):
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        self.limit, self.kept, self.total = limit, 0, 0
        self.digest = hashlib.sha256()
        self.error = None
        self.upload_limit, self.uploaded, self.upload = upload_limit, 0, upload
        self.upload_truncated = False
        self.name = name

    def __call__(self, chunk):
        self.total += len(chunk)
        self.digest.update(chunk)
        room = self.limit - self.kept
        if room > 0 and self.error is None:
            part = chunk[:room]
            try:
                written = 0
                while written < len(part):
                    written += os.write(self.fd, part[written:])
                self.kept += len(part)
            except OSError as error:
                # A full disk must not stop enforcement; the receipt records it.
                self.error = str(error)
        if self.upload is not None:
            room = self.upload_limit - self.uploaded
            if room > 0:
                part = chunk[:room]
                offset = self.uploaded
                for start in range(0, len(part), UPLOAD_CHUNK):
                    piece = part[start:start + UPLOAD_CHUNK]
                    if not self.upload({'event': 'log', 'stream': self.name, 'offset': offset + start,
                                        'data': base64.b64encode(piece).decode()}):
                        self.upload_truncated = True
                self.uploaded += len(part)
            if len(chunk) > max(room, 0):
                self.upload_truncated = True

    def close(self):
        try:
            os.fsync(self.fd)
        except OSError:
            pass
        os.close(self.fd)

    def summary(self):
        return {'bytes': self.total, 'kept_bytes': self.kept, 'sha256': self.digest.hexdigest(),
                'truncated': self.total > self.kept, 'write_error': self.error,
                'uploaded_bytes': self.uploaded, 'upload_truncated': self.upload_truncated}


class Emitter:
    """JSON lines to the supervisor without ever blocking enforcement.

    A writer thread drains a bounded queue. Log chunks and heartbeats are
    dropped when the queue is full (the receipt says so); a state or receipt
    line waits briefly. A broken pipe means the supervisor is gone.
    """

    def __init__(self, fd=1, size=EVENT_QUEUE):
        self.fd = fd
        self.items = queue.Queue(size)
        self.healthy = True
        self.dropped = 0
        self.thread = threading.Thread(target=self._drain, daemon=True)
        self.thread.start()

    def _drain(self):
        while True:
            item = self.items.get()
            if item is None:
                return
            try:
                data = memoryview(item)
                while data:
                    written = os.write(self.fd, data)
                    data = data[written:]
            except OSError:
                self.healthy = False

    def emit(self, event, droppable=False):
        line = dump(dict(event, time=utc_now())) + b'\n'
        try:
            if droppable:
                self.items.put_nowait(line)
            else:
                self.items.put(line, timeout=5)
            return True
        except queue.Full:
            self.dropped += 1
            if not droppable:
                self.healthy = False
            return False

    def close(self, timeout=10):
        try:
            self.items.put(None, timeout=timeout)
        except queue.Full:
            return
        self.thread.join(timeout)


class Record:
    """The launch's durable state file in its own directory."""

    def __init__(self, directory):
        self.path = Path(directory) / 'state.json'
        self.data = {}

    def load(self):
        self.data = json.loads(read_private(self.path, 65536))
        return self.data

    def update(self, state=None, **values):
        if state is not None:
            self.data['state'] = state
        self.data.update(values)
        self.data['updated_at'] = utc_now()
        write_private(self.path, dump(self.data))


def tree_digest(path, limit_entries=20000):
    """Digest of a snapshot share: relative path, type, mode and content of each entry."""
    digest = hashlib.sha256()
    count = 0
    base = Path(path)
    for directory, folders, files in os.walk(base):
        folders.sort()
        for name in sorted(files):
            item = Path(directory) / name
            meta = os.lstat(item)
            count += 1
            if count > limit_entries or not stat.S_ISREG(meta.st_mode):
                raise LaunchError('snapshot share holds an unsupported entry: ' + str(item))
            content = hashlib.sha256()
            with open(item, 'rb') as source:
                for chunk in iter(lambda: source.read(1 << 20), b''):
                    content.update(chunk)
            digest.update(b'f\0' + str(item.relative_to(base)).encode() + b'\0' +
                          oct(meta.st_mode & 0o777).encode() + b'\0' + content.digest())
        for name in folders:
            digest.update(b'd\0' + str((Path(directory) / name).relative_to(base)).encode())
    return digest.hexdigest()


class Host:
    """The real operations of one installed instance. Tests replace this object."""

    def __init__(self, root=ROOT, run=subprocess.run):
        from domain_control import Instance, load_gateway
        from settings import load_settings
        self.root = Path(root)
        self.run = run
        self.settings = load_settings(self.root / 'settings.json')
        self.gateway = load_gateway(self.root)
        self.instance = Instance(self.root, self.settings, run=run, gateway=self.gateway)

    # Capabilities -------------------------------------------------------
    def runtime(self):
        # The appliance guest records its installation; it cannot see host folders.
        return 'appliance' if (self.root / 'appliance-installed').exists() else 'docker-host'

    def preflight(self):
        try:
            done = self.run([str(self.root / 'pilot-network-diagnostic'), 'preflight'], capture_output=True,
                            timeout=15, env={'PATH': '/usr/bin:/bin'})
            report = json.loads(done.stdout.decode() or '{}')
            return {'ok': bool(report.get('ok')), 'error': report.get('error'), 'kernel': report.get('kernel')}
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            return {'ok': False, 'error': 'preflight unavailable: ' + str(error), 'kernel': None}

    def capabilities(self):
        runtime = self.runtime()
        names = ['snapshots'] + (['live-mounts'] if runtime == 'docker-host' else [])
        preflight = self.preflight()
        if preflight['ok']:
            names.append('kernel-bpf-lsm')
        return {'runtime': runtime, 'capabilities': sorted(names), 'preflight': preflight,
                'instance': self.settings['instance'], 'source_revision': self.settings['source']}

    def capability_names(self):
        # A launch needs only the mount capabilities; the guard runs the kernel preflight itself.
        return ['snapshots'] + (['live-mounts'] if self.runtime() == 'docker-host' else [])

    # Preparation ---------------------------------------------------------
    def precheck(self):
        if (self.root / 'appliance-stopping').exists():
            raise LaunchError('appliance stop requested; start the appliance first')
        if not (self.root / 'initialized').exists():
            raise LaunchError('the instance is not initialized; run configure.py first')
        if not self.instance.empty_domain() or self.instance.pins_remain():
            # A guard killed earlier leaves pins; release them once nothing is live.
            self.instance.release_orphaned_pins()
        if not self.instance.empty_domain() or self.instance.pins_remain():
            raise LaunchError('previous command domain or pins remain')
        if self.run(['/usr/bin/docker', 'container', 'inspect', self.settings['name']], capture_output=True,
                    timeout=5, env={'PATH': '/usr/bin:/bin'}).returncode == 0:
            raise LaunchError('the owned target is still present')
        from domain_control import COMMAND_FILES
        self.instance.archive_previous(COMMAND_FILES)

    def stage_policy(self, policy):
        from settings import effective_policy, resolver_file
        write_private(self.root / 'policy-active.json', dump(policy))
        info = effective_policy(self.root, self.settings)
        if info['document'].get('mode') != policy['mode']:
            raise LaunchError('the native validator did not confirm the launch mode')
        resolver = self.root / 'resolv.conf'
        write_private(resolver, resolver_file(info['document']['dns']['resolvers']).encode())
        return info

    def resolve_image(self, reference):
        done = self.run(['/usr/bin/docker', 'image', 'inspect', reference], capture_output=True, timeout=10,
                        env={'PATH': '/usr/bin:/bin'})
        if done.returncode != 0:
            raise LaunchError('agent image is not present on this target (images are never pulled): ' + reference)
        item = json.loads(done.stdout)[0]
        image_id = item.get('Id', '')
        if not launch_job.IMAGE_ID.fullmatch(image_id):
            raise LaunchError('agent image has no content digest')
        if reference != image_id and reference not in (item.get('RepoDigests') or []):
            raise LaunchError('agent image digest is not this local image: ' + reference)
        revision = (item.get('Config') or {}).get('Labels', {}) or {}
        if revision.get('org.opencontainers.image.revision') != self.settings['source']:
            raise LaunchError('agent image was not built from the installed source revision; '
                              'the guard binds the image to it')
        return image_id

    def check_image(self, image_id, program):
        from image_contract import validate_image
        try:
            validate_image(image_id, program)
        except subprocess.CalledProcessError as error:
            raise LaunchError('agent image failed the launch contract (exit %d)' % error.returncode) from None

    def stage_mounts(self, entries, launch):
        import mounts
        for item in launch['mounts']:
            if item['mode'] != 'snapshot':
                continue
            identity_path = self.root / 'shares' / ('.' + item['name'] + '.json')
            try:
                identity = json.loads(read_private(identity_path, 65536))
            except (OSError, LaunchError, ValueError):
                raise LaunchError('snapshot %s is not installed; run the snapshot-mount job first' % item['name'])
            if identity.get('source') != item['source']:
                raise LaunchError('snapshot %s was taken from a different folder' % item['name'])
        raw = mounts.render_document(entries)
        mounts.parse_document(raw)
        write_private(self.root / mounts.LAUNCH_MOUNTS, raw)

    def start_target(self, image_id, keepalive, taskboard_bridge=False):
        domain = Path(self.settings['domain'])
        if not domain.exists():
            # A guest reboot clears cgroups; the protected settings name only this owned domain.
            domain.mkdir()
        # The taskboard bridge volume is mounted only when the launch asks
        # (launch_job.taskboard_bridge); otherwise the target has no path to it.
        self._script(['restart-target.sh', '--launch', image_id, str(keepalive)] +
                     (['--taskboard-bridge'] if taskboard_bridge else []), 180)

    def start_guard(self):
        self._script(['start-guard.sh'], 60)

    def connect_broker(self, broker):
        """Attach the target to its launch's broker network, after the guard is attached.

        The target keeps its own network and gains exactly one more: the
        internal /29 that holds only the broker. The guard allows the broker's
        one exact address and port and denies every other private address.
        """
        target = self.settings['name']
        env = {'PATH': '/usr/bin:/bin'}
        done = self.run(['/usr/bin/docker', 'network', 'connect', '--ip', broker['target_address'], broker['network'], target],
                        capture_output=True, timeout=20, env=env)
        if done.returncode != 0:
            raise LaunchError('the target could not join its broker network: ' +
                              done.stderr.decode(errors='replace')[-500:].strip())
        done = self.run(['/usr/bin/docker', 'inspect', target], capture_output=True, timeout=10, env=env)
        if done.returncode != 0:
            raise LaunchError('the target could not be inspected after joining its broker network')
        networks = (json.loads(done.stdout)[0].get('NetworkSettings') or {}).get('Networks') or {}
        joined = networks.get(broker['network']) or {}
        if set(networks) != {self.settings['network'], broker['network']} or joined.get('IPAddress') != broker['target_address']:
            raise LaunchError('the target is not on exactly its own network and its broker network')

    def _script(self, args, timeout):
        done = self.run([str(self.root / args[0])] + args[1:], capture_output=True, timeout=timeout,
                        env={'PATH': '/usr/bin:/bin'})
        if done.returncode != 0:
            tail = done.stderr.decode(errors='replace')[-1500:]
            raise LaunchError('%s failed (exit %d): %s' % (args[0], done.returncode, tail.strip()))

    # Execution ------------------------------------------------------------
    def bind(self):
        return self.gateway.load_binding(str(self.root / 'config.json'))

    def execute(self, config, command, target, guard_ok, alive, sinks, should_stop, grace, extra):
        return self.gateway.execute_detailed(config, command, target, guard_ok, alive, stdin=subprocess.DEVNULL,
                                             sinks=sinks, should_stop=should_stop, grace_ns=grace,
                                             audit_extra=extra)

    def guard_pid(self):
        try:
            return self.instance.read_guard_pid()
        except (OSError, KeyError, ValueError):
            return None

    def command_identity(self):
        try:
            data = json.loads((self.root / 'config.json').read_text())
            return {'container_id': data.get('container_id'), 'guard_pid': data.get('guard_pid'),
                    'guard_start_ticks': data.get('guard_start_ticks'), 'deadline_ns': data.get('deadline_ns')}
        except (OSError, ValueError):
            return None

    def teardown(self, pid):
        return self.instance.teardown(pid, LAUNCH_GUARD_WAIT_S)

    def guard_receipt(self):
        path = self.root / 'guard-receipt.json'
        if not path.exists():
            return None
        try:
            return json.loads(read_private(path, MAX_GUARD_RECEIPT))
        except (OSError, ValueError, LaunchError):
            return None

    def mount_identities(self):
        try:
            active = json.loads((self.root / 'mounts-active.json').read_text())
        except (OSError, ValueError):
            return []
        out = []
        for item in active:
            entry = {'path': item['path'], 'source': item['source'], 'read_only': item['read_only']}
            try:
                meta = os.stat(item['source'])
                entry.update(device=meta.st_dev, inode=meta.st_ino)
            except OSError as error:
                entry['error'] = str(error)
            identity = Path(item['source']).parent / ('.' + Path(item['source']).name + '.json')
            if Path(item['source']).parent == self.root / 'shares' and identity.exists():
                try:
                    data = json.loads(read_private(identity, 65536))
                    entry.update(snapshot_of=data.get('source'), tree_sha256=data.get('tree_sha256'))
                except (OSError, ValueError, LaunchError):
                    entry['error'] = 'snapshot identity unreadable'
            out.append(entry)
        return out

    def digests(self):
        out = {}
        for name in OBJECTS + ('pilot-network-diagnostic', 'run-in-target.sh'):
            try:
                out[name] = hashlib.sha256((self.root / name).read_bytes()).hexdigest()
            except OSError:
                out[name] = None
        return out

    def collect_command_files(self, destination, expected=None):
        """Move this launch's command files from the instance root into its directory."""
        from domain_control import COMMAND_FILES
        if expected is not None and self.command_identity() != expected:
            return False
        destination = Path(destination)
        destination.mkdir(mode=0o700, exist_ok=True)
        for name in COMMAND_FILES:
            path = self.root / name
            if path.exists():
                path.rename(destination / name)
        return True

    def append_event(self, record):
        self.instance.append_event(record)


def evidence_block(guard):
    """The guard's evidence for upload: complete counts and digests, bounded lists."""
    if guard is None:
        return None
    block = {key: guard.get(key) for key in ('scope', 'source_revision', 'boot_id', 'policy_digest', 'object_sha256',
                                             'domain', 'pin_dir', 'rule_ids', 'started_mono_ns', 'deadline_mono_ns',
                                             'finished_mono_ns', 'counters', 'network', 'stop', 'collection_error',
                                             'complete', 'mode', 'lifetime_seconds', 'target')}
    events = guard.get('events') or []
    block['network_events_kept'] = len(events)
    block['network_denials'] = [item for item in events if not item.get('Allowed')][:UPLOAD_DENIALS]
    host = guard.get('host')
    if isinstance(host, dict):
        # The socket mode and whether a socket LSM guard is attached are
        # part of what was (and was not) enforced: always kept.
        trimmed = {'complete': host.get('complete'), 'sockets': host.get('sockets'),
                   'socket_lsm_guard': host.get('socket_lsm_guard')}
        for name in ('filesystem', 'process'):
            part = dict(host.get(name) or {})
            denials = part.get('denials') or []
            part['denials_total_kept'] = len(denials)
            part['denials'] = denials[:UPLOAD_DENIALS]
            trimmed[name] = part
        block['host'] = trimmed
    return block


def classify(result, setup_error, stop_request, cleanup_errors, signalled, stopped_in_setup=False):
    """Map the run to a terminal state and reason. 'stopped' needs a proven cleanup."""
    if stopped_in_setup and not cleanup_errors:
        if signalled:
            return 'failed', 'supervisor_stopped'
        reason = (stop_request or {}).get('reason', 'stop_requested')
        return ('stopped', 'stop_requested') if reason == 'stop_requested' else ('failed', reason)
    if setup_error is not None:
        return 'failed', 'cleanup_incomplete' if cleanup_errors else 'setup_failed'
    if cleanup_errors or result is None or not result['cleaned']:
        return 'failed', 'cleanup_incomplete'
    state = result['state']
    if state == 'completed':
        return 'stopped', 'exited'
    if state == 'stopped':
        if signalled:
            return 'failed', 'supervisor_stopped'
        reason = (stop_request or {}).get('reason', 'stop_requested')
        return ('stopped', 'stop_requested') if reason == 'stop_requested' else ('failed', reason)
    if state == 'expired':
        return 'expired', 'lifetime_expired'
    if state == 'disconnected':
        return 'failed', 'supervisor_lost'
    if state == 'guard_lost':
        return 'failed', 'guard_lost'
    return 'failed', state


def read_stop_request(directory):
    path = Path(directory) / 'stop-request.json'
    if not path.exists():
        return None
    try:
        data = json.loads(read_private(path, 4096))
    except (OSError, ValueError, LaunchError):
        return {'reason': 'stop_requested', 'grace_seconds': 0}
    if data.get('reason') not in STOP_REASONS or type(data.get('grace_seconds')) is not int:
        return {'reason': 'stop_requested', 'grace_seconds': 0}
    return data


def broker_summary(broker, joined):
    """How the target joined its broker network; counts come from the broker's own stats on the host."""
    if not broker:
        return None
    return {'network': broker['network'], 'address': broker['address'], 'port': broker['port'],
            'target_address': broker['target_address'], 'env': sorted(broker['env']), 'target_joined': joined}


def build_receipt(launch, host, state, reason, result, guard, cleanup_errors, logs, started_at, mounts_identity,
                  setup_error=None, evidence_missing=None, emitter=None, broker_joined=False):
    receipt = {
        'version': RECEIPT_VERSION, 'launch_id': launch['launch_id'], 'job_id': launch['job_id'],
        'spec_digest': launch['spec_digest'], 'policy_digest': launch['policy_digest'],
        'profile_policy_digest': launch['profile_policy_digest'], 'mode': launch['mode'],
        'lifetime_seconds': launch['lifetime_seconds'], 'image': launch.get('image'),
        'image_id': launch.get('image_id'), 'state': state, 'reason': reason,
        'exit_code': result['exit_code'] if result and reason == 'exited' else None,
        'started_at': started_at, 'ended_at': utc_now(),
        'started_mono_ns': result['started_mono_ns'] if result else None,
        'ended_mono_ns': result['finished_mono_ns'] if result else None,
        'objects': host.digests(), 'mounts': mounts_identity, 'logs': logs,
        'output': {key: result[key] for key in ('stdout_sha256', 'stderr_sha256', 'stdout_bytes', 'stderr_bytes')}
        if result else None,
        'evidence': evidence_block(guard), 'evidence_complete': bool(guard and guard.get('complete')),
        'guard_receipt_sha256': hashlib.sha256(dump(guard)).hexdigest() if guard else None,
        'cleanup': {'domain_empty': not cleanup_errors, 'enforcement_released': not cleanup_errors,
                    'errors': cleanup_errors},
        'broker': broker_summary(launch.get('broker'), broker_joined),
        'kernel_verified': False,
        'evidence_missing': evidence_missing or (None if guard else 'guard_receipt_absent'),
    }
    if setup_error:
        receipt['setup_error'] = setup_error
    if emitter is not None:
        receipt['events_dropped'] = emitter.dropped
    return receipt


def run_launch(raw, host, launches, emitter, supervisor_alive, signalled=lambda: False, clock=time.monotonic):
    """Run one launch to its terminal state; the caller holds the instance lock."""
    launch = launch_job.check_job(raw, host.capability_names())
    directory = Path(launches) / launch['launch_id']
    # At most once on this host: a second job for the same launch is refused.
    directory.mkdir(mode=0o700)
    write_private(directory / 'job.json', raw)
    record = Record(directory)
    started_at = utc_now()
    record.update('provisioning', pid=os.getpid(), start_ticks=process_start_ticks(os.getpid()),
                  launch_id=launch['launch_id'], job_id=launch['job_id'], started_at=started_at)
    emitter.emit({'event': 'state', 'state': 'provisioning', 'launch_id': launch['launch_id']})
    upload = (lambda event: emitter.emit(event, droppable=True)) if launch['upload_limit_bytes'] else None
    logs = {name: BoundedLog(directory / (name + '.log'), launch['log_limit_bytes'], launch['upload_limit_bytes'],
                             upload, name) for name in ('stdout', 'stderr')}
    result, setup_error, cleanup_errors, guard, pid = None, None, [], None, None
    identity = None
    last_beat = [clock()]
    stop_request = [None]
    broker_joined = [False]

    def should_stop():
        now = clock()
        if now - last_beat[0] >= HEARTBEAT_S:
            last_beat[0] = now
            emitter.emit({'event': 'heartbeat', 'launch_id': launch['launch_id'],
                          'stdout_bytes': logs['stdout'].total, 'stderr_bytes': logs['stderr'].total},
                         droppable=True)
        if signalled():
            return True
        if stop_request[0] is None:
            stop_request[0] = read_stop_request(directory)
        return stop_request[0] is not None

    def grace(state):
        if state == 'expired':
            return min(EXPIRY_GRACE_S, launch['stop_grace_seconds']) * 1_000_000_000
        if state == 'stopped' and stop_request[0] is not None:
            return min(int(stop_request[0].get('grace_seconds', 0)), launch_job.MAX_STOP_GRACE_S) * 1_000_000_000
        return launch['stop_grace_seconds'] * 1_000_000_000 if state == 'stopped' else 0

    def checkpoint():
        if signalled() or read_stop_request(directory) is not None:
            stop_request[0] = read_stop_request(directory)
            raise StopDuringSetup('stop requested before the agent started')

    stopped_in_setup = False
    try:
        host.precheck()
        checkpoint()
        info = host.stage_policy(launch['policy'])
        if info['digest'] != launch['policy_digest']:
            raise LaunchError('the effective policy digest differs from the verified launch')
        launch['image_id'] = host.resolve_image(launch['image'])
        host.check_image(launch['image_id'], launch['command'][0])
        checkpoint()
        host.stage_mounts(launch_job.mount_entries(launch), launch)
        host.start_target(launch['image_id'], launch['lifetime_seconds'] + KEEPALIVE_MARGIN_S, launch['taskboard_bridge'])
        checkpoint()
        host.start_guard()
        pid = host.guard_pid()
        checkpoint()
        if launch['broker'] is not None:
            # Only after the guard is attached: the policy allows exactly the
            # broker's endpoint from the first packet on.
            host.connect_broker(launch['broker'])
            broker_joined[0] = True
        identity = host.command_identity()
        config, guard_ok, target = host.bind()
        # The signed expiry is a hard cap too: the host deadline is the earlier
        # of the lifetime (start-guard.sh) and the expiry, on the monotonic clock.
        remaining_ns = (launch['expires_at_ms'] - int(time.time() * 1000)) * 1_000_000
        config['deadline_ns'] = min(int(config['deadline_ns']), time.monotonic_ns() + max(remaining_ns, 0))
        record.update('running', command=identity, deadline_ns=config['deadline_ns'])
        emitter.emit({'event': 'state', 'state': 'running', 'launch_id': launch['launch_id'],
                      'policy_digest': launch['policy_digest'], 'image_id': launch['image_id']})
        result = host.execute(config, launch_job.shell_command(launch), target, guard_ok,
                              lambda: supervisor_alive() and emitter.healthy, logs, should_stop, grace,
                              {'launch_id': launch['launch_id'], 'spec_digest': launch['spec_digest'],
                               'mode': launch['mode'], 'lifetime_seconds': launch['lifetime_seconds']})
    except StopDuringSetup as error:
        stopped_in_setup = True
        setup_error = str(error)
    except Exception as error:  # noqa: BLE001 - every failure fails closed with a receipt
        setup_error = '%s: %s' % (type(error).__name__, str(error)[:2000])
    finally:
        record.update('stopping')
        emitter.emit({'event': 'state', 'state': 'stopping', 'launch_id': launch['launch_id']})
        try:
            if pid is None:
                pid = host.guard_pid()
            cleanup_errors = host.teardown(pid)
        except Exception as error:  # noqa: BLE001
            cleanup_errors = ['teardown: %s: %s' % (type(error).__name__, error)]
        try:
            guard = host.guard_receipt()
            mounts_identity = host.mount_identities()
            host.collect_command_files(directory / 'instance')
        except Exception as error:  # noqa: BLE001
            guard, mounts_identity = None, []
            cleanup_errors = cleanup_errors + ['evidence collection: %s' % error]
        for item in logs.values():
            item.close()
        state, reason = classify(result, setup_error, stop_request[0], cleanup_errors, signalled(),
                                 stopped_in_setup)
        receipt = build_receipt(launch, host, state, reason, result, guard, cleanup_errors,
                                {name: item.summary() for name, item in logs.items()}, started_at,
                                mounts_identity, setup_error, emitter=emitter, broker_joined=broker_joined[0])
        write_private(directory / 'receipt.json', dump(receipt))
        record.update(state, reason=reason, ended_at=receipt['ended_at'])
        emitter.emit({'event': 'receipt', 'launch_id': launch['launch_id'], 'receipt': receipt})
    return receipt


def reconcile_launch(directory, host, reason):
    """Tear down one launch whose runtime is gone and record it as failed. Caller holds the lock."""
    record = Record(directory)
    data = record.load()
    if data.get('state') in TERMINAL:
        return None
    job = json.loads(read_private(Path(directory) / 'job.json', launch_job.MAX_JOB_BYTES))
    expected = data.get('command')
    # The caller holds the instance lock and no runtime is alive, so any guard
    # still bound in the instance root is orphaned: stop it as well.
    try:
        cleanup_errors = host.teardown(host.guard_pid())
    except Exception as error:  # noqa: BLE001
        cleanup_errors = ['teardown: %s: %s' % (type(error).__name__, error)]
    collected = expected is not None and host.collect_command_files(Path(directory) / 'instance', expected)
    guard = None
    if collected:
        path = Path(directory) / 'instance' / 'guard-receipt.json'
        try:
            guard = json.loads(read_private(path, MAX_GUARD_RECEIPT)) if path.exists() else None
        except (OSError, ValueError, LaunchError):
            guard = None
    launch = {'launch_id': job['launch_id'], 'job_id': job['job_id'], 'spec_digest': job['spec_digest'],
              'policy_digest': job['policy_digest'], 'profile_policy_digest': job['profile_policy_digest'],
              'mode': job['spec'].get('mode'), 'lifetime_seconds': job['spec'].get('lifetime_seconds'),
              'image': (job['spec'].get('agent') or {}).get('image'), 'broker': job.get('broker')}
    logs = {}
    for name in ('stdout', 'stderr'):
        path = Path(directory) / (name + '.log')
        logs[name] = {'kept_bytes': path.stat().st_size if path.exists() else 0, 'complete': False}
    missing = None if guard else ('guard_receipt_absent' if collected else 'command_files_superseded')
    receipt = build_receipt(launch, host, 'failed', reason, None, guard, cleanup_errors, logs,
                            data.get('started_at'), [], evidence_missing=missing)
    receipt['reconciled'] = True
    write_private(Path(directory) / 'receipt.json', dump(receipt))
    record.update('failed', reason=reason, ended_at=receipt['ended_at'])
    return receipt


def acquire(root, wait_s=0, clock=time.monotonic, sleep=time.sleep):
    fd = os.open(Path(root) / LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    deadline = clock() + wait_s
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            if clock() >= deadline:
                os.close(fd)
                raise Busy('another guarded command or launch is running on this instance') from None
            sleep(0.2)


def launch_directory(launches, launch_id):
    if not isinstance(launch_id, str) or not launch_job.LAUNCH_ID.fullmatch(launch_id):
        raise JobError('invalid launch id')
    path = Path(launches) / launch_id
    if path.is_symlink() or not path.is_dir():
        raise JobError('unknown launch: ' + launch_id)
    return path


def launches_root(root):
    path = Path(root) / 'launches'
    path.mkdir(mode=0o700, exist_ok=True)
    meta = os.lstat(path)
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_mode & 0o077:
        raise LaunchError('launch directory custody differs')
    return path


def request_stop(directory, host, grace, reason, root, wait_s=0, sleep=time.sleep, clock=time.monotonic):
    """Idempotent stop: a terminal launch returns its result; a running one is asked to stop."""
    if reason not in STOP_REASONS:
        raise JobError('invalid stop reason')
    if type(grace) is not int or not 0 <= grace <= launch_job.MAX_STOP_GRACE_S:
        raise JobError('grace must be 0..%d seconds' % launch_job.MAX_STOP_GRACE_S)
    record = Record(directory)
    data = record.load()
    if data.get('state') in TERMINAL:
        return {'state': data['state'], 'reason': data.get('reason'), 'already_terminal': True}
    if not (Path(directory) / 'stop-request.json').exists():
        write_private(Path(directory) / 'stop-request.json',
                      dump({'reason': reason, 'grace_seconds': grace, 'requested_at': utc_now()}))
    try:
        fd = acquire(root)
    except Busy:
        deadline = clock() + wait_s
        while clock() < deadline:
            if record.load().get('state') in TERMINAL:
                break
            sleep(0.2)
        data = record.load()
        return {'state': data.get('state'), 'reason': data.get('reason'), 'stop_requested': True}
    try:
        # Nobody holds the instance: the runtime is gone. Tear down what it left.
        receipt = reconcile_launch(directory, host, 'launcher_lost')
        data = record.load()
        return {'state': data.get('state'), 'reason': data.get('reason'), 'reconciled': receipt is not None}
    finally:
        os.close(fd)


def reconcile_all(root, host, reason, wait_s=30):
    fd = acquire(root, wait_s)
    try:
        out = []
        launches = launches_root(root)
        for directory in sorted(launches.iterdir()):
            if directory.is_symlink() or not directory.is_dir() or not (directory / 'state.json').exists():
                continue
            receipt = reconcile_launch(directory, host, reason)
            if receipt is not None:
                out.append({'launch_id': directory.name, 'state': receipt['state'], 'reason': receipt['reason']})
        if not host.instance.empty_domain() or host.instance.pins_remain():
            try:
                host.instance.release_orphaned_pins()
            except (OSError, RuntimeError, subprocess.SubprocessError):
                pass
        return out
    finally:
        os.close(fd)


def read_log(directory, stream, offset, limit):
    if stream not in ('stdout', 'stderr') or type(offset) is not int or offset < 0 or \
       type(limit) is not int or not 0 < limit <= MAX_LOG_READ:
        raise JobError('logs needs stdout|stderr, OFFSET >= 0 and LIMIT 1..%d' % MAX_LOG_READ)
    fd = os.open(Path(directory) / (stream + '.log'), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return os.pread(fd, limit, offset)
    finally:
        os.close(fd)


def stage_profile(root, host, profile_id, version, raw):
    """Pre-check a profile with the native validator and stage a copy. Running launches never change."""
    if not launch_job.LAUNCH_ID.fullmatch(profile_id) or not version.isdigit() or not 0 < int(version) < 1 << 31:
        raise JobError('usage: stage-profile PROFILE_ID VERSION < policy.json')
    document = launch_job.parse_json(raw, 16384)
    if not isinstance(document, dict):
        raise JobError('a profile is one JSON object')
    staged = Path(root) / 'profiles'
    staged.mkdir(mode=0o700, exist_ok=True)
    path = staged / ('%s-%s.json' % (profile_id, version))
    pending = staged / ('.%s-%s.pending.json' % (profile_id, version))
    write_private(pending, raw)
    done = host.run([str(Path(root) / 'pilot-network-diagnostic'), 'network-info', str(pending)],
                    capture_output=True, timeout=10, env={'PATH': '/usr/bin:/bin'})
    if done.returncode != 0:
        pending.unlink()
        raise JobError('the native validator rejected the profile: ' + done.stderr.decode(errors='replace')[-800:])
    info = json.loads(done.stdout)
    os.replace(pending, path)
    # A launch needs a version two document; a version one profile serves SSH commands only.
    return {'policy_digest': info['digest'], 'version': info['document']['version'],
            'launchable': info['document']['version'] == 'agentgate.poc.v2' and 'mode' not in document}


def pull_image(host, reference):
    """Pull one digest-pinned image; a tag is never pulled."""
    if not launch_job.IMAGE_REFERENCE.fullmatch(reference):
        raise JobError('only NAME@sha256:DIGEST images are pulled')
    done = host.run(['/usr/bin/docker', 'pull', '--quiet', reference], capture_output=True, timeout=1800,
                    env={'PATH': '/usr/bin:/bin'})
    if done.returncode != 0:
        raise LaunchError('docker pull failed: ' + done.stderr.decode(errors='replace')[-800:])
    return {'pulled': reference}


def install_share(root, name, source, archive):
    import mounts
    mounts.check_name(name)
    result = mounts.install_snapshot(root, name, archive, record=False)
    share = mounts.snapshot_source(root, name)
    identity = {'name': name, 'source': source, 'files': result['files'], 'bytes': result['bytes'],
                'tree_sha256': tree_digest(share), 'installed_at': utc_now()}
    write_private(Path(root) / 'shares' / ('.' + name + '.json'), dump(identity))
    return identity


def snapshot_local(root, name, source, max_bytes=None, max_entries=None):
    import mounts
    mounts.check_name(name)
    mounts.check_source_rules(source, forbidden=(str(root),), home=None)
    mounts.check_live_directory(source)
    max_bytes = min(max_bytes or mounts.SNAPSHOT_MAX_BYTES, mounts.SNAPSHOT_MAX_BYTES)
    max_entries = min(max_entries or mounts.SNAPSHOT_MAX_ENTRIES, mounts.SNAPSHOT_MAX_ENTRIES)
    with tempfile.TemporaryDirectory(dir=str(root)) as directory:
        archive = Path(directory) / 'share.tar'
        mounts.build_snapshot(source, archive, max_bytes, max_entries)
        return install_share(root, name, source, archive)


def option(args, name, default, kind=int):
    if name in args:
        index = args.index(name)
        if index + 1 >= len(args):
            raise JobError('missing value for ' + name)
        value = args[index + 1]
        del args[index:index + 2]
        try:
            return kind(value)
        except ValueError:
            raise JobError('invalid value for ' + name) from None
    return default


def main(argv, host_factory=Host, root=ROOT, stdin=None, stdout=None):
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    if os.geteuid() != 0 and host_factory is Host:
        raise LaunchError('the launch runtime runs as root on the target')
    if not argv:
        raise JobError('usage: see the module documentation')
    args = list(argv[1:])
    command = argv[0]

    def out(value):
        stdout.write(dump(value) + b'\n')
        stdout.flush()

    host = host_factory(root)
    if command == 'capabilities' and not args:
        out(host.capabilities())
        return 0
    launches = launches_root(root)
    if command == 'run' and not args:
        raw = stdin.read(launch_job.MAX_JOB_BYTES + 1)
        try:
            fd = acquire(root)
        except Busy as error:
            out({'event': 'rejected', 'reason': 'busy', 'error': str(error)})
            raise
        emitter = Emitter(stdout.fileno() if hasattr(stdout, 'fileno') else 1)
        signalled = threading.Event()
        previous = signal.signal(signal.SIGTERM, lambda *_: signalled.set())
        parent = os.getppid()
        parent_ticks = process_start_ticks(parent)
        try:
            receipt = run_launch(raw, host, launches, emitter, lambda: process_alive(parent, parent_ticks),
                                 signalled.is_set)
        except (JobError, FileExistsError) as error:
            # Refused before anything ran; a repeated launch id never runs twice.
            reason = 'duplicate_launch' if isinstance(error, FileExistsError) else 'invalid_job'
            emitter.emit({'event': 'rejected', 'reason': reason, 'error': str(error)[:2000]})
            raise JobError(str(error)) from None
        finally:
            signal.signal(signal.SIGTERM, previous)
            emitter.close()
            os.close(fd)
        return 0 if receipt['state'] in ('stopped', 'expired') else 1
    if command == 'stop' and len(args) >= 1:
        grace = option(args, '--grace', 10)
        reason = option(args, '--reason', 'stop_requested', str)
        wait = option(args, '--wait', 0)
        if len(args) != 1 or not 0 <= wait <= 120:
            raise JobError('usage: stop ID [--grace S] [--reason R] [--wait S]')
        out(request_stop(launch_directory(launches, args[0]), host, grace, reason, root, wait))
        return 0
    if command in ('status', 'receipt') and len(args) == 1:
        directory = launch_directory(launches, args[0])
        if command == 'status':
            out(Record(directory).load())
        else:
            path = directory / 'receipt.json'
            if not path.exists():
                raise JobError('no receipt yet for ' + args[0])
            stdout.write(read_private(path, MAX_GUARD_RECEIPT) + b'\n')
        return 0
    if command == 'list' and not args:
        items = []
        for directory in sorted(launches.iterdir())[-500:]:
            try:
                data = Record(directory).load()
                items.append({'launch_id': directory.name, 'state': data.get('state'), 'reason': data.get('reason')})
            except (OSError, ValueError, LaunchError):
                items.append({'launch_id': directory.name, 'state': 'unreadable'})
        out(items)
        return 0
    if command == 'logs' and len(args) == 4:
        try:
            offset, limit = int(args[2]), int(args[3])
        except ValueError:
            raise JobError('OFFSET and LIMIT are integers') from None
        stdout.write(read_log(launch_directory(launches, args[0]), args[1], offset, limit))
        stdout.flush()
        return 0
    if command == 'reconcile':
        reason = option(args, '--reason', 'host_restarted', str)
        if args or reason not in ('host_restarted', 'launcher_lost'):
            raise JobError('usage: reconcile [--reason host_restarted|launcher_lost]')
        out(reconcile_all(root, host, reason))
        return 0
    if command == 'stage-profile' and len(args) == 2:
        out(stage_profile(root, host, args[0], args[1], stdin.read(16385)))
        return 0
    if command == 'pull' and len(args) == 1:
        out(pull_image(host, args[0]))
        return 0
    if command == 'snapshot':
        max_bytes = option(args, '--max-bytes', None)
        max_entries = option(args, '--max-entries', None)
        if len(args) != 2:
            raise JobError('usage: snapshot NAME SOURCE [--max-bytes N] [--max-entries N]')
        fd = acquire(root)
        try:
            out(snapshot_local(root, args[0], args[1], max_bytes, max_entries))
        finally:
            os.close(fd)
        return 0
    if command == 'install-snapshot' and len(args) == 3:
        fd = acquire(root)
        try:
            out(install_share(root, args[0], args[1], args[2]))
        finally:
            os.close(fd)
        return 0
    raise JobError('unknown command; see the module documentation')


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except Busy as error:
        print('agentgate-launch-busy: ' + str(error), file=sys.stderr)
        sys.exit(BUSY)
    except JobError as error:
        print('agentgate-launch-invalid: ' + str(error), file=sys.stderr)
        sys.exit(2)
    except Exception as error:
        print('agentgate-launch-error: %s: %s' % (type(error).__name__, error), file=sys.stderr)
        sys.exit(1)
