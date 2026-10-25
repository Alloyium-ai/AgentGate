# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Validate one launcher job: a verified launch handed over by agentgate-hostd.

agentgate-hostd verifies the service signature, the digest binding and the
deadline. This module checks the launch again on the target, with the same
rules, because it is the last step before Docker and the kernel: every value
that later reaches a shell, a Docker argument, a path or a cgroup name passes
through here first. Nothing here touches the system.
"""
import hashlib
import ipaddress
import json
import re
import shlex

JOB_VERSION = 'agentgate.launcher-job.v1'
SPEC_VERSION = 'agentgate.launch.v1'
MAX_JOB_BYTES = 256 << 10
LAUNCH_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}')
NAME = re.compile(r'[a-z0-9][a-z0-9-]{0,39}')
MOUNT_NAME = re.compile(r'[a-z0-9][a-z0-9_-]{0,31}')
DIGEST = re.compile(r'[a-f0-9]{64}')
IMAGE_ID = re.compile(r'sha256:[a-f0-9]{64}')
IMAGE_REFERENCE = re.compile(r'[a-z0-9][a-z0-9._/-]{0,127}@sha256:[a-f0-9]{64}')
ENV_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}')
PROGRAM = re.compile(r'[A-Za-z0-9._+/-]{1,255}')
WORKDIR = re.compile(r'/[A-Za-z0-9._/-]{1,255}')
WORKSPACE = '/var/lib/agentgate/workspace'
MOUNT_ROOT = '/var/lib/agentgate/mounts'
LIFETIMES = {'oneshot': (1, 3600), 'session': (60, 86400)}
MAX_ARGS = 64
MAX_ARG_BYTES = 4096
MAX_COMMAND_BYTES = 16384
MAX_ENV = 64
MAX_MOUNTS = 8
# Upper bounds for the host's own knobs.
MAX_STOP_GRACE_S = 30
MAX_LOG_BYTES = 64 << 20
MAX_UPLOAD_BYTES = 4 << 20
RESERVED_ENV = ('PATH', 'IFS', 'ENV', 'BASH_ENV', 'SHELLOPTS', 'PS4')
RESERVED_PREFIXES = ('LD_', 'AGENTGATE_', 'DYLD_')
MAX_SECRETS = 8
# The taskboard's AF_UNIX bridge volume. A launch target gets it only when the
# launch asks: its signed policy keeps the taskboard endpoint and its
# filesystem grants reading this path. A launch with a broker never does.
TASKBOARD_BRIDGE = '/run/agentgate/taskboard'
BROKER_KEYS = {'network', 'subnet', 'address', 'port', 'target_address', 'env'}
ROUTE = re.compile(r'[a-z0-9][a-z0-9-]{0,39}')


class JobError(ValueError):
    """A launcher job that must be refused before anything runs."""


def secret_like(name):
    """The contract's secret names: *_KEY, *_TOKEN, *_SECRET, *PASSWORD*, and close variants."""
    upper = name.upper()
    return (upper.endswith(('KEY', 'TOKEN', 'SECRET', 'SECRETS')) or
            any(part in upper for part in ('PASSWORD', 'PASSWD', 'CREDENTIAL', 'PRIVATE_KEY', 'API_KEY')))


def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise JobError('duplicate JSON key: ' + key)
        out[key] = value
    return out


def _no_constant(value):
    raise JobError('non-JSON number ' + value)


def parse_json(raw, limit=MAX_JOB_BYTES):
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > limit:
        raise JobError('launcher job exceeds %d bytes' % limit)
    try:
        return json.loads(raw, object_pairs_hook=_unique, parse_constant=_no_constant)
    except JobError:
        raise
    except (ValueError, UnicodeDecodeError) as error:
        raise JobError('launcher job is not valid JSON: ' + str(error)) from None


def text(value, label, pattern=None, limit=MAX_ARG_BYTES):
    if not isinstance(value, str) or '\x00' in value or not value or len(value.encode()) > limit:
        raise JobError('invalid ' + label)
    if pattern is not None and not pattern.fullmatch(value):
        raise JobError('invalid ' + label + ': ' + repr(value[:80]))
    return value


def integer(value, label, low, high):
    if type(value) is not int or not low <= value <= high:
        raise JobError('%s must be an integer %d..%d' % (label, low, high))
    return value


def check_program(program):
    text(program, 'agent program', PROGRAM, 255)
    if program.startswith('-') or '..' in program.split('/') or program.endswith('/') or \
       ('/' in program and not program.startswith('/')):
        raise JobError('agent program must be a plain name or an absolute path: ' + repr(program))
    return program


def check_mounts(mounts, capabilities):
    if mounts is None:
        return []
    if not isinstance(mounts, list) or len(mounts) > MAX_MOUNTS:
        raise JobError('mounts must be a list of at most %d entries' % MAX_MOUNTS)
    names, out = set(), []
    for item in mounts:
        if not isinstance(item, dict) or set(item) != {'name', 'source', 'mode'}:
            raise JobError('each mount needs exactly name, source and mode')
        name = text(item['name'], 'mount name', MOUNT_NAME, 32)
        if name in names:
            raise JobError('mount name repeats: ' + name)
        names.add(name)
        mode = item['mode']
        if mode not in ('read-only', 'snapshot', 'read-write'):
            raise JobError('mount mode must be read-only, snapshot or read-write')
        source = text(item['source'], 'mount source', None, 4096)
        if mode in ('read-only', 'read-write') and 'live-mounts' not in capabilities:
            raise JobError('mount %s needs a live host folder; this target does not advertise live-mounts '
                           '(use mode "snapshot")' % name)
        if mode == 'snapshot' and 'snapshots' not in capabilities:
            raise JobError('this target does not advertise snapshots')
        out.append({'name': name, 'source': source, 'mode': mode})
    return out


def check_workdir(workdir, mounts):
    if workdir is None:
        return WORKSPACE
    text(workdir, 'workdir', WORKDIR, 256)
    parts = workdir.split('/')[1:]
    if '' in parts or '.' in parts or '..' in parts:
        raise JobError('workdir must be a canonical absolute path')
    if workdir == WORKSPACE or workdir.startswith(WORKSPACE + '/'):
        return workdir
    for item in mounts:
        base = MOUNT_ROOT + '/' + item['name']
        if workdir == base or workdir.startswith(base + '/'):
            return workdir
    raise JobError('workdir must be the workspace or a mounted folder below ' + MOUNT_ROOT)


def check_env(env):
    if env is None:
        return {}
    if not isinstance(env, dict) or len(env) > MAX_ENV:
        raise JobError('env must be an object of at most %d names' % MAX_ENV)
    out = {}
    for name, value in env.items():
        text(name, 'environment name', ENV_NAME, 64)
        if name.upper() in RESERVED_ENV or name.upper().startswith(RESERVED_PREFIXES):
            raise JobError('environment name is reserved by the runtime: ' + name)
        if secret_like(name):
            raise JobError('environment name looks like a secret; secrets arrive only through "secrets": ' + name)
        if not isinstance(value, str) or '\x00' in value or len(value.encode()) > MAX_ARG_BYTES:
            raise JobError('invalid value for environment name ' + name)
        out[name] = value
    return out


def optional(value, empty):
    """The service's canonical spec may carry an empty value for an optional field."""
    return empty if value in (None, '', [], {}) else value


def same_mounts(requested, mounts):
    """The job's resolved mounts must be exactly the spec's requested mounts.

    Same count and, in order, name for name the same mode (agentgate-hostd's
    sameMounts applies the same rule). The source path is the service's
    resolution of the request; check_mounts and mounts.py validate it.
    """
    if not isinstance(requested, list) or len(requested) > MAX_MOUNTS:
        raise JobError('spec mounts must be a list of at most %d entries' % MAX_MOUNTS)
    if len(requested) != len(mounts):
        raise JobError('the launch job resolves %d mounts but its spec requests %d' % (len(mounts), len(requested)))
    for index, (want, got) in enumerate(zip(requested, mounts), 1):
        if not isinstance(want, dict) or set(want) != {'name', 'source', 'mode'}:
            raise JobError('each spec mount needs exactly name, source and mode')
        if want['name'] != got['name'] or want['mode'] != got['mode']:
            raise JobError('the launch job mount %d (%s, %s) differs from its spec' % (index, got['name'], got['mode']))


def check_spec(spec, capabilities, mounts):
    """Validate the launch spec; mounts are the job's resolved mounts (already checked)."""
    if not isinstance(spec, dict):
        raise JobError('the launch spec must be an object')
    allowed = {'version', 'name', 'target', 'mode', 'lifetime_seconds', 'agent', 'access', 'mounts',
               'secrets', 'approval'}
    required = {'version', 'name', 'mode', 'lifetime_seconds', 'agent', 'access'}
    if not required <= set(spec) or set(spec) - allowed:
        raise JobError('launch spec fields differ: missing %s, unknown %s' %
                       (sorted(required - set(spec)), sorted(set(spec) - allowed)))
    if spec['version'] != SPEC_VERSION:
        raise JobError('launch spec version must be ' + SPEC_VERSION)
    text(spec['name'], 'launch name', NAME, 40)
    mode = spec['mode']
    if mode not in LIFETIMES:
        raise JobError('mode must be oneshot or session')
    low, high = LIFETIMES[mode]
    integer(spec['lifetime_seconds'], mode + ' lifetime_seconds', low, high)
    if optional(spec.get('target'), None) is not None:
        text(spec['target'], 'target', None, 128)
    if optional(spec.get('approval'), None) is not None:
        text(spec['approval'], 'approval', None, 32)
    if not isinstance(spec['access'], dict) or not spec['access']:
        raise JobError('access must name a profile version or embed a document')
    same_mounts(optional(spec.get('mounts'), []), mounts)
    secrets = optional(spec.get('secrets'), [])
    if not isinstance(secrets, list) or len(secrets) > MAX_SECRETS:
        raise JobError('secrets must be a list of at most %d references' % MAX_SECRETS)
    refs = []
    for item in secrets:
        # A reference names a secret only; a value or path is never accepted.
        if not isinstance(item, dict) or set(item) != {'ref', 'expose'} or not isinstance(item['expose'], dict) or \
           set(item['expose']) != {'env'}:
            raise JobError('each secret reference needs exactly ref and expose.env')
        refs.append((text(item['ref'], 'secret ref', NAME, 40), text(item['expose']['env'], 'secret env', ENV_NAME, 64)))
    if len({ref for ref, _ in refs}) != len(refs) or len({env for _, env in refs}) != len(refs):
        raise JobError('secret refs and their environment names are unique')
    agent = spec['agent']
    if not isinstance(agent, dict) or not {'image', 'command'} <= set(agent) or \
       set(agent) - {'image', 'command', 'env', 'workdir'}:
        raise JobError('agent needs image and command, and may add env and workdir')
    image = agent['image']
    if not isinstance(image, str) or not (IMAGE_ID.fullmatch(image) or IMAGE_REFERENCE.fullmatch(image)):
        raise JobError('agent.image must be an immutable digest: sha256:HEX or NAME@sha256:HEX')
    command = agent['command']
    if not isinstance(command, list) or not 1 <= len(command) <= MAX_ARGS:
        raise JobError('agent.command must be a list of 1..%d arguments' % MAX_ARGS)
    for argument in command:
        text(argument, 'agent.command argument', None, MAX_ARG_BYTES)
    check_program(command[0])
    env = check_env(optional(agent.get('env'), None))
    workdir = check_workdir(optional(agent.get('workdir'), None), mounts)
    if sum(len(item.encode()) for item in command) + sum(len(k) + len(v.encode()) for k, v in env.items()) > \
            MAX_COMMAND_BYTES:
        raise JobError('agent command and environment exceed %d bytes' % MAX_COMMAND_BYTES)
    return {'name': spec['name'], 'mode': mode, 'lifetime_seconds': spec['lifetime_seconds'], 'image': image,
            'command': list(command), 'env': env, 'workdir': workdir, 'spec_lifetime_seconds': spec['lifetime_seconds'],
            'secret_refs': refs}


def check_broker(broker, launch_id, policy, refs, env):
    """Validate the broker block: the launch network the target joins and the base URLs the agent receives.

    The block names no path and no value: the broker container, its
    configuration and the secret files stay on the host side. It must match
    the signed policy's single exact endpoint, and each secret reference must
    receive exactly its route's base URL.
    """
    if broker is None:
        if refs:
            raise JobError('a launch with secrets needs its broker block')
        if policy.get('broker') is not None:
            raise JobError('the policy names a broker endpoint but the launch has no broker')
        return None
    if not refs:
        raise JobError('a broker block needs at least one secret reference')
    if not isinstance(broker, dict) or set(broker) != BROKER_KEYS:
        raise JobError('the broker block needs exactly ' + ', '.join(sorted(BROKER_KEYS)))
    if broker['network'] != 'agentgate-%s-broker' % launch_id:
        raise JobError('the broker network must be the launch network agentgate-LAUNCH-broker')
    try:
        subnet = ipaddress.IPv4Network(text(broker['subnet'], 'broker subnet', None, 18), strict=True)
        address = ipaddress.IPv4Address(text(broker['address'], 'broker address', None, 15))
        target = ipaddress.IPv4Address(text(broker['target_address'], 'broker target address', None, 15))
    except ValueError:
        raise JobError('the broker network addresses are invalid') from None
    if subnet.prefixlen != 29 or not subnet.is_private or str(subnet) != broker['subnet'] or \
       address != subnet.network_address + 2 or target != subnet.network_address + 3 or \
       str(address) != broker['address'] or str(target) != broker['target_address']:
        raise JobError('the broker network is a private /29 with the broker at .2 and the target at .3')
    port = integer(broker['port'], 'broker port', 1024, 65535)
    if policy.get('broker') != {'address': broker['address'], 'protocol': 'tcp', 'port': port} or 'taskboard' in policy:
        raise JobError("the policy's single exact endpoint must be exactly this broker")
    urls = broker['env']
    if not isinstance(urls, dict) or len(urls) != len(refs):
        raise JobError('the broker gives each secret reference exactly one base URL')
    for ref, name in refs:
        if name not in urls:
            raise JobError('secret %s has no base URL in the broker block' % ref)
        if name.upper() in RESERVED_ENV or name.upper().startswith(RESERVED_PREFIXES) or name in env:
            raise JobError('broker environment name is reserved or set twice: ' + name)
        if urls[name] != 'http://%s:%d/%s' % (broker['address'], port, ref) or not ROUTE.fullmatch(ref):
            raise JobError('broker base URL for %s must be http://ADDRESS:PORT/%s' % (name, ref))
    return {key: broker[key] for key in sorted(BROKER_KEYS - {'env'})} | {'port': port, 'env': dict(urls)}


def taskboard_bridge(policy, broker):
    """Whether the launch target gets the taskboard bridge volume (read-only).

    Only a launch whose effective policy names the taskboard endpoint and
    grants reading the bridge path asks for it; a launch with a broker (whose
    policy has no taskboard) and a policy without the path never get it.
    """
    read_only = policy['filesystem'].get('read_only') or []
    if not isinstance(read_only, list):
        raise JobError('the policy filesystem read_only list is invalid')
    return broker is None and isinstance(policy.get('taskboard'), dict) and TASKBOARD_BRIDGE in read_only


def check_job(raw, capabilities):
    """Return the validated launch, or raise JobError. raw is the job's bytes.

    lifetime_seconds is the effective lifetime: the spec lifetime, shortened
    by the host to what remains before the job's signed expiry. mounts are the
    resolved mounts of the signed job. policy is the effective launch document
    and policy_digest its native digest; profile_policy_digest is the digest
    of the exact policy bytes the service signed.
    """
    job = parse_json(raw)
    wanted = {'version', 'launch_id', 'job_id', 'spec', 'spec_digest', 'policy', 'policy_digest',
              'profile_policy_digest', 'stop_grace_seconds', 'log_limit_bytes', 'upload_limit_bytes',
              'lifetime_seconds', 'mounts', 'expires_at_ms', 'broker'}
    if not isinstance(job, dict) or set(job) != wanted or job['version'] != JOB_VERSION:
        raise JobError('launcher job fields differ from ' + JOB_VERSION)
    text(job['launch_id'], 'launch id', LAUNCH_ID, 64)
    text(job['job_id'], 'job id', LAUNCH_ID, 64)
    for key in ('spec_digest', 'policy_digest', 'profile_policy_digest'):
        text(job[key], key, DIGEST, 64)
    integer(job['stop_grace_seconds'], 'stop_grace_seconds', 0, MAX_STOP_GRACE_S)
    integer(job['log_limit_bytes'], 'log_limit_bytes', 4096, MAX_LOG_BYTES)
    integer(job['upload_limit_bytes'], 'upload_limit_bytes', 0, MAX_UPLOAD_BYTES)
    integer(job['expires_at_ms'], 'expires_at_ms', 1, 1 << 53)
    mounts = check_mounts(job['mounts'], capabilities)
    spec = check_spec(job['spec'], capabilities, mounts)
    low, high = LIFETIMES[spec['mode']]
    lifetime = integer(job['lifetime_seconds'], 'effective lifetime_seconds', low, min(high, spec['lifetime_seconds']))
    spec['lifetime_seconds'] = lifetime
    spec['mounts'] = mounts
    policy = job['policy']
    if not isinstance(policy, dict) or policy.get('mode') != spec['mode'] or \
       policy.get('duration_seconds') != lifetime or policy.get('version') != 'agentgate.poc.v2':
        raise JobError('the effective policy must be a version two launch document with the launch mode and lifetime')
    if not isinstance(policy.get('filesystem'), dict):
        raise JobError('a launch policy needs its filesystem section')
    broker = check_broker(job['broker'], job['launch_id'], policy, spec.pop('secret_refs'), spec['env'])
    if broker is not None:
        # The agent receives only the broker's base URLs, never a value.
        spec['env'] = dict(spec['env'], **broker['env'])
    spec['broker'] = broker
    spec['taskboard_bridge'] = taskboard_bridge(policy, broker)
    return {'launch_id': job['launch_id'], 'job_id': job['job_id'], 'spec_digest': job['spec_digest'],
            'policy': policy, 'policy_digest': job['policy_digest'],
            'profile_policy_digest': job['profile_policy_digest'],
            'stop_grace_seconds': job['stop_grace_seconds'], 'log_limit_bytes': job['log_limit_bytes'],
            'upload_limit_bytes': job['upload_limit_bytes'], 'expires_at_ms': job['expires_at_ms'], **spec}


def shell_command(launch):
    """The one string run-in-target.sh runs with /bin/sh -c --.

    Every name is validated above and every value is single-quoted; the agent
    replaces the shell with exec, so the shell never interprets agent text.
    """
    env = dict(launch['env'])
    env.setdefault('HOME', WORKSPACE)
    lines = ['export %s=%s' % (name, shlex.quote(value)) for name, value in sorted(env.items())
             if ENV_NAME.fullmatch(name)]
    lines.append('cd -- %s || exit 125' % shlex.quote(launch['workdir']))
    lines.append('exec ' + ' '.join(shlex.quote(item) for item in launch['command']))
    return '\n'.join(lines)


def mount_entries(launch):
    """mounts.py entries for the launch's validated mounts."""
    entries = []
    for item in launch['mounts']:
        if item['mode'] == 'snapshot':
            entries.append({'name': item['name'], 'kind': 'snapshot', 'read_only': True})
        else:
            entries.append({'name': item['name'], 'kind': 'bind', 'source': item['source'],
                            'read_only': item['mode'] == 'read-only'})
    return entries


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
