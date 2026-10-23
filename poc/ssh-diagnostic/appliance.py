#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Start the guarded SSH POC in one Docker-managed disposable KVM VM.

Use "appliance.py grant --help" to grant or revoke access without editing JSON.
"""
import argparse
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import shlex
import subprocess
import sys

from appliance_common import (DEFAULT_BASE, LABEL, admin, inspect_owned,
    load, output, preflight, protected, ready_command, run, ssh, state_directory, wait_guest, write)
from appliance_build import build, revision
from appliance_guest import GUEST, audit, configure, health, transition
import grants

ROOT = Path(__file__).resolve().parent.parent.parent


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('start', 'status', 'audit', 'stop', 'policy'),
                        help='or "grant": see "appliance.py grant --help"')
    parser.add_argument('--state', default=str(Path.home() / '.local/share/agentgate/poc'))
    parser.add_argument('--policy', help='protected network policy JSON; policy action applies this file')
    parser.add_argument('--token-file', help='protected taskboard token; initial start only')
    parser.add_argument('--builder', help='reuse an owned idle Docker Buildx builder; optional')
    parser.add_argument('--coding-base', help='trusted Debian/Ubuntu compatible workload base image')
    parser.add_argument('--port', type=int, help='host loopback SSH port; default22365')
    parser.add_argument('--revision', help='source revision; defaults to the current Git commit')
    return parser.parse_args()


def key(state, name):
    if (state / name).exists() or (state / (name + '.pub')).exists():
        protected(state / name)
        expected = (state / (name + '.pub')).read_text().split()[:2]
        actual = output(['ssh-keygen', '-y', '-f', str(state / name)]).split()[:2]
        if expected != actual:
            raise ValueError('key binding differs; state retained')
        return
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'agentgate-' + name,
         '-f', str(state / name)])
    (state / name).chmod(0o600)


def validate_policy(state, binding, path):
    """Use the native validator in a bounded container, before a VM is created."""
    args = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cpus', '1',
            '--memory', '128m', '--pids-limit', '32', '--cap-drop', 'ALL',
            '--user', str(os.getuid()) + ':' + str(os.getgid()),
            '--mount', 'type=bind,source=' + str(path) + ',target=/policy.json,readonly',
            binding['images']['artifacts'], '/pilot-network-diagnostic', 'network-info', '/policy.json']
    return json.loads(output(args, timeout=15))


def new_binding(state, args):
    if not args.policy or not args.token_file:
        raise ValueError('initial start requires --policy FILE and --token-file FILE')
    if not (ROOT / 'ssh/Dockerfile').is_file():
        raise ValueError('run from the exported AgentGate source repository')
    policy = protected(Path(args.policy).absolute())
    token = protected(Path(args.token_file).absolute())
    if not 16 <= len(token.strip()) <=4096:
        raise ValueError('taskboard token length must be16..4096 bytes')
    port = args.port or 22365
    if not 1024 <= port <=65535:
        raise ValueError('choose a host loopback port from1024 through65535')
    owner = hashlib.sha256(str(state).encode()).hexdigest()[:16]
    if args.builder and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,100}', args.builder):
        raise ValueError('invalid owned builder name')
    binding = {'version':1, 'name':'ag-poc-' + owner, 'owner':owner, 'port':port,
               'revision':revision(ROOT, args.revision), 'coding_base':args.coding_base or DEFAULT_BASE,
               'policy_sha256':hashlib.sha256(policy).hexdigest(),
               'build_builder':args.builder or ('ag-poc-' + owner + '-build')}
    intent = state / 'initialization.json'
    if intent.exists():
        if json.loads(protected(intent)) != binding:
            raise ValueError('initialization binding differs; state retained')
    else:
        write(intent, json.dumps(binding, sort_keys=True).encode())
    write(state / 'policy.json', policy)
    write(state / 'taskboard.token', token)
    for name in ('management-key', 'workload-key', 'guest-host-key'):
        key(state, name)
    public = (state / 'guest-host-key.pub').read_text().split()
    write(state / 'known_hosts', (binding['name'] + ' ' + public[0] + ' ' + public[1] + '\n').encode())
    build(ROOT, state, binding)
    binding['policy_digest'] = validate_policy(state, binding, state / 'policy.json')['digest']
    write(state / 'binding.json', json.dumps(binding, sort_keys=True).encode())
    return binding


def matching(state, args, binding):
    """Refuse a different source, base, port, or policy without changing the state."""
    requested = revision(ROOT, args.revision)
    if getattr(args, 'builder', None) and args.builder != binding.get('build_builder'):
        raise ValueError('builder binding differs; state retained')
    if requested != binding['revision'] or args.coding_base and args.coding_base != binding['coding_base']:
        raise ValueError('source/base binding differs; use a new state directory')
    if args.port and args.port != binding['port']:
        raise ValueError('port binding differs; use a new state directory')
    if args.policy and hashlib.sha256(protected(Path(args.policy).absolute())).hexdigest() != binding['policy_sha256']:
        raise ValueError('policy binding differs: the instance policy changed through grant or the policy '
                         'command. Run start without --policy; use "grant" or "policy" for edits')
    if args.token_file and protected(Path(args.token_file).absolute()) != protected(state / 'taskboard.token'):
        raise ValueError('token binding differs; use a new state directory')
    if hashlib.sha256(protected(state / 'policy.json')).hexdigest() != binding['policy_sha256']:
        raise ValueError('stored policy binding differs; state retained')


def start_container(state, binding):
    item = inspect_owned(binding)
    if item:
        if not item['State']['Running']:
            run(['docker', 'start', binding['name']], stdout=subprocess.DEVNULL)
        return
    args = ['docker', 'run', '-d', '--init', '--name', binding['name'], '--restart', 'unless-stopped',
            '--label', LABEL + '=' + binding['owner'], '--stop-timeout', '45',
            '--cpus', '2', '--memory', '4g', '--pids-limit', '256', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--device', '/dev/kvm',
            '--user', str(os.getuid()) + ':' + str(os.getgid()),
            '--group-add', str(Path('/dev/kvm').stat().st_gid),
            '-p', '127.0.0.1:' + str(binding['port']) + ':23264',
            '--mount', 'type=bind,source=' + str(state) + ',target=/state', binding['images']['appliance']]
    run(args, stdout=subprocess.DEVNULL)


def start(state, args):
    existing = (state / 'binding.json').exists()
    binding = load(state) if existing else new_binding(state, args)
    if existing:
        # Finish or discard a grant an interruption left, before the binding is checked.
        grants.start_sync(state, binding, guest=False)
    matching(state, args, binding)
    start_container(state, binding)
    wait_guest(state, binding)
    configure(ROOT, state, binding)
    transition(state, binding, False)
    if binding.get('policy_pending'):
        # Grants made while stopped apply now, before the readiness command.
        grants.start_sync(state, binding)
    run(ssh(state, binding, 'workload-key') + ['true'], timeout=45, stdout=subprocess.DEVNULL)
    admin(state, binding, 'touch ' + GUEST + '/appliance-installed; chmod 0400 ' + GUEST + '/appliance-installed')
    result = health(state, binding)
    print('ready=true')
    print(result['ssh'] + ' \'python3 -c "print(6+6)"\'')


def apply_policy(state, binding, file):
    """Validate and apply an operator file through the same engine as grant."""
    if not file:
        raise ValueError('policy action requires --policy FILE')
    try:
        grants.apply_file(state, binding, file)
    except grants.GrantError as error:
        raise RuntimeError(str(error)) from None


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'grant':
        # grant needs Docker only for the appliance validator; it takes the same state lock.
        return grants.main(sys.argv[2:], 'python3 ' + shlex.quote(sys.argv[0]) + ' grant')
    args = arguments()
    preflight()
    state = state_directory(args.state)
    fd = os.open(state / 'control.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('another appliance or grant command is using ' + str(state) +
                               '; retry when it finishes') from None
        if args.action == 'start':
            return start(state, args)
        binding = load(state)
        item = inspect_owned(binding)
        if args.action == 'status':
            if item and item['State']['Running'] and binding.get('policy_pending'):
                print(json.dumps({'state': 'policy_pending', 'policy_digest': binding['policy_digest'],
                                  'hint': 'run: appliance.py grant sync'}))
            else:
                print(json.dumps(health(state, binding) if item and item['State']['Running'] else
                                 {'state': 'stopped', 'policy_pending': bool(binding.get('policy_pending'))}))
        elif args.action == 'audit':
            print(audit(state, binding) if item and item['State']['Running'] else protected(state / 'audit.jsonl').decode())
        elif args.action == 'stop':
            if item and item['State']['Running']:
                transition(state, binding, True); audit(state, binding)
                run(['docker', 'stop', '-t', '45', binding['name']], timeout=60, stdout=subprocess.DEVNULL)
            print('stopped=true state_audit_workspace_preserved=true')
        elif args.action == 'policy':
            if not item or not item['State']['Running']:
                raise ValueError('start the appliance before applying policy')
            apply_policy(state, binding, args.policy)
    finally:
        os.close(fd)

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print('agentgate-appliance-error: ' + str(error), file=sys.stderr)
        sys.exit(1)
