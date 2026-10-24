#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Validate protected inputs for the isolated diagnostic scripts."""
import ipaddress
import json
from pathlib import Path
import re
import shlex
import sys
import subprocess
from urllib.parse import urlsplit

from gateway import read_root_file


def validate_settings(data, root):
    """Return shell variables from exact, validated diagnostic settings."""
    required = {'instance', 'source', 'policy_format',
                'target_image', 'bridge_image', 'taskboard_url', 'task_id', 'ipv6_subnet'}
    if set(data) != required or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,31}', data['instance']):
        raise ValueError('invalid diagnostic settings')
    if str(root) != '/var/lib/agentgate-poc-' + data['instance']:
        raise ValueError('install below /var/lib/agentgate-poc-INSTANCE')
    for key, pattern in [('source', r'[a-f0-9]{40}'),
                         ('target_image', r'sha256:[a-f0-9]{64}'),
                         ('bridge_image', r'sha256:[a-f0-9]{64}')]:
        if not isinstance(data[key], str) or not re.fullmatch(pattern, data[key]):
            raise ValueError('invalid diagnostic digest: ' + key)
    if data['policy_format'] not in ('agentgate.network-poc.v1', 'agentgate.poc.v2'):
        raise ValueError('invalid network policy format')
    url = urlsplit(data['taskboard_url'])
    host = ipaddress.ip_address(url.hostname or '')
    if (url.scheme != 'http' or url.username or url.password or url.path != '/' or
            url.query or url.fragment or not url.port or not host.is_private or
            host.is_loopback or host.is_link_local or host.is_multicast or
            url.geturl() != data['taskboard_url']):
        raise ValueError('a private literal HTTP taskboard endpoint is required')
    if type(data['task_id']) is not int or data['task_id'] < 1:
        raise ValueError('invalid task id')
    subnet = ipaddress.ip_network(data['ipv6_subnet'], strict=True)
    if subnet.version != 6 or subnet.prefixlen != 64 or not subnet.is_private:
        raise ValueError('an owned private IPv6 /64 is required')
    prefix = 'ag-mvp-' + data['instance']
    result = dict(data)
    result.update(root=str(root), poc=str(root), diag=str(root), component=str(root),
                  domain='/sys/fs/cgroup/' + prefix + '-domain',
                  cgroup='/sys/fs/cgroup/' + prefix + '-domain',
                  pins='/sys/fs/bpf/ag-mvp-net-' + prefix + '-domain',
                  host_pins='/sys/fs/bpf/ag-mvp-host-' + prefix + '-domain',
                  name=prefix + '-target', target=prefix + '-target', network=prefix + '-net',
                  workspace=prefix + '-work', bridge=prefix + '-bridge-volume',
                  bridge_container=prefix + '-bridge', bridge_network=prefix + '-bridge-net',
                  artifact='/run/agentgate/poc-' + data['instance'] + '/streams')
    return result


def load_settings(path):
    path = Path(path)
    return validate_settings(json.loads(read_root_file(path)), path.parent)


def effective_policy(root, data):
    """Read the protected per-command snapshot through the native validator."""
    path = root / 'policy-active.json'
    read_root_file(path)
    result = subprocess.check_output([str(root / 'pilot-network-diagnostic'),
                                      'network-info', str(path)], timeout=5)
    info = json.loads(result)
    board = info['document']['taskboard']
    url = urlsplit(data['taskboard_url'])
    if (board['address'] != url.hostname or board['port'] != url.port or
            board['task_id'] != data['task_id']):
        raise ValueError('policy taskboard differs from the isolated bridge; configure a new instance')
    return info


def resolver_file(resolvers):
    """The owned target's resolver file for the policy's exact resolvers."""
    return ''.join('nameserver ' + ip + '\n' for ip in resolvers) + 'options timeout:2 attempts:3\n'


def shell_assignments(values):
    """Render values for the trusted scripts' eval: fixed key names, every value quoted."""
    lines = []
    for key, value in values.items():
        if not re.fullmatch(r'[a-z][a-z0-9_]*', key):
            raise ValueError('invalid settings key')
        lines.append(f'{key}={shlex.quote(str(value))}')
    return '\n'.join(lines)


if __name__ == '__main__':
    path = Path(sys.argv[1])
    values = load_settings(path)
    info = effective_policy(path.parent, values)
    values['policy'] = info['digest']
    # The active policy, not the install-time format, decides the host controls.
    values['host_controls'] = '1' if info['document'].get('filesystem') is not None else '0'
    print(shell_assignments(values))
