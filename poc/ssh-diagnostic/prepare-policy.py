#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Snapshot the current operator policy before each command. Invalid input fails closed."""
import os
from pathlib import Path
from gateway import read_root_file
from settings import effective_policy, load_settings

root = Path(__file__).resolve().parent
raw = read_root_file(root / 'policy.json')
fd = os.open(root / 'policy-active.json', os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'wb') as output:
    output.write(raw)
    output.flush()
    os.fsync(output.fileno())
info = effective_policy(root, load_settings(root / 'settings.json'))
# Docker custom networks use an embedded loopback resolver. Replace only this
# owned target's generated file before attach; the BPF guard denies loopback.
resolvers = info['document']['dns']['resolvers']
(root / 'resolv.conf').write_text(''.join('nameserver ' + ip + '\n' for ip in resolvers) +
                                  'options timeout:2 attempts:3\n')
(root / 'resolv.conf').chmod(0o600)
