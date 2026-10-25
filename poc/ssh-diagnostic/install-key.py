#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Add one public key with the fixed diagnostic forced command."""
import base64
import os
from pathlib import Path
import stat
import sys

root = Path(__file__).resolve().parent
source = Path(sys.argv[1]) if len(sys.argv) == 2 else root / 'poc-key.pub'
if len(sys.argv) > 2 or source.parent != root or not source.name.endswith('.pub'):
    raise ValueError('invalid public key path')
fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
try:
    meta = os.fstat(fd)
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o077:
        raise ValueError('untrusted public key file')
    public = os.read(fd, 8193).decode('ascii').strip()
finally:
    os.close(fd)
parts = public.split()
if len(parts) not in (2, 3) or parts[0] != 'ssh-ed25519':
    raise ValueError('invalid public key')
if len(base64.b64decode(parts[1], validate=True)) < 48:
    raise ValueError('invalid public key encoding')
target = Path('/root/.ssh/authorized_keys')
lines = target.read_text().splitlines()
if not lines or any(parts[1] in line for line in lines):
    raise ValueError('public key already installed or management key missing')
forced = str(root / 'operator-gateway.py')
lines.append(f'restrict,command="{forced}" {parts[0]} {parts[1]}')
temporary = target.with_name('authorized_keys.agentgate-new')
fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'w') as output:
    output.write('\n'.join(lines) + '\n')
    output.flush()
    os.fsync(output.fileno())
os.replace(temporary, target)
fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
print('owned_poc_key_added=true management_keys_preserved=true')
