#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Replace only the owned target's Docker-generated resolver file before attach."""
import json
import os
from pathlib import Path
import stat
import subprocess
from gateway import read_root_file
from settings import load_settings

root = Path(__file__).resolve().parent
settings = load_settings(root / 'settings.json')
item = json.loads(subprocess.check_output(['docker', 'inspect', settings['name']], timeout=5))[0]
container = item['Id']
if len(container) != 64 or any(c not in '0123456789abcdef' for c in container):
    raise ValueError('invalid owned target ID')
expected = '/var/lib/docker/containers/' + container + '/resolv.conf'
if item['ResolvConfPath'] != expected or str(Path(expected).resolve()) != expected:
    raise ValueError('invalid owned resolver path')
raw = read_root_file(root / 'resolv.conf')
fd = os.open(expected, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    meta = os.fstat(fd)
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0:
        raise ValueError('untrusted owned resolver file')
    os.ftruncate(fd, 0)
    os.write(fd, raw)
    os.fsync(fd)
finally:
    os.close(fd)
