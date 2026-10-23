# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Validate the Debian/Ubuntu coding image before installing an SSH key."""
import json
import subprocess

PROBE = """import os
from pathlib import Path
assert os.getuid() == 65534 and os.getgid() == 65534
for name in ('/bin/sh','/usr/bin/setpriv','/usr/bin/python3','/usr/bin/curl'):
 assert os.access(name, os.X_OK), name
for name in ('/var/lib/agentgate/workspace','/run/agentgate/streams'):
 assert Path(name).is_dir(), name
# Host folder mounts land below this directory. A symlink here would redirect them.
for name in ('/var/lib/agentgate','/var/lib/agentgate/mounts'):
 assert not Path(name).is_symlink() and (not Path(name).exists() or Path(name).is_dir()), name
print('coding_image_contract=passed')
"""

def validate_image(reference):
    """Run the image contract without a network, host mounts, or secrets."""
    item = json.loads(subprocess.check_output(['docker', 'image', 'inspect', reference], timeout=5))[0]
    if item['Config'].get('Volumes'):
        raise ValueError('coding image declares unapproved volumes')
    subprocess.run(['docker', 'run', '--rm', '--pull', 'never', '--network', 'none',
                    '--read-only', '--user', '65534:65534', '--cap-drop', 'ALL',
                    '--security-opt', 'no-new-privileges', '--cpus', '1', '--memory', '128m',
                    '--pids-limit', '32', '--entrypoint', '/usr/bin/python3', reference,
                    '-c', PROBE], check=True, timeout=15)
