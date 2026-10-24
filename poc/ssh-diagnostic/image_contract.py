# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Validate the Debian/Ubuntu coding image before installing an SSH key or launching an agent."""
import json
import re
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

# A long-running agent additionally needs: a keepalive (sleep) for the target's
# main process, and an agent program that the image itself provides from an
# executable tree, never from a writable or mounted one.
LAUNCH_PROBE = """import os, shutil, stat, sys
from pathlib import Path
assert any(os.access(name, os.X_OK) for name in ('/bin/sleep', '/usr/bin/sleep')), 'sleep'
program = sys.argv[1]
if '/' not in program:
 program = shutil.which(program, path='/usr/local/bin:/usr/bin:/bin') or ''
assert program.startswith('/'), 'agent program not found in /usr/local/bin:/usr/bin:/bin'
real = os.path.realpath(program)
for tree in ('/var/lib/agentgate', '/tmp', '/run', '/dev', '/proc'):
 assert not (real == tree or real.startswith(tree + '/')), 'agent program in a writable or mounted tree: ' + real
meta = os.stat(real)
assert stat.S_ISREG(meta.st_mode) and os.access(real, os.X_OK), 'agent program not executable: ' + real
assert not meta.st_mode & 0o022, 'agent program is group or world writable: ' + real
print('launch_image_contract=passed program=' + real)
"""

PROGRAM = re.compile(r'[A-Za-z0-9._+/-]{1,255}')
DIGEST = re.compile(r'sha256:[a-f0-9]{64}')


def contract_run(reference, entrypoint_args):
    return ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none',
            '--read-only', '--user', '65534:65534', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--cpus', '1', '--memory', '128m',
            '--pids-limit', '32', '--entrypoint', '/usr/bin/python3', reference] + entrypoint_args


def check_program(program):
    """The agent program name reaches Docker as one argument; refuse anything odd."""
    if not isinstance(program, str) or not PROGRAM.fullmatch(program) or program.startswith('-') or \
       '..' in program.split('/') or program.endswith('/'):
        raise ValueError('agent program must be a plain name or absolute path: ' + repr(program))
    return program


def validate_image(reference, program=None, run=None, check_output=None):
    """Run the image contract without a network, host mounts, or secrets.

    With program, also run the launch contract for a long-running agent.
    """
    run = run or subprocess.run
    check_output = check_output or subprocess.check_output
    item = json.loads(check_output(['docker', 'image', 'inspect', reference], timeout=5))[0]
    if item['Config'].get('Volumes'):
        raise ValueError('coding image declares unapproved volumes')
    run(contract_run(reference, ['-c', PROBE]), check=True, timeout=15)
    if program is not None:
        if not DIGEST.fullmatch(reference):
            raise ValueError('a launch image is checked by its content digest')
        run(contract_run(reference, ['-c', LAUNCH_PROBE, check_program(program)]), check=True, timeout=15)
    return item
