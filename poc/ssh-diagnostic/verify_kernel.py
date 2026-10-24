#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Logic of the kernel verification kit (verify-kernel.sh, verify-probe.sh).

The probe driver runs one real guarded launch on a disposable BPF LSM VM;
inside the target, the agent attempts every operation in CHECKS and prints one
"name outcome" line per attempt (outcome 0 or an errno name). This module
judges those lines against the expectations and writes the probe verdict. It
decides nothing about trust: the service attaches the report to a target and
decides whether to mark the kernel verified. The host agent never sets
kernel_verified itself. Nothing here has run on a BPF LSM kernel.

Commands:
  checks           print the expectation table as JSON
  judge CANARY     read probe lines on stdin, print the verdict JSON; CANARY is
                   the secret canary that must never appear in the agent's output
"""
import json
import sys

# Expectations:
#   allowed     the operation succeeds (outcome 0)
#   denied      the operation fails, with any error
#   permission  the operation fails with EPERM or EACCES: the guard refused it,
#               not a closed port, a timeout or a missing file
#   unreadable  the file cannot be opened at all (any error); its content never
#               appears in the output
CHECKS = [
    ('allow-write', 'allowed', 'write a file in the workspace'),
    ('allow-read', 'allowed', 'read it back'),
    ('allow-exec', 'allowed', 'run /bin/true'),
    ('allow-create', 'allowed', 'create a new file in the workspace with open(O_CREAT|O_EXCL)'),
    ('deny-read-shadow', 'denied', 'read /etc/shadow'),
    ('deny-write-usr', 'denied', 'create a file below /usr'),
    ('deny-exec-workspace', 'denied', 'execute a file from the writable workspace'),
    ('deny-hardlink', 'denied', 'hard-link /etc/hostname into the workspace'),
    ('deny-mknod', 'denied', 'create a character device node'),
    ('deny-mkfifo', 'denied', 'create a FIFO in the workspace'),
    ('deny-unix-bind', 'denied', 'bind an AF_UNIX socket to a workspace path'),
    ('deny-ptrace', 'denied', 'ptrace'),
    ('deny-private-ip', 'denied', 'connect to a private address outside the policy'),
    ('deny-foreign-dns', 'denied', 'send DNS to a resolver the policy does not list'),
    ('allow-broker-endpoint', 'allowed', "connect to the launch broker's exact address and port"),
    ('deny-broker-other-port', 'permission', 'connect to the broker address on another port'),
    ('deny-broker-gateway', 'permission', "connect to the broker network's gateway (.1)"),
    ('deny-broker-neighbour', 'permission', 'connect to another address in the broker /29'),
    ('deny-secret-mount', 'unreadable', "open the broker container's secret path"),
    ('deny-secret-store', 'unreadable', "open the host's secret store file"),
]

PERMISSION = ('EPERM', 'EACCES')


def parse(lines):
    outcomes = {}
    for line in lines:
        parts = line.split()
        if len(parts) == 2 and parts[0] not in outcomes:
            outcomes[parts[0]] = parts[1]
    return outcomes


def judge(text, canary):
    """Judge the agent's probe output; the canary must not appear anywhere in it."""
    outcomes = parse(text.splitlines())
    probes, ok = [], True
    for name, expected, description in CHECKS:
        got = outcomes.get(name, 'missing')
        if expected == 'allowed':
            passed = got == '0'
        elif expected == 'permission':
            passed = got in PERMISSION
        else:
            passed = got not in ('0', 'missing')
        ok = ok and passed
        probes.append({'name': name, 'expected': expected, 'errno': got, 'ok': passed, 'what': description})
    leaked = bool(canary) and canary in text
    probes.append({'name': 'secret-canary-absent', 'expected': 'absent', 'errno': 'n/a', 'ok': not leaked,
                   'what': "the host's secret canary never appears in the agent's output"})
    return {'ok': ok and not leaked, 'probes': probes}


def main(argv, stdin=sys.stdin, stdout=sys.stdout):
    if argv == ['checks']:
        json.dump([{'name': n, 'expected': e, 'what': d} for n, e, d in CHECKS], stdout, indent=2)
        stdout.write('\n')
        return 0
    if len(argv) == 2 and argv[0] == 'judge':
        verdict = judge(stdin.read(), argv[1])
        json.dump(verdict, stdout, indent=2, sort_keys=True)
        stdout.write('\n')
        return 0 if verdict['ok'] else 1
    sys.stderr.write(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
