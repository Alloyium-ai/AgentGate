#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Logic of the kernel verification kit (verify-kernel.sh, verify-probe.sh).

The probe driver runs one real guarded launch on a disposable BPF LSM VM;
inside the target, the agent attempts every operation in CHECKS and prints one
"name outcome" line per attempt (outcome 0 or an errno name). Each guard-denied
operation is paired with a positive control that the SAME mechanism allows, so
a negative that fails for an unrelated reason (a read-only filesystem, a
dropped capability, a non-executable file, an unroutable address) cannot pass:
the control would then also fail, or the negative would show the wrong errno.

This module judges those lines against the expectations and, separately, the
driver cross-checks the launch receipt's host block: every operation the guard
was meant to deny must have recorded at least one denial there. A probe that
reports EACCES while the host evidence shows no denial for that operation (the
guard silently off, the error from elsewhere) fails the stage.

It decides nothing about trust: the service attaches the report to a target and
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
#   allowed     the operation succeeds (outcome 0); a positive control that the
#               same mechanism the paired negative exercises must allow
#   permission  the operation fails with EPERM or EACCES: the guard refused it,
#               not a closed port, a timeout, a read-only mount, a dropped
#               capability or a non-executable file
#   unreadable  the file cannot be opened at all (any error); its content never
#               appears in the output
CHECKS = [
    # Positive controls. Each exercises the mechanism its paired negative does.
    ('allow-write', 'allowed', 'write a file in the writable workspace'),
    ('allow-read', 'allowed', 'read that file back'),
    ('allow-create', 'allowed', 'create a new file with open(O_CREAT|O_EXCL) in the workspace'),
    ('allow-exec-tree', 'allowed', 'execute a real ELF (/bin/true) from an execute tree'),
    ('allow-read-sibling', 'allowed', 'read a world-readable file in a read_only tree, outside the deny tree'),
    # Filesystem negatives, each on a writable filesystem so only the guard denies.
    ('deny-read-tree', 'permission', 'read a world-readable file inside a deny tree'),
    ('deny-write-readonly', 'permission', 'write into a read_only tree on a writable filesystem'),
    ('deny-exec-nontree', 'permission', 'execute the same real ELF from a non-execute writable tree'),
    ('deny-mknod-regular', 'permission', 'mknod(2) a plain regular file in a writable tree'),
    ('deny-mkfifo', 'permission', 'mkfifo in a writable tree'),
    ('deny-unix-bind', 'permission', 'bind an AF_UNIX socket to a writable-tree path'),
    ('deny-hardlink', 'permission', 'hard-link within one filesystem'),
    # Process negative: a real attach that observes the kernel refusal.
    ('deny-ptrace', 'permission', 'PTRACE_ATTACH a sibling process'),
    # Network negatives: reachable private addresses and a denied resolver, EPERM from the hooks.
    ('allow-broker-endpoint', 'allowed', "connect to the launch broker's exact address and port"),
    ('deny-broker-other-port', 'permission', 'connect to the broker address on another port'),
    ('deny-broker-gateway', 'permission', "connect to the broker network's reachable gateway (.1)"),
    ('deny-broker-neighbour', 'permission', 'connect to another reachable address in the broker /29'),
    ('deny-foreign-dns', 'permission', 'send DNS to a resolver the policy does not list'),
    # The secret store and the broker's secret path never open; the canary never leaks.
    ('deny-secret-mount', 'unreadable', "open the broker container's secret path"),
    ('deny-secret-store', 'unreadable', "open the host's secret store file"),
]

PERMISSION = ('EPERM', 'EACCES')

# Each filesystem/process negative must leave a recorded denial for this host
# operation (hostguard.go operation names). The driver reads the counts from the
# receipt's host block; a probe that looks denied but recorded none fails.
REQUIRED_HOST_DENIALS = {
    'deny-read-tree': ('filesystem', 'read'),
    'deny-write-readonly': ('filesystem', 'write'),
    'deny-exec-nontree': ('filesystem', 'execute'),
    'deny-mknod-regular': ('filesystem', 'create'),
    'deny-mkfifo': ('filesystem', 'create'),
    'deny-unix-bind': ('filesystem', 'create'),
    'deny-hardlink': ('filesystem', 'hardlink'),
    'deny-ptrace': ('process', 'ptrace'),
}


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


def host_denial_counts(host):
    """Return {(part, operation): denied} from a receipt's host block."""
    counts = {}
    if not isinstance(host, dict):
        return counts
    for part in ('filesystem', 'process'):
        operations = (host.get(part) or {}).get('operations') or {}
        if not isinstance(operations, dict):
            continue
        for name, entry in operations.items():
            if isinstance(entry, dict):
                counts[(part, name)] = int(entry.get('denied') or 0)
    return counts


def required_denials(outcomes, host):
    """Confirm every guard negative the probe saw denied left a recorded host denial.

    outcomes maps a probe name to its errno; host is the receipt's host block.
    Returns a list of probe dicts, one per required operation, failing when the
    operation recorded no denial even though the probe was supposed to deny it.
    """
    counts = host_denial_counts(host)
    seen = {}
    for name, (part, operation) in REQUIRED_HOST_DENIALS.items():
        seen.setdefault((part, operation), []).append(name)
    probes = []
    for (part, operation), names in sorted(seen.items()):
        denied = counts.get((part, operation), 0)
        probes.append({'name': 'host-denial-%s-%s' % (part, operation), 'expected': 'recorded>=1',
                       'errno': 'denied=%d' % denied, 'ok': denied >= 1,
                       'what': 'the guard recorded a %s %s denial for %s' % (part, operation, ', '.join(sorted(names)))})
    return probes


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
