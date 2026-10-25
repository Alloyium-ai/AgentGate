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
driver cross-checks the launch receipt's host block: every negative the guard
was meant to deny must have left its OWN denial record there, for its operation
and, where the hook resolves one, its exact path (EXPECTED_HOST_DENIALS). A
probe that reports EACCES while no matching record exists (the guard silently
off, the error from elsewhere, or a denial of some other path such as Python
writing __pycache__ under /usr) fails the stage.

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
    ('deny-write-readonly', 'permission', 'open an existing file of a read_only tree for writing, on a writable filesystem'),
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

# Each filesystem/process negative must leave its own denial record in the
# receipt's host block: (part, operation, path, reason), operation named as in
# hostguard.go, path relative to the fixtures mount as $MOUNT. Hooks that never
# resolve a path record none: path_mknod for mknod(2), mkfifo and an AF_UNIX
# bind (reason 7: a node not made by open(O_CREAT)), path_link (reason 7) and
# ptrace. Those probes each need one path-less record of their operation, so
# the three create probes need three. An open(O_CREAT) is decided as create in
# file_open on the new file's path, which is why the write probe opens an
# existing file: a new name would record create, not write. None matches any
# reason.
EXPECTED_HOST_DENIALS = {
    'deny-read-tree': ('filesystem', 'read', '$MOUNT/blocked/secret', None),
    'deny-write-readonly': ('filesystem', 'write', '$MOUNT/ro/data', None),
    'deny-exec-nontree': ('filesystem', 'execute', '$MOUNT/elf/true', None),
    'deny-mknod-regular': ('filesystem', 'create', None, 7),
    'deny-mkfifo': ('filesystem', 'create', None, 7),
    'deny-unix-bind': ('filesystem', 'create', None, 7),
    'deny-hardlink': ('filesystem', 'hardlink', None, 7),
    'deny-ptrace': ('process', 'ptrace', None, None),
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


def host_denials(host):
    """Return the receipt host block's denial records as (part, operation, path, reason).

    A path is None when the record has none; anything malformed is skipped.
    """
    out = []
    if not isinstance(host, dict):
        return out
    for part in ('filesystem', 'process'):
        records = (host.get(part) or {}).get('denials') or []
        if not isinstance(records, list):
            continue
        for d in records:
            if isinstance(d, dict) and isinstance(d.get('operation'), str):
                path = d.get('path') if isinstance(d.get('path'), str) and d.get('path') else None
                reason = d.get('reason') if isinstance(d.get('reason'), int) else None
                out.append((part, d['operation'], path, reason))
    return out


def required_denials(outcomes, host, mount):
    """Match every guard negative to its own recorded denial in the host block.

    outcomes maps a probe name to its errno (unused: the judge checks it);
    host is the receipt's host block and mount the fixtures mount inside the
    target. Each record satisfies at most one probe, so a denial of some other
    path, or one create denial for three create probes, fails the probes it
    cannot cover. Returns one probe dict per negative.
    """
    records = host_denials(host)
    used = set()
    truncated = any(bool((host.get(part) or {}).get('denials_truncated')) for part in ('filesystem', 'process')) \
        if isinstance(host, dict) else False
    probes = []
    # Probes with an exact path first, so a path-less probe never takes their record.
    for name in sorted(EXPECTED_HOST_DENIALS, key=lambda n: (EXPECTED_HOST_DENIALS[n][2] is None, n)):
        part, operation, path, reason = EXPECTED_HOST_DENIALS[name]
        want = path.replace('$MOUNT', mount) if path else None
        match = None
        for i, (rpart, roperation, rpath, rreason) in enumerate(records):
            if i in used or (rpart, roperation, rpath) != (part, operation, want):
                continue
            if reason is not None and rreason != reason:
                continue
            match = i
            break
        if match is not None:
            used.add(match)
        what = 'the guard recorded a %s %s denial %s for %s' % (part, operation, 'of ' + want if want else 'without a path', name)
        if match is None and truncated:
            what += ' (the receipt truncated its denial list)'
        probes.append({'name': 'host-denial-' + name, 'expected': '%s %s %s' % (part, operation, want or '(no path)'),
                       'errno': 'matched' if match is not None else 'unmatched', 'ok': match is not None, 'what': what})
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
