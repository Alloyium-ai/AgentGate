#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
#
# Staged kernel verification for a disposable BPF-LSM VM. It runs preflight,
# loads every BPF object (reporting each program's verifier result verbatim),
# then drives one real guarded launch and probes positive and negative
# behaviour. It emits a JSON report the service attaches to a target; the
# service, never this script, decides kernel_verified.
#
# It REFUSES to run without the disposable-VM marker, and cleans up after
# itself. It cannot run in the build sandbox (no BPF-LSM kernel, no Docker);
# its logic is unit-tested with fakes (see test_verify_kernel.py).
#
# Usage:
#   verify-kernel.sh --instance NAME [--report FILE] [--keep]
#   verify-kernel.sh --self-check            # argument and environment checks only
# Environment hooks (for the tests; empty on a real VM):
#   AGENTGATE_VERIFY_ROOT   instance root override (default /var/lib/agentgate-poc-NAME)
#   AGENTGATE_VERIFY_MARKER disposable-VM marker path (default /etc/alloyium-disposable-vm)
#   AGENTGATE_VERIFY_FAKE   a directory of stand-in docker/guard commands on PATH
set -u

PROGRAM=verify-kernel.sh
MARKER=${AGENTGATE_VERIFY_MARKER:-/etc/alloyium-disposable-vm}
INSTANCE=
REPORT=
KEEP=0
SELF_CHECK=0

die() { printf '%s: %s\n' "$PROGRAM" "$1" >&2; exit "${2:-1}"; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --instance) shift; INSTANCE=${1:-}; [ -n "$INSTANCE" ] || die 'missing instance name' 2 ;;
    --report) shift; REPORT=${1:-}; [ -n "$REPORT" ] || die 'missing report path' 2 ;;
    --keep) KEEP=1 ;;
    --self-check) SELF_CHECK=1 ;;
    *) die "unknown argument: $1" 2 ;;
  esac
  shift || true
done

# A disposable VM marker is mandatory; this script creates and destroys
# guarded containers and must never run on a real machine.
require_marker() {
  [ -r "$MARKER" ] || die "refusing to run: the disposable-VM marker $MARKER is absent" 3
  case "$(cat "$MARKER" 2>/dev/null)" in
    kernel-poc-*) ;;
    *) die "refusing to run: $MARKER does not mark a disposable VM" 3 ;;
  esac
}

valid_instance() {
  case "$INSTANCE" in
    '' ) die 'an --instance NAME is required' 2 ;;
    *[!a-z0-9-]* | -* ) die 'the instance name may use only a-z 0-9 and -' 2 ;;
  esac
}

require_marker
valid_instance
[ "$(id -u)" -eq 0 ] || die 'the verification kit runs as root on the VM' 4

ROOT=${AGENTGATE_VERIFY_ROOT:-/var/lib/agentgate-poc-$INSTANCE}
[ -d "$ROOT" ] || die "instance root $ROOT is absent; configure the instance first" 4
GUARD="$ROOT/pilot-network-diagnostic"
[ -x "$GUARD" ] || die "guard binary $GUARD is absent" 4
WORK=$(mktemp -d "${TMPDIR:-/tmp}/agentgate-verify.XXXXXX") || die 'cannot make a work directory'
cleanup() { [ "$KEEP" -eq 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT

python3 - "$WORK/report.json" "$INSTANCE" "$ROOT" <<'PY'
import json, sys
path, instance, root = sys.argv[1:4]
json.dump({'version': 'agentgate.kernel-verification.v1', 'instance': instance, 'root': root,
           'checks': [], 'kernel': None, 'ok': False, 'probes': [], 'denials': []},
          open(path, 'w'))
PY

record() {  # stage name, ok(0/1), detail (verbatim), optional raw-json file
  python3 - "$WORK/report.json" "$1" "$2" "$3" "${4:-}" <<'PY'
import json, sys
path, stage, ok, detail, raw = (sys.argv + [''])[1:6]
report = json.load(open(path))
entry = {'stage': stage, 'ok': ok == '1', 'detail': detail[:20000]}
if raw:
    try:
        entry['data'] = json.load(open(raw))
    except (OSError, ValueError):
        entry['detail'] += ' (unreadable detail)'
report['checks'].append(entry)
json.dump(report, open(path, 'w'))
PY
}

if [ "$SELF_CHECK" -eq 1 ]; then
  record self-check 1 'arguments, marker, root and guard binary verified'
  [ -n "$REPORT" ] && install -m 0600 "$WORK/report.json" "$REPORT"
  echo verify_self_check=ok >&2
  exit 0
fi

# Stage 1: preflight. The guard reports the exact refusal if the kernel is wrong.
if "$GUARD" preflight >"$WORK/preflight.json" 2>"$WORK/preflight.err"; then
  record preflight 1 "$(cat "$WORK/preflight.err")" "$WORK/preflight.json"
else
  record preflight 0 "$(cat "$WORK/preflight.err"; cat "$WORK/preflight.json")" "$WORK/preflight.json"
fi

# Stage 2: load every BPF object on its own. The verifier log of each failing
# program is reported verbatim; fs_access.bpf.c is being changed because
# path_mknod cannot call bpf_d_path on 6.8, so the raw log matters most here.
if "$GUARD" load-check "$ROOT/network_policy.bpf.o" "$ROOT/fs_access.bpf.o" "$ROOT/process_guard.bpf.o" \
    >"$WORK/load.json" 2>"$WORK/load.err"; then
  record bpf-load 1 "$(cat "$WORK/load.err")" "$WORK/load.json"
else
  record bpf-load 0 "$(cat "$WORK/load.err")" "$WORK/load.json"
fi

# Stage 3: a validation-time check that a more-specific allow beneath a deny is
# rejected. If it ever validates, deny trees would not be absolute.
cat >"$WORK/bad-policy.json" <<JSON
{"version":"agentgate.poc.v2","default":"deny","ipv6":"deny","duration_seconds":25,
 "dns":{"resolvers":["1.1.1.1"],"protocols":["udp","tcp"],"port":53},
 "web":{"destination":"public-ipv4","rules":[{"protocol":"tcp","port":443}]},
 "taskboard":{"address":"10.0.0.2","protocol":"tcp","port":8080,"task_id":1},
 "filesystem":{"read_only":["/etc"],"scratch":["/var/lib/agentgate/workspace"],
   "execute":["/usr"],"deny":["/etc/secret"],"devices":[]},
 "process":{"signals":["TERM"]}}
JSON
# Place a more-specific allowance inside the deny tree.
python3 - "$WORK/bad-policy.json" <<'PY'
import json, sys
path = sys.argv[1]
doc = json.load(open(path))
doc['filesystem']['read_only'].append('/etc/secret/readable')
json.dump(doc, open(path, 'w'))
PY
if "$GUARD" network-info "$WORK/bad-policy.json" >"$WORK/overlap.out" 2>"$WORK/overlap.err"; then
  record deny-overrides-allow 0 "a more-specific allow beneath a deny validated: $(cat "$WORK/overlap.out")"
else
  record deny-overrides-allow 1 "rejected as expected: $(cat "$WORK/overlap.err")"
fi

# Stage 4: behaviour probes through a real guarded launch. The probe program
# runs inside the target (it entered via nsenter), so bpf_d_path must render
# container-absolute paths that match the policy selectors; a host-side overlay
# path would make selectors silently stop matching. These need Docker and the
# BPF-LSM kernel; the harness exposes them through AGENTGATE_VERIFY_FAKE for the
# tests and the real guard on the VM.
if [ -n "${AGENTGATE_VERIFY_FAKE:-}" ]; then
  PATH="$AGENTGATE_VERIFY_FAKE:$PATH"
fi
PROBE_SCRIPT="$ROOT/verify-probe.sh"
if [ -x "$PROBE_SCRIPT" ]; then
  if "$PROBE_SCRIPT" "$WORK/probes.json" >"$WORK/probes.log" 2>&1; then
    record probes 1 "$(cat "$WORK/probes.log")" "$WORK/probes.json"
  else
    record probes 0 "$(cat "$WORK/probes.log")" "$WORK/probes.json"
  fi
else
  record probes 0 "no probe driver at $PROBE_SCRIPT; behaviour was not exercised"
fi

# Finalise: ok only when every stage passed. kernel_verified stays absent; the
# service sets it from this report.
python3 - "$WORK/report.json" <<'PY'
import json, sys
path = sys.argv[1]
report = json.load(open(path))
checks = report['checks']
report['ok'] = bool(checks) and all(c['ok'] for c in checks)
for c in checks:
    data = c.get('data') or {}
    if c['stage'] == 'preflight':
        report['kernel'] = data.get('kernel')
    if c['stage'] == 'probes':
        report['probes'] = data.get('probes', [])
        report['denials'] = data.get('denials', [])
json.dump(report, open(path, 'w'), indent=2, sort_keys=True)
PY

if [ -n "$REPORT" ]; then
  install -m 0600 "$WORK/report.json" "$REPORT" || die "cannot write the report to $REPORT"
fi
cat "$WORK/report.json"
if python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["ok"] else 1)' "$WORK/report.json"; then
  echo verify_kernel=passed >&2
  exit 0
fi
echo verify_kernel=failed >&2
exit 5
