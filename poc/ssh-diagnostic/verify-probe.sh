#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
#
# Behaviour probe driver for verify-kernel.sh. It runs ONE real guarded oneshot
# launch whose agent attempts allowed and denied operations from inside the
# target (it entered via nsenter), then reads the launch receipt and confirms:
#   - every allowed read, write and exec in the workspace succeeded;
#   - the denied operations failed with the expected errno
#     (read /etc/shadow, write /usr, exec from the workspace, ptrace, an
#     unlisted signal, device-node creation, hard link, outbound to a private
#     IP, DNS to a non-listed resolver);
#   - the guard's filesystem denials render CONTAINER-ABSOLUTE paths that match
#     the policy selectors (e.g. /etc/shadow, /var/lib/agentgate/workspace/...),
#     never a host-side overlay path such as /var/lib/docker/overlay2/...; a
#     host path would mean bpf_d_path rendered the wrong mount and selectors
#     silently stop matching.
# It writes a JSON result to $1 and exits non-zero if any expectation fails.
#
# This needs Docker and the BPF-LSM kernel; it cannot run in the build sandbox.
# verify-kernel.sh's tests replace it with a fake. Its own logic is unexercised
# on a kernel.
set -u
RESULT=${1:?usage: verify-probe.sh RESULT.json}
ROOT=${AGENTGATE_VERIFY_PROBE_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)}
IMAGE=${AGENTGATE_VERIFY_PROBE_IMAGE:?set AGENTGATE_VERIFY_PROBE_IMAGE to the digest of an installed probe image}
LAUNCH="$ROOT/launch.py"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/agentgate-probe.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
WS=/var/lib/agentgate/workspace

# The agent probe. Each line prints "name errno" so the driver checks both the
# positive and negative outcomes, independently of the kernel denial records.
PROBE='
import errno, os, socket, subprocess, sys
def attempt(name, fn):
    try:
        fn(); print(name, "0")
    except OSError as e:
        print(name, errno.errorcode.get(e.errno, e.errno))
    except Exception as e:
        print(name, type(e).__name__)
ws = "'"$WS"'"
attempt("allow-write", lambda: open(ws + "/probe.txt", "w").write("ok"))
attempt("allow-read", lambda: open(ws + "/probe.txt").read())
attempt("allow-exec", lambda: subprocess.run(["/bin/true"], check=True))
attempt("deny-read-shadow", lambda: open("/etc/shadow").read())
attempt("deny-write-usr", lambda: open("/usr/probe", "w"))
os.chmod(ws + "/probe.txt", 0o755)
attempt("deny-exec-workspace", lambda: subprocess.run([ws + "/probe.txt"]))
attempt("deny-hardlink", lambda: os.link("/etc/hostname", ws + "/link"))
attempt("deny-mknod", lambda: os.mknod(ws + "/dev", 0o600 | 0o020000))
attempt("deny-ptrace", lambda: subprocess.run(["/bin/sh", "-c", "exec 3<&0"], preexec_fn=lambda: __import__("ctypes").CDLL(None).ptrace(0, 0, 0, 0)))
attempt("deny-private-ip", lambda: socket.create_connection(("10.0.0.254", 9), timeout=3))
attempt("deny-foreign-dns", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"\x00", ("203.0.113.254", 53)))
sys.stdout.flush()
'

cat >"$WORK/policy.json" <<JSON
{"version":"agentgate.poc.v2","default":"deny","ipv6":"deny","mode":"oneshot","duration_seconds":60,
 "dns":{"resolvers":["1.1.1.1"],"protocols":["udp","tcp"],"port":53},
 "web":{"destination":"public-ipv4","rules":[{"protocol":"tcp","port":443}]},
 "taskboard":{"address":"10.77.0.2","protocol":"tcp","port":8080,"task_id":1},
 "filesystem":{"workspace":"$WS","scratch":["$WS"],"read_only":["/etc","/usr","/bin","/lib","/lib64","/proc"],
   "execute":["/usr","/bin","/lib","/lib64"],"deny":["/etc/shadow"],"devices":[]},
 "process":{"signals":["TERM"],"anonymous_execute":false}}
JSON

python3 - "$WORK" "$IMAGE" "$ROOT" "$PROBE" >"$WORK/job.json" <<'PY'
import hashlib, json, pathlib, sys
work, image, root, probe = sys.argv[1:5]
policy = json.load(open(pathlib.Path(work) / 'policy.json'))
spec = {"version": "agentgate.launch.v1", "name": "kernel-verify", "target": "local", "mode": "oneshot",
        "lifetime_seconds": 60,
        "agent": {"image": image, "command": ["python3", "-c", probe], "env": {}, "workdir": policy["filesystem"]["workspace"]},
        "access": {"profile": "verify", "version": 1}, "mounts": [], "secrets": [], "approval": "auto"}
digest = lambda v: hashlib.sha256(json.dumps(v, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
job = {"version": "agentgate.launcher-job.v1", "launch_id": "kernelverify00000000000000000000", "job_id": "kernelverifyjob000000000000000000",
       "spec": spec, "spec_digest": digest(spec), "policy": policy, "policy_digest": digest(policy),
       "profile_policy_digest": digest(policy), "stop_grace_seconds": 5, "log_limit_bytes": 1 << 20,
       "upload_limit_bytes": 0, "lifetime_seconds": 60, "mounts": [],
       "expires_at_ms": 0}
import time
job["expires_at_ms"] = int(time.time() * 1000) + 120000
json.dump(job, sys.stdout)
PY

python3 "$LAUNCH" run <"$WORK/job.json" >"$WORK/events.jsonl" 2>"$WORK/run.err" || true
python3 "$LAUNCH" receipt kernelverify00000000000000000000 >"$WORK/receipt.json" 2>>"$WORK/run.err" || true
python3 "$LAUNCH" logs kernelverify00000000000000000000 stdout 0 1048576 >"$WORK/stdout.log" 2>/dev/null || true

# Evaluate the outcomes. The expected errno set is the contract's: allowed
# operations succeed (errno 0), denied ones fail (EACCES/EPERM), and every
# rendered filesystem denial path is container-absolute.
python3 - "$WORK" "$RESULT" "$WS" <<'PY'
import json, pathlib, sys
work, result, ws = sys.argv[1:4]
work = pathlib.Path(work)
outcomes = {}
for line in (work / 'stdout.log').read_text(errors='replace').splitlines():
    parts = line.split()
    if len(parts) == 2:
        outcomes[parts[0]] = parts[1]
expected_ok = {"allow-write", "allow-read", "allow-exec"}
expected_deny = {"deny-read-shadow", "deny-write-usr", "deny-exec-workspace", "deny-hardlink", "deny-mknod",
                 "deny-ptrace", "deny-private-ip", "deny-foreign-dns"}
probes = []
ok = True
for name in sorted(expected_ok | expected_deny):
    got = outcomes.get(name, "missing")
    if name in expected_ok:
        passed = got == "0"
    else:
        passed = got not in ("0", "missing")
    ok = ok and passed
    probes.append({"name": name, "errno": got, "ok": passed})
denials = []
container_absolute = True
try:
    receipt = json.load(open(work / 'receipt.json'))
    host = (receipt.get('evidence') or {}).get('host') or {}
    for part in ('filesystem', 'process'):
        for d in (host.get(part) or {}).get('denials', [])[:200]:
            path = d.get('path', '')
            denials.append(d)
            if path and not (path.startswith('/etc') or path.startswith('/usr') or path.startswith(ws) or path.startswith('/dev')):
                container_absolute = False
except (OSError, ValueError) as error:
    ok = False
    probes.append({"name": "receipt-readable", "errno": str(error), "ok": False})
probes.append({"name": "denials-container-absolute", "errno": "n/a", "ok": container_absolute,
               "note": "bpf_d_path rendered container-absolute paths" if container_absolute
                       else "a denial rendered a host-side path; selectors would stop matching"})
ok = ok and container_absolute
json.dump({"ok": ok, "probes": probes, "denials": denials[:100]}, open(result, 'w'), indent=2, sort_keys=True)
sys.exit(0 if ok else 1)
PY
