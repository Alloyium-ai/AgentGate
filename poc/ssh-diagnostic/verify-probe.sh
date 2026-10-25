#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
#
# Behaviour probe driver for verify-kernel.sh. It runs ONE real guarded oneshot
# launch whose agent attempts allowed and denied operations from inside the
# target (it entered via nsenter). Every guard denial is a true A/B against a
# positive control that the SAME mechanism allows, staged on a writable host
# folder the launch mounts read-write (so the rootfs, a dropped capability, a
# non-ELF file or an unroutable address can never be the cause of a negative):
#   - read a world-readable file inside a deny tree (denied) vs a sibling in a
#     read_only tree (allowed);
#   - write to an existing file of a read_only tree on that writable folder
#     (denied; a new name would be decided as a create) vs the workspace
#     (allowed);
#   - exec the same real ELF (/bin/true) from a non-execute writable tree
#     (denied) vs from an execute tree (allowed);
#   - mknod(2) a plain regular file in a writable tree (denied) vs open(O_CREAT)
#     of the same file (allowed): the create A/B, differing only in the syscall;
#   - mkfifo, an AF_UNIX pathname bind and a hard link within one filesystem,
#     each in a writable tree (denied), so EROFS/EXDEV cannot mask the guard;
#   - PTRACE_ATTACH a sibling (denied) observed by the attaching process;
#   - connect to the broker's exact endpoint (allowed) but its other ports, the
#     reachable network gateway and a neighbour, and a non-listed DNS resolver
#     (all EPERM from the hooks, never a timeout);
#   - the broker's secret path and the host's secret store never open, and a
#     random canary written to that store never appears in the agent's output.
# verify_kernel.py judges the outcomes, every guard negative requiring EPERM or
# EACCES, not a generic failure. The driver then cross-checks the launch
# receipt's host block: every negative must have left its own denial record
# there, of its operation and, where the hook resolves one, its exact path
# (verify_kernel.EXPECTED_HOST_DENIALS), and the rendered denial paths must be
# container-absolute (a host-side overlay path would mean bpf_d_path rendered
# the wrong mount and the selectors silently stopped matching). It writes a
# JSON result to $1 and exits non-zero if any expectation fails.
#
# This needs Docker and the BPF-LSM kernel; it cannot run in the build sandbox.
# verify-kernel.sh's tests replace it with a fake, and verify_kernel.py's
# judgement and the receipt cross-check are unit-tested. The probe launch
# itself is unexercised on a kernel, and the broker stand-in is a plain
# listener, not agentgate-broker.
set -u
RESULT=${1:?usage: verify-probe.sh RESULT.json}
ROOT=${AGENTGATE_VERIFY_PROBE_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)}
KIT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
IMAGE=${AGENTGATE_VERIFY_PROBE_IMAGE:?set AGENTGATE_VERIFY_PROBE_IMAGE to the digest of an installed probe image}
LAUNCH="$ROOT/launch.py"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/agentgate-probe.XXXXXX")
# The agent runs as 65534; the fixtures folder is chowned to it so a write the
# guard denies would otherwise physically succeed on this writable bind.
AGENT_UID=65534
AGENT_GID=65534
FIX="$WORK/fixtures"
MOUNT=/var/lib/agentgate/mounts/fixtures
LAUNCH_ID=kernelverify00000000000000000000
# The launch's own broker network: gateway .1, broker .2, target .3, neighbour .4.
NET=agentgate-$LAUNCH_ID-broker
SUBNET=172.30.255.0/29
GATEWAY=172.30.255.1
BROKER=172.30.255.2
TARGET_IP=172.30.255.3
PORT=8443
LISTENER=agentgate-verify-broker
# The store directory is fixed on a VM; the tests point it elsewhere.
STORE=${AGENTGATE_VERIFY_PROBE_STORE:-/var/lib/agentgate/secrets/verify-probe}
CANARY=$(head -c 48 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 40)
cleanup() {
  docker rm -f "$LISTENER" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$STORE" "$WORK"
}
trap cleanup EXIT

# The host's secret store holds a canary the agent must never read.
install -d -m 0700 "$(dirname -- "$STORE")" "$STORE"
(umask 077 && printf '%s' "$CANARY" >"$STORE/probe")

# Stage the fixtures the guard trees are placed over. The folder is writable
# throughout and owned by the agent, so only the guard denies a write, exec,
# mknod, hard link or read below a deny tree.
install -d -m 0755 "$FIX" "$FIX/work" "$FIX/ro" "$FIX/blocked" "$FIX/elf"
printf 'readable sibling\n' >"$FIX/ro/data"
printf 'world readable but under a deny tree\n' >"$FIX/blocked/secret"
cp /bin/true "$FIX/elf/true"
chmod 0644 "$FIX/ro/data" "$FIX/blocked/secret"
chmod 0755 "$FIX/elf/true"
chmod 0700 "$FIX/work"
chown -R "$AGENT_UID:$AGENT_GID" "$FIX"

docker network create --internal --driver bridge --subnet "$SUBNET" --gateway "$GATEWAY" "$NET" >/dev/null
docker run -d --rm --pull never --name "$LISTENER" --network "$NET" --ip "$BROKER" --read-only --cap-drop ALL \
  --security-opt no-new-privileges --entrypoint python3 "$IMAGE" -c '
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 8443))
s.listen(16)
while True:
    c, _ = s.accept()
    c.sendall(b"agentgate-broker-stand-in\n")
    c.close()
' >/dev/null

# The agent probe. Each line prints "name errno" so the judge checks the
# positive control and the negative independently of the kernel denial records.
PROBE='
import ctypes, errno, os, signal, socket, stat, subprocess, sys, time
from urllib.parse import urlsplit
def attempt(name, fn):
    try:
        fn(); print(name, "0")
    except OSError as e:
        print(name, errno.errorcode.get(e.errno, e.errno))
    except Exception as e:
        print(name, type(e).__name__)
fix = "'"$MOUNT"'"
work, ro, blocked, elf = fix + "/work", fix + "/ro", fix + "/blocked", fix + "/elf/true"
# Positive controls, each exercising the mechanism a negative below exercises.
attempt("allow-write", lambda: open(work + "/probe.txt", "w").write("ok"))
attempt("allow-read", lambda: open(work + "/probe.txt").read())
attempt("allow-create", lambda: os.close(os.open(work + "/created.txt", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)))
attempt("allow-exec-tree", lambda: subprocess.run(["/bin/true"], check=True))
attempt("allow-read-sibling", lambda: open(ro + "/data").read())
# Filesystem negatives, each on the writable bind: only the guard can deny them.
attempt("deny-read-tree", lambda: open(blocked + "/secret").read())
attempt("deny-write-readonly", lambda: open(ro + "/data", "r+").write("x"))
attempt("deny-exec-nontree", lambda: subprocess.run([elf], check=True))
attempt("deny-mknod-regular", lambda: os.mknod(work + "/node", 0o600 | stat.S_IFREG))
attempt("deny-mkfifo", lambda: os.mkfifo(work + "/fifo"))
attempt("deny-unix-bind", lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).bind(work + "/probe.sock"))
attempt("deny-hardlink", lambda: os.link(ro + "/data", work + "/link"))
# A real PTRACE_ATTACH on a sibling, so the refusal is observed, not swallowed.
def ptrace_attach():
    child = os.fork()
    if child == 0:
        signal.signal(signal.SIGTERM, lambda *a: os._exit(0))
        time.sleep(30); os._exit(0)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        ctypes.set_errno(0)
        if libc.ptrace(16, child, 0, 0) != 0:  # PTRACE_ATTACH
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        os.waitpid(child, 0)
    finally:
        try:
            os.kill(child, signal.SIGKILL); os.waitpid(child, 0)
        except OSError:
            pass
attempt("deny-ptrace", ptrace_attach)
# Network negatives: reachable private addresses and a denied resolver.
broker = urlsplit(os.environ["PROBE_BROKER_URL"])
host, port = broker.hostname, broker.port
base = host.rsplit(".", 1)[0]
attempt("allow-broker-endpoint", lambda: socket.create_connection((host, port), timeout=3).close())
attempt("deny-broker-other-port", lambda: socket.create_connection((host, port + 1), timeout=3))
attempt("deny-broker-gateway", lambda: socket.create_connection((base + ".1", port), timeout=3))
attempt("deny-broker-neighbour", lambda: socket.create_connection((base + ".4", port), timeout=3))
attempt("deny-foreign-dns", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"\x00", ("203.0.113.254", 53)))
attempt("deny-secret-mount", lambda: print(open("/run/agentgate/secrets/probe").read()))
attempt("deny-secret-store", lambda: print(open("'"$STORE"'/probe").read()))
sys.stdout.flush()
'

# The broker takes the single exact private endpoint instead of the taskboard.
# The guard trees sit over the writable fixtures bind; the workspace is one of
# its subdirectories, so the whole folder is writable except where a read_only
# or deny tree restricts it.
cat >"$WORK/policy.json" <<JSON
{"version":"agentgate.poc.v2","default":"deny","ipv6":"deny","mode":"oneshot","duration_seconds":60,
 "dns":{"resolvers":["1.1.1.1"],"protocols":["udp","tcp"],"port":53},
 "web":{"destination":"public-ipv4","rules":[{"protocol":"tcp","port":443}]},
 "broker":{"address":"$BROKER","protocol":"tcp","port":$PORT},
 "filesystem":{"workspace":"$MOUNT/work","scratch":[],"read_only":["/etc","/proc","$MOUNT/ro"],
   "execute":["/usr","/bin","/lib","/lib64"],"deny":["/etc/shadow","$MOUNT/blocked"],
   "devices":["/dev/null","/dev/urandom"],"memory":{"anonymous_execute":false}},
 "process":{"signals":["SIGTERM"]}}
JSON
# The native validator's digest is the one launch.py compares.
"$ROOT/pilot-network-diagnostic" network-info "$WORK/policy.json" >"$WORK/policy-info.json" || { echo 'the probe policy was rejected' >&2; exit 1; }

python3 - "$WORK" "$IMAGE" "$PROBE" "$LAUNCH_ID" "$NET" "$SUBNET" "$BROKER" "$PORT" "$TARGET_IP" "$FIX" "$MOUNT" >"$WORK/job.json" <<'PY'
import hashlib, json, pathlib, sys, time
work, image, probe, launch_id, net, subnet, broker, port, target, fix, mount = sys.argv[1:12]
policy = json.load(open(pathlib.Path(work) / 'policy.json'))
native = json.load(open(pathlib.Path(work) / 'policy-info.json'))['digest']
# The launch mounts the fixtures folder read-write; the guard trees decide what
# the agent may do below it. The spec requests exactly this mount (same_mounts).
mounts = [{"name": "fixtures", "source": fix, "mode": "read-write"}]
spec = {"version": "agentgate.launch.v1", "name": "kernel-verify", "target": "local", "mode": "oneshot",
        "lifetime_seconds": 60,
        "agent": {"image": image, "command": ["python3", "-c", probe], "env": {}, "workdir": mount + "/work"},
        "access": {"profile": "verify", "version": 1}, "mounts": list(mounts),
        "secrets": [{"ref": "probe", "expose": {"env": "PROBE_BROKER_URL"}}], "approval": "auto"}
digest = lambda v: hashlib.sha256(json.dumps(v, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
job = {"version": "agentgate.launcher-job.v1", "launch_id": launch_id, "job_id": "kernelverifyjob000000000000000000",
       "spec": spec, "spec_digest": digest(spec), "policy": policy, "policy_digest": native,
       "profile_policy_digest": native, "stop_grace_seconds": 5, "log_limit_bytes": 1 << 20,
       "upload_limit_bytes": 0, "lifetime_seconds": 60, "mounts": list(mounts),
       "expires_at_ms": int(time.time() * 1000) + 120000,
       "broker": {"network": net, "subnet": subnet, "address": broker, "port": int(port), "target_address": target,
                  "env": {"PROBE_BROKER_URL": "http://%s:%s/probe" % (broker, port)}}}
json.dump(job, sys.stdout)
PY

python3 "$LAUNCH" run <"$WORK/job.json" >"$WORK/events.jsonl" 2>"$WORK/run.err" || true
python3 "$LAUNCH" receipt "$LAUNCH_ID" >"$WORK/receipt.json" 2>>"$WORK/run.err" || true
python3 "$LAUNCH" logs "$LAUNCH_ID" stdout 0 1048576 >"$WORK/stdout.log" 2>/dev/null || true

# Judge the outcomes (verify_kernel.py), then cross-check the receipt: every
# negative left its own denial record (operation and path), each rendered
# denial path is container-absolute, and at least one denial was recorded.
python3 -I "$KIT/verify_kernel.py" judge "$CANARY" <"$WORK/stdout.log" >"$WORK/judged.json" || true
python3 -I - "$KIT" "$WORK" "$RESULT" "$MOUNT" <<'PY'
import json, pathlib, sys
kit, work, result, mount = sys.argv[1:5]
sys.path.insert(0, kit)
import verify_kernel
work = pathlib.Path(work)
try:
    judged = json.load(open(work / 'judged.json'))
except (OSError, ValueError) as error:
    judged = {'ok': False, 'probes': [{'name': 'judge', 'errno': str(error), 'ok': False}]}
ok, probes = bool(judged.get('ok')), list(judged.get('probes') or [])
# Container-absolute prefixes: the rootfs trees plus the fixtures mount.
prefixes = ('/etc', '/usr', '/proc', '/dev', mount)
denials, container_absolute, recorded = [], True, 0
host = {}
try:
    receipt = json.load(open(work / 'receipt.json'))
    host = (receipt.get('evidence') or {}).get('host') or {}
    for part in ('filesystem', 'process'):
        for d in (host.get(part) or {}).get('denials', [])[:200]:
            recorded += 1
            path = d.get('path', '')
            denials.append(d)
            if path and not path.startswith(prefixes):
                container_absolute = False
    joined = (receipt.get('broker') or {}).get('target_joined') is True
    probes.append({'name': 'target-joined-broker-network', 'errno': 'n/a', 'ok': joined})
    ok = ok and joined
except (OSError, ValueError) as error:
    ok = False
    probes.append({"name": "receipt-readable", "errno": str(error), "ok": False})
# Every negative must match its own recorded denial.
for probe in verify_kernel.required_denials({}, host, mount):
    probes.append(probe)
    ok = ok and probe['ok']
probes.append({"name": "denials-container-absolute", "errno": "recorded=%d" % recorded, "ok": container_absolute and recorded >= 1,
               "note": "a denial rendered a host-side path; selectors would stop matching" if not container_absolute
                       else "no filesystem or process denial was recorded; the guard did not deny anything" if recorded < 1
                       else "bpf_d_path rendered container-absolute paths"})
ok = ok and container_absolute and recorded >= 1
json.dump({"ok": ok, "probes": probes, "denials": denials[:100]}, open(result, 'w'), indent=2, sort_keys=True)
sys.exit(0 if ok else 1)
PY
