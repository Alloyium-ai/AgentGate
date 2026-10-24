#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
#
# Behaviour probe driver for verify-kernel.sh. It runs ONE real guarded oneshot
# launch whose agent attempts allowed and denied operations from inside the
# target (it entered via nsenter), then reads the launch receipt and confirms:
#   - every allowed read, write, create (open O_CREAT) and exec in the
#     workspace succeeded;
#   - the denied operations failed (read /etc/shadow, write /usr, exec from the
#     workspace, ptrace, device-node and FIFO creation, an AF_UNIX pathname
#     bind, hard link, outbound to a private IP, DNS to a non-listed resolver);
#   - the launch reaches its broker endpoint and nothing else private: the
#     policy names a broker endpoint (instead of the taskboard) on the launch's
#     own internal /29, a stand-in listener from the probe image holds the
#     broker address, and the agent is refused (EPERM/EACCES) on another port,
#     on the network's gateway and on a neighbour address;
#   - the agent cannot open the broker's secret path or the host's secret
#     store, and a random canary written to that store never appears in its
#     output;
#   - the guard's filesystem denials render CONTAINER-ABSOLUTE paths that match
#     the policy selectors (e.g. /etc/shadow, /var/lib/agentgate/workspace/...),
#     never a host-side overlay path such as /var/lib/docker/overlay2/...; a
#     host path would mean bpf_d_path rendered the wrong mount and selectors
#     silently stop matching.
# verify_kernel.py judges the outcomes. It writes a JSON result to $1 and exits
# non-zero if any expectation fails.
#
# This needs Docker and the BPF-LSM kernel; it cannot run in the build sandbox.
# verify-kernel.sh's tests replace it with a fake, and verify_kernel.py's
# judgement is unit-tested. The probe launch itself is unexercised on a kernel,
# and the broker stand-in is a plain listener, not agentgate-broker.
set -u
RESULT=${1:?usage: verify-probe.sh RESULT.json}
ROOT=${AGENTGATE_VERIFY_PROBE_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)}
KIT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
IMAGE=${AGENTGATE_VERIFY_PROBE_IMAGE:?set AGENTGATE_VERIFY_PROBE_IMAGE to the digest of an installed probe image}
LAUNCH="$ROOT/launch.py"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/agentgate-probe.XXXXXX")
WS=/var/lib/agentgate/workspace
LAUNCH_ID=kernelverify00000000000000000000
# The launch's own broker network: gateway .1, broker .2, target .3.
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

# The agent probe. Each line prints "name errno" so the judge checks both the
# positive and negative outcomes, independently of the kernel denial records.
PROBE='
import errno, os, socket, subprocess, sys
from urllib.parse import urlsplit
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
attempt("allow-create", lambda: os.close(os.open(ws + "/created.txt", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)))
attempt("deny-read-shadow", lambda: open("/etc/shadow").read())
attempt("deny-write-usr", lambda: open("/usr/probe", "w"))
os.chmod(ws + "/probe.txt", 0o755)
attempt("deny-exec-workspace", lambda: subprocess.run([ws + "/probe.txt"]))
attempt("deny-hardlink", lambda: os.link("/etc/hostname", ws + "/link"))
attempt("deny-mknod", lambda: os.mknod(ws + "/dev", 0o600 | 0o020000))
attempt("deny-mkfifo", lambda: os.mkfifo(ws + "/fifo"))
attempt("deny-unix-bind", lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).bind(ws + "/probe.sock"))
attempt("deny-ptrace", lambda: subprocess.run(["/bin/sh", "-c", "exec 3<&0"], preexec_fn=lambda: __import__("ctypes").CDLL(None).ptrace(0, 0, 0, 0)))
attempt("deny-private-ip", lambda: socket.create_connection(("10.0.0.254", 9), timeout=3))
attempt("deny-foreign-dns", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"\x00", ("203.0.113.254", 53)))
broker = urlsplit(os.environ["PROBE_BROKER_URL"])
host, port = broker.hostname, broker.port
base = host.rsplit(".", 1)[0]
attempt("allow-broker-endpoint", lambda: socket.create_connection((host, port), timeout=3).close())
attempt("deny-broker-other-port", lambda: socket.create_connection((host, port + 1), timeout=3))
attempt("deny-broker-gateway", lambda: socket.create_connection((base + ".1", port), timeout=3))
attempt("deny-broker-neighbour", lambda: socket.create_connection((base + ".4", port), timeout=3))
attempt("deny-secret-mount", lambda: print(open("/run/agentgate/secrets/probe").read()))
attempt("deny-secret-store", lambda: print(open("/var/lib/agentgate/secrets/verify-probe/probe").read()))
sys.stdout.flush()
'

# The broker takes the single exact private endpoint instead of the taskboard.
cat >"$WORK/policy.json" <<JSON
{"version":"agentgate.poc.v2","default":"deny","ipv6":"deny","mode":"oneshot","duration_seconds":60,
 "dns":{"resolvers":["1.1.1.1"],"protocols":["udp","tcp"],"port":53},
 "web":{"destination":"public-ipv4","rules":[{"protocol":"tcp","port":443}]},
 "broker":{"address":"$BROKER","protocol":"tcp","port":$PORT},
 "filesystem":{"workspace":"$WS","scratch":["/tmp"],"read_only":["/etc","/proc"],
   "execute":["/usr","/bin","/lib","/lib64"],"deny":["/etc/shadow"],"devices":["/dev/null","/dev/urandom"],
   "memory":{"anonymous_execute":false}},
 "process":{"signals":["SIGTERM"]}}
JSON
# The native validator's digest is the one launch.py compares.
"$ROOT/pilot-network-diagnostic" network-info "$WORK/policy.json" >"$WORK/policy-info.json" || { echo 'the probe policy was rejected' >&2; exit 1; }

python3 - "$WORK" "$IMAGE" "$PROBE" "$LAUNCH_ID" "$NET" "$SUBNET" "$BROKER" "$PORT" "$TARGET_IP" >"$WORK/job.json" <<'PY'
import hashlib, json, pathlib, sys, time
work, image, probe, launch_id, net, subnet, broker, port, target = sys.argv[1:10]
policy = json.load(open(pathlib.Path(work) / 'policy.json'))
native = json.load(open(pathlib.Path(work) / 'policy-info.json'))['digest']
spec = {"version": "agentgate.launch.v1", "name": "kernel-verify", "target": "local", "mode": "oneshot",
        "lifetime_seconds": 60,
        "agent": {"image": image, "command": ["python3", "-c", probe], "env": {}, "workdir": policy["filesystem"]["workspace"]},
        "access": {"profile": "verify", "version": 1}, "mounts": [],
        "secrets": [{"ref": "probe", "expose": {"env": "PROBE_BROKER_URL"}}], "approval": "auto"}
digest = lambda v: hashlib.sha256(json.dumps(v, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
job = {"version": "agentgate.launcher-job.v1", "launch_id": launch_id, "job_id": "kernelverifyjob000000000000000000",
       "spec": spec, "spec_digest": digest(spec), "policy": policy, "policy_digest": native,
       "profile_policy_digest": native, "stop_grace_seconds": 5, "log_limit_bytes": 1 << 20,
       "upload_limit_bytes": 0, "lifetime_seconds": 60, "mounts": [],
       "expires_at_ms": int(time.time() * 1000) + 120000,
       "broker": {"network": net, "subnet": subnet, "address": broker, "port": int(port), "target_address": target,
                  "env": {"PROBE_BROKER_URL": "http://%s:%s/probe" % (broker, port)}}}
json.dump(job, sys.stdout)
PY

python3 "$LAUNCH" run <"$WORK/job.json" >"$WORK/events.jsonl" 2>"$WORK/run.err" || true
python3 "$LAUNCH" receipt "$LAUNCH_ID" >"$WORK/receipt.json" 2>>"$WORK/run.err" || true
python3 "$LAUNCH" logs "$LAUNCH_ID" stdout 0 1048576 >"$WORK/stdout.log" 2>/dev/null || true

# Judge the outcomes (verify_kernel.py), then check that every rendered
# filesystem denial path is container-absolute.
python3 -I "$KIT/verify_kernel.py" judge "$CANARY" <"$WORK/stdout.log" >"$WORK/judged.json" || true
python3 - "$WORK" "$RESULT" "$WS" <<'PY'
import json, pathlib, sys
work, result, ws = sys.argv[1:4]
work = pathlib.Path(work)
try:
    judged = json.load(open(work / 'judged.json'))
except (OSError, ValueError) as error:
    judged = {'ok': False, 'probes': [{'name': 'judge', 'errno': str(error), 'ok': False}]}
ok, probes = bool(judged.get('ok')), list(judged.get('probes') or [])
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
    joined = (receipt.get('broker') or {}).get('target_joined') is True
    probes.append({'name': 'target-joined-broker-network', 'errno': 'n/a', 'ok': joined})
    ok = ok and joined
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
