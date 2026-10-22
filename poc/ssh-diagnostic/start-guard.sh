#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
set -eu
poc=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
eval "$(python3 "$poc/settings.py" "$poc/settings.json")"
test -d "$domain"
grep -q 'populated 0' "$domain/cgroup.events"
test ! -e "$root/guard-ready" && test ! -e "$root/guard-receipt.json" && test ! -e "$root/config.json"
start_ns=$(python3 -c 'import time; print(time.monotonic_ns())')
host_objects=
if test "$host_controls" = 1; then
  # Filesystem and process enforcement attach with the network guard, or not at all.
  test ! -e "$host_pins"
  host_objects="$component/fs_access.bpf.o $component/process_guard.bpf.o"
fi
nohup "$poc/pilot-network-diagnostic" \
  "$diag/target.json" "$diag/policy-active.json" \
  "$component/network_policy.bpf.o" --network-policy - \
  "$root/guard-ready" "$root/guard-receipt.json" "$source" "$domain" $host_objects \
  </dev/null >"$root/guard.log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
ready=0
for attempt in $(seq 1 40); do
  if test -s "$root/guard-ready"; then ready=1; break; fi
  if ! kill -0 "$pid" 2>/dev/null; then break; fi
  sleep 0.1
done
if test "$ready" -ne 1; then tail -n 20 "$root/guard.log" >&2; exit 1; fi
test -d "$pins"
for index in 0 1 2 3 4 5; do test -e "$pins/link-$index"; done
if test "$host_controls" = 1; then
  test -d "$host_pins"
  for index in $(seq 0 22); do test -e "$host_pins/link-$index"; done
fi
python3 - "$poc" "$pid" "$name" "$network" "$domain" "$source" "$policy" "$start_ns" "$diag/policy-active.json" "$host_controls" "$host_pins" <<'PY'
import hashlib,json,os,pathlib,subprocess,sys,time
root=pathlib.Path(sys.argv[1]); pid=int(sys.argv[2]); name,network,domain,source,policy=sys.argv[3:8]
start_ns=int(sys.argv[8]); policy_path=pathlib.Path(sys.argv[9])
host_controls=sys.argv[10]=='1'; host_pins=sys.argv[11] if host_controls else ''
duration=int(json.loads(policy_path.read_text())['duration_seconds'])
assert 1 <= duration <= 60
raw=pathlib.Path(f'/proc/{pid}/stat').read_text()
ticks=int(raw.rsplit(')',1)[1].split()[19])
target=json.loads(subprocess.check_output(['/usr/bin/docker','inspect',name]))[0]
assert target['State']['Running'] and target['Config']['User']=='65534:65534'
runner=root/'run-in-target.sh'
config={'container':name,'container_id':target['Id'],'image_id':target['Image'],
        'network':network,'domain':domain,
        'runner_path':str(runner),
        'runner_sha256':hashlib.sha256(runner.read_bytes()).hexdigest(),
        'guard_pid':pid,'guard_start_ticks':ticks,'guard_ready':str(root/'guard-ready'),'guard_pins':str(pathlib.Path('/sys/fs/bpf')/('ag-mvp-net-'+pathlib.Path(domain).name)),
                'deadline_ns':min(time.monotonic_ns()+25_000_000_000,start_ns+duration*1_000_000_000),
        'audit_path':str(root/'audit.jsonl'),
        'source_revision':source,'policy_digest':policy,
        'host_controls':host_controls,'host_pins':host_pins}
path=root/'config.json'
assert config['deadline_ns'] > time.monotonic_ns()+1_000_000_000
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as file:
    json.dump(config,file,sort_keys=True)
    file.flush(); os.fsync(file.fileno())
print('guard_attached_before_ssh=true target_image_bound=true',flush=True)
PY

trap - EXIT
