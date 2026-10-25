#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
set -euo pipefail
poc=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
eval "$(python3 "$poc/settings.py" "$poc/settings.json")"
# No arguments: the SSH command target, exactly as before, with the taskboard
# bridge volume read-only. A launch passes --launch IMAGE_ID KEEPALIVE_SECONDS
# [--taskboard-bridge]: its own immutable image, a container that outlives its
# lifetime, host folders from the launch's validated mount list, and the
# taskboard bridge only when the launch asks for it (launch_job.taskboard_bridge).
keep=(-c 'sleep 600')
mount_source=("$root")
with_bridge=1
case "$#" in
0) ;;
3|4)
  test "$1" = --launch || exit 2
  with_bridge=0
  if test "$#" -eq 4; then test "$4" = --taskboard-bridge || exit 2; with_bridge=1; fi
  case "$2" in sha256:*) ;; *) exit 2 ;; esac
  case "${2#sha256:}" in *[!a-f0-9]*) exit 2 ;; esac
  test "${#2}" -eq 71 || exit 2
  case "$3" in *[!0-9]*|'') exit 2 ;; esac
  test "$3" -ge 60 && test "$3" -le 90000 || exit 2
  target_image=$2
  keep=(-c 'exec sleep "$1"' agentgate-keepalive "$3")
  mount_source=(launch "$root") ;;
*) exit 2 ;;
esac
test -d "$domain"
grep -qx 'populated 0' "$domain/cgroup.events"
test ! -e "$poc/guard-receipt.json"
test ! -e "$poc/config.json"
docker container inspect "$name" >/dev/null 2>&1 && exit 2
image=$(docker image inspect "$target_image" --format '{{.Id}}')
# /run is volatile across guest reboot. Restore only this configured root-owned mount.
install -d -o 0 -g 0 -m 0711 "$artifact"
bridge_mount=()
if test "$with_bridge" -eq 1; then
  bridge_image=$(docker image inspect "$bridge_image" --format '{{.Id}}')
  bridge_container_id=$(docker inspect "$bridge_container" --format '{{.Id}}')
  bridge_mount=(--mount "type=volume,source=$bridge,target=/run/agentgate/taskboard,readonly")
fi
# Host folders come only from the validated, root-owned mounts file: one Docker
# argument per line, refused unless the active policy controls file access.
mount_lines=$(python3 "$poc/mounts.py" "${mount_source[@]}")
host_mounts=()
if test -n "$mount_lines"; then mapfile -t host_mounts <<<"$mount_lines"; fi
docker run --pull never -d --name "$name" --no-healthcheck --init --network "$network" --read-only \
  --user 65534:65534 --cpus 1 --memory 512m --pids-limit 64 --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:mode=0700,size=64m \
  --mount "type=volume,source=$workspace,target=/var/lib/agentgate/workspace" \
  --mount "type=bind,source=$artifact,target=/run/agentgate/streams" \
  "${bridge_mount[@]}" \
  "${host_mounts[@]}" \
  --entrypoint /bin/sh "$image" "${keep[@]}" >/dev/null
python3 "$poc/prepare-resolver.py"
container_id=$(docker inspect "$name" --format '{{.Id}}')
workspace_source=$(docker volume inspect "$workspace" --format '{{.Mountpoint}}')
bridge_args=()
if test "$with_bridge" -eq 1; then
  bridge_source=$(docker volume inspect "$bridge" --format '{{.Mountpoint}}')
  bridge_args=("$bridge" "$bridge_source" "$bridge_container_id" "$bridge_image" "$bridge_network" "$task_id" "$taskboard_url")
fi
python3 - "$root/target.json" "$container_id" "$image" "$network" "$workspace" "$workspace_source" "$artifact" "${bridge_args[@]}" <<'PY'
import json,os,sys
path,container,image,network,workspace,workspace_source,artifact=sys.argv[1:8]
record={'socket_path':'/var/run/docker.sock','container_id':container,'image_digest':image,'network_name':network,'workspace':'/var/lib/agentgate/workspace','workspace_volume':workspace,'workspace_source':workspace_source,'artifact_path':'/run/agentgate/streams','artifact_source':artifact,'host_mounts':json.load(open(os.path.join(os.path.dirname(path),'mounts-active.json')))}
# The bridge fields are all present (the bridge is mounted) or all absent.
if len(sys.argv) == 15:
    bridge,bridge_source,bridge_container,bridge_image,bridge_network,task_id,taskboard_url=sys.argv[8:]
    record.update({'bridge_path':'/run/agentgate/taskboard','bridge_source':bridge_source,'bridge_volume':bridge,'bridge_task_id':int(task_id),'bridge_container_id':bridge_container,'bridge_image_digest':bridge_image,'bridge_network_name':bridge_network,'bridge_upstream_url':taskboard_url})
elif len(sys.argv) != 8:
    sys.exit(2)
with open(path,'w') as out:
    json.dump(record,out)
PY
echo diagnostic_fresh_target_ready=true
