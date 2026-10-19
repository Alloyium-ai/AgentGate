#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
set -euo pipefail
poc=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
eval "$(python3 "$poc/settings.py" "$poc/settings.json")"
test -d "$domain"
grep -qx 'populated 0' "$domain/cgroup.events"
test ! -e "$poc/guard-receipt.json"
test ! -e "$poc/config.json"
docker container inspect "$name" >/dev/null 2>&1 && exit 2
image=$(docker image inspect "$target_image" --format '{{.Id}}')
bridge_image=$(docker image inspect "$bridge_image" --format '{{.Id}}')
bridge_container_id=$(docker inspect "$bridge_container" --format '{{.Id}}')
host_args=()
while IFS= read -r address; do
  test -n "$address"
  host_args+=(--add-host "$hostname:$address")
done < "$root/dns-addresses.txt"
docker run --pull never -d --name "$name" --init --network "$network" --read-only \
  --user 65534:65534 --cpus 1 --memory 512m --pids-limit 64 --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:mode=0700,size=64m \
  "${host_args[@]}" \
  --mount "type=volume,source=$workspace,target=/var/lib/agentgate/workspace" \
  --mount "type=bind,source=$artifact,target=/run/agentgate/streams" \
  --mount "type=volume,source=$bridge,target=/run/agentgate/taskboard,readonly" \
  --entrypoint /bin/sh "$image" -c 'sleep 600' >/dev/null
container_id=$(docker inspect "$name" --format '{{.Id}}')
workspace_source=$(docker volume inspect "$workspace" --format '{{.Mountpoint}}')
bridge_source=$(docker volume inspect "$bridge" --format '{{.Mountpoint}}')
python3 - "$root/target.json" "$container_id" "$image" "$network" "$workspace" "$workspace_source" "$bridge" "$bridge_source" "$bridge_container_id" "$bridge_image" "$bridge_network" "$task_id" "$taskboard_url" "$artifact" <<'PY'
import json,sys
path,container,image,network,workspace,workspace_source,bridge,bridge_source,bridge_container,bridge_image,bridge_network,task_id,taskboard_url,artifact=sys.argv[1:]
with open(path,'w') as out:
    json.dump({'socket_path':'/var/run/docker.sock','container_id':container,'image_digest':image,'network_name':network,'workspace':'/var/lib/agentgate/workspace','workspace_volume':workspace,'workspace_source':workspace_source,'artifact_path':'/run/agentgate/streams','artifact_source':artifact,'bridge_path':'/run/agentgate/taskboard','bridge_source':bridge_source,'bridge_volume':bridge,'bridge_task_id':int(task_id),'bridge_container_id':bridge_container,'bridge_image_digest':bridge_image,'bridge_network_name':bridge_network,'bridge_upstream_url':taskboard_url},out)
PY
echo diagnostic_fresh_target_ready=true
