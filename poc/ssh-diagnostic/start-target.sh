#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
set -euo pipefail
poc=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
eval "$(python3 "$poc/settings.py" "$poc/settings.json")"
guard_pid=
target_host_pid=
image=$(docker image inspect "$target_image" --format '{{.Id}}')
case "$image" in sha256:*) ;; *) echo missing_image_digest >&2; exit 2 ;; esac
policy_input="$root/policy-readable.json"
token="$root/secrets/taskboard.token"
test -f "$token"
for resource in "$name" "$bridge_container"; do if docker container inspect "$resource" >/dev/null 2>&1; then echo owned_name_busy >&2; exit 2; fi; done
for resource in "$network" "$bridge_network"; do if docker network inspect "$resource" >/dev/null 2>&1; then echo owned_network_busy >&2; exit 2; fi; done
for resource in "$workspace" "$bridge"; do if docker volume inspect "$resource" >/dev/null 2>&1; then echo owned_volume_busy >&2; exit 2; fi; done
docker network create --driver bridge --ipv6 --subnet "$ipv6_subnet" "$network" >/dev/null
docker network create --driver bridge "$bridge_network" >/dev/null
docker volume create "$workspace" >/dev/null
docker volume create "$bridge" >/dev/null
docker run --pull never --rm --network none --cpus 1 --memory 128m --pids-limit 32 --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --user 0:0 --entrypoint /bin/sh -v "$workspace:/work" -v "$bridge:/bridge" "$target_image" -ec 'chown 65534:65534 /work; chmod 0700 /work; chown 0:65534 /bridge; chmod 0750 /bridge'
docker run --pull never --rm --network none --cpus 1 --memory 128m --pids-limit 32 --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --user 0:0 --entrypoint /bin/sh -v "$root/secrets:/secrets" "$target_image" -ec 'chown 0:0 /secrets/taskboard.token; chmod 0600 /secrets/taskboard.token'
bridge_image=$(docker image inspect "$bridge_image" --format '{{.Id}}')
docker run --pull never -d --name "$bridge_container" --network "$bridge_network" --read-only --cpus 1 --memory 512m --pids-limit 32 --cap-drop ALL --cap-add CHOWN --security-opt no-new-privileges \
  -e AGENTGATE_TASKBOARD_SOCKET=/run/agentgate/taskboard/taskboard.sock \
  -e AGENTGATE_TASKBOARD_SOCKET_GID=65534 \
  -e AGENTGATE_TASKBOARD_URL=$taskboard_url \
  -e AGENTGATE_TASKBOARD_TASK_ID="$task_id" \
  -e AGENTGATE_TASKBOARD_TOKEN_FILE=/run/secrets/taskboard-token \
  -e AGENTGATE_TASKBOARD_SNAPSHOT=/run/agentgate/taskboard/task.json \
  -v "$token:/run/secrets/taskboard-token:ro" \
  -v "$bridge:/run/agentgate/taskboard" \
  "$bridge_image" >/dev/null
bridge_container_id=$(docker inspect "$bridge_container" --format '{{.Id}}')
ready=0
for attempt in $(seq 1 20); do
  if docker exec "$bridge_container" test -s /run/agentgate/taskboard/task.json >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
if test "$ready" -ne 1; then echo bridge_snapshot_absent >&2; exit 1; fi
mkdir -p "$artifact"
docker run --pull never --rm --network none --cpus 1 --memory 128m --pids-limit 32 --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --user 0:0 --entrypoint /bin/sh -v "$artifact:/artifact" "$target_image" -ec 'chown 0:0 /artifact; chmod 0711 /artifact'
docker run --pull never -d --name "$name" --no-healthcheck --init --network "$network" --read-only --user 65534:65534 --cpus 1 --memory 512m --pids-limit 64 --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:mode=0700,size=64m \
  --mount "type=volume,source=$workspace,target=/var/lib/agentgate/workspace" \
  --mount "type=bind,source=$artifact,target=/run/agentgate/streams" \
  --mount "type=volume,source=$bridge,target=/run/agentgate/taskboard,readonly" \
  --entrypoint /bin/sh "$image" -c 'sleep 600' >/dev/null
python3 "$poc/prepare-resolver.py"
container_id=$(docker inspect "$name" --format '{{.Id}}')
target_host_pid=$(docker inspect "$name" --format '{{.State.Pid}}')
test ! -e "$cgroup"
mkdir "$cgroup"
workspace_source=$(docker volume inspect "$workspace" --format '{{.Mountpoint}}')
bridge_source=$(docker volume inspect "$bridge" --format '{{.Mountpoint}}')
python3 - "$root/target.json" "$container_id" "$image" "$network" "$workspace" "$workspace_source" "$bridge" "$bridge_source" "$artifact" "$bridge_container_id" "$bridge_image" "$bridge_network" "$task_id" "$taskboard_url" <<'PY'
import json,sys
path,container,image,network,workspace,workspace_source,bridge,bridge_source,artifact,bridge_container,bridge_image,bridge_network,task_id,taskboard_url=sys.argv[1:]
with open(path,'w') as out:
    json.dump({'socket_path':'/var/run/docker.sock','container_id':container,'image_digest':image,'network_name':network,'workspace':'/var/lib/agentgate/workspace','workspace_volume':workspace,'workspace_source':workspace_source,'artifact_path':'/run/agentgate/streams','artifact_source':artifact,'bridge_path':'/run/agentgate/taskboard','bridge_source':bridge_source,'bridge_volume':bridge,'bridge_task_id':int(task_id),'bridge_container_id':bridge_container,'bridge_image_digest':bridge_image,'bridge_network_name':bridge_network,'bridge_upstream_url':taskboard_url},out)
PY

echo diagnostic_target_ready=true
