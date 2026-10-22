#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
# Fixed diagnostic only. The trusted SSH gateway invokes this after BPF attach.
set -eu
test "$#" -eq 3
test "$(id -u)" -eq 0
target_pid=$1
domain=$2
command=$3
case "$target_pid" in *[!0-9]*|'') exit 2;; esac
case "$domain" in /sys/fs/cgroup/ag-mvp-*) ;; *) exit 2;; esac
test -d "$domain"
test -r "/proc/$target_pid/ns/net"
test -r "/proc/$target_pid/root/bin/sh"
test -x "/proc/$target_pid/root/usr/bin/setpriv"
printf '%s\n' "$$" > "$domain/cgroup.procs"
exec env -i PATH=/usr/local/bin:/usr/bin:/bin nsenter --target "$target_pid" \
  --mount --net --pid --uts --ipc --root="/proc/$target_pid/root" \
  --wdns=/var/lib/agentgate/workspace --setuid=65534 --setgid=65534 -- \
  /usr/bin/setpriv --no-new-privs -- /bin/sh -c "$command"
