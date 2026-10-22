#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
# Fixed diagnostic only. The trusted SSH gateway invokes this after BPF attach.
set -eu
test "$#" -eq 3 || test "$#" -eq 4
test "$(id -u)" -eq 0
target_pid=$1
domain=$2
command=$3
mode=${4:-early-join}
case "$target_pid" in *[!0-9]*|'') exit 2;; esac
case "$domain" in /sys/fs/cgroup/ag-mvp-*) ;; *) exit 2;; esac
test -d "$domain"
test -r "/proc/$target_pid/ns/net"
test -r "/proc/$target_pid/root/bin/sh"
test -x "/proc/$target_pid/root/usr/bin/setpriv"
case "$mode" in
early-join)
  printf '%s\n' "$$" > "$domain/cgroup.procs"
  exec env -i PATH=/usr/local/bin:/usr/bin:/bin nsenter --target "$target_pid" \
    --mount --net --pid --uts --ipc --root="/proc/$target_pid/root" \
    --wdns=/var/lib/agentgate/workspace --setuid=65534 --setgid=65534 -- \
    /usr/bin/setpriv --no-new-privs -- /bin/sh -c "$command" ;;
late-join)
  # Filesystem and process policy would also bind env, nsenter and setpriv, and
  # namespace files have no absolute path. Open the domain's cgroup.procs here,
  # as root, and let the unprivileged shell join as its first action. The kernel
  # checks the opener's credentials, and the shell closes the descriptor before
  # it runs the command. A failed join or a wrong membership exits unrun.
  exec 3>"$domain/cgroup.procs"
  exec env -i PATH=/usr/local/bin:/usr/bin:/bin nsenter --target "$target_pid" \
    --mount --net --pid --uts --ipc --root="/proc/$target_pid/root" \
    --wdns=/var/lib/agentgate/workspace --setuid=65534 --setgid=65534 -- \
    /usr/bin/setpriv --no-new-privs -- /bin/sh -c \
    'set -eu; echo "$$" >&3; exec 3>&-; joined=0; while read -r line; do case "$line" in 0::*) if test "$line" = "0::/$2"; then joined=1; fi;; esac; done < /proc/self/cgroup; test "$joined" = 1 || exit 125; exec /bin/sh -c "$1"' \
    agentgate-join "$command" "${domain##*/}" ;;
*) exit 2 ;;
esac
