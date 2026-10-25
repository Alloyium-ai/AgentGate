#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
#
# Install an AgentGate release set (from `make agentgate`, or a release
# directory with the same files) onto this machine:
#
#   sudo deploy/install.sh --from build [--sha256sums HEX] [--broker-uid 10002]
#
# It checks the prerequisites, copies the release into a private staging
# directory and verifies every file there against SHA256SUMS (and
# SHA256SUMS itself against --sha256sums when given), then installs:
#
#   /usr/local/bin/agentgate                        the CLI
#   /usr/local/sbin/agentgate-hostd                 the host agent
#   /usr/local/libexec/agentgate/agentgate-broker   the credential broker
#   /usr/local/libexec/agentgate/community          the control service binary
#   /etc/systemd/system/agentgate-broker@.service   the broker unit (sample)
#
# with the system user agentgate-broker (the broker's run_as identity) and
# the directories /etc/agentgate (0755), /etc/agentgate/broker (0700),
# /var/lib/agentgate (0755), /var/lib/agentgate/secrets (0700) and
# /var/lib/agentgate/broker (0711), all owned by root. Running it again
# changes nothing that is already in place. It refuses, before changing
# anything, a checksum mismatch, a file that is not regular, a symlink or
# a group- or world-writable directory on a destination path.
#
# It does not enroll the host (agentgate up or agentgate-hostd install does,
# and writes the agentgate-hostd unit) and does not start a control service
# (docs/PROVISIONING.md, "Deploy", covers docker compose).
#
# --root DIR installs below DIR instead of / (packaging and tests): it skips
# the root check, user creation and systemctl, and prints what it would run.
set -euo pipefail
umask 022

root=/
from=
pinned_sums=
broker_uid=10002
usage() {
  echo "usage: install.sh --from DIR [--sha256sums HEX] [--broker-uid N] [--root DIR]" >&2
  exit 2
}
while test "$#" -gt 0; do
  case "$1" in
    --from) test "$#" -ge 2 || usage; from=$2; shift 2 ;;
    --sha256sums) test "$#" -ge 2 || usage; pinned_sums=$2; shift 2 ;;
    --broker-uid) test "$#" -ge 2 || usage; broker_uid=$2; shift 2 ;;
    --root) test "$#" -ge 2 || usage; root=$2; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

refuse() {
  echo "install.sh: refused: $1" >&2
  if test "$#" -ge 2; then echo "  fix: $2" >&2; fi
  exit 1
}
say() { echo "install.sh: $*"; }

case "$root" in
  /) system=1 ;;
  /*) system=0 ;;
  *) refuse "--root must be an absolute path" ;;
esac
case "/$root/" in */../*|*/./*) refuse "--root must not contain . or .. segments" ;; esac
root=${root%/}
test -n "$from" || usage
case "$broker_uid" in ''|*[!0-9]*) refuse "--broker-uid must be a number" ;; esac
test "$broker_uid" -ge 1000 && test "$broker_uid" -le 2147483646 || refuse "--broker-uid must be an unprivileged id (1000 or more)"
if test -n "$pinned_sums" && ! [[ "$pinned_sums" =~ ^[0-9a-f]{64}$ ]]; then
  refuse "--sha256sums is the 64 hex digit SHA-256 of SHA256SUMS"
fi

# ---- prerequisites ---------------------------------------------------------
if test "$system" -eq 1; then
  # A root install uses only the system's own tools.
  PATH=/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
  export PATH
  test "$(id -u)" -eq 0 || refuse "installing into / needs root" "sudo $0 --from $from"
fi
test "$(uname -s)" = Linux || refuse "AgentGate hosts run Linux"
missing=()
for tool in sha256sum install cmp mktemp stat cp mv; do
  command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if test "$system" -eq 1; then
  for tool in getent useradd groupadd; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
fi
test "${#missing[@]}" -eq 0 || refuse "missing tools: ${missing[*]}" "install coreutils and passwd (shadow-utils)"
warnings=()
for tool in docker python3 systemctl setpriv; do
  command -v "$tool" >/dev/null 2>&1 || warnings+=("$tool is not installed; agentgate-hostd install needs it on a host that runs launches")
done
if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
  warnings+=("the kernel does not list bpf in /sys/kernel/security/lsm; launches fail closed until it does (agentgate doctor reports kernel-bpf-lsm)")
fi

# ---- the release set -----------------------------------------------------
files=(agentgate agentgate-hostd agentgate-broker community agentgate-broker@.service)
test -d "$from" && test ! -L "$from" || refuse "--from $from is not a directory"
for name in SHA256SUMS "${files[@]}"; do
  test -f "$from/$name" && test ! -L "$from/$name" || refuse "$from/$name is missing or not a regular file" "run make agentgate, or download the whole release"
done
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
chmod 0700 "$staging"
# Verify the copies, never the originals: nothing can swap a file between
# the check and the install.
for name in SHA256SUMS "${files[@]}"; do
  cp -- "$from/$name" "$staging/$name"
done
sums_digest=$(sha256sum "$staging/SHA256SUMS" | cut -d' ' -f1)
say "SHA256SUMS digest $sums_digest (compare it with the published release)"
if test -n "$pinned_sums" && test "$pinned_sums" != "$sums_digest"; then
  refuse "SHA256SUMS has digest $sums_digest, not the pinned $pinned_sums" "download the release again from its source"
fi
listed=()
while IFS= read -r line; do
  [[ "$line" =~ ^([0-9a-f]{64})\ \ ([A-Za-z0-9@._-]+)$ ]] || refuse "SHA256SUMS has a malformed line"
  name=${BASH_REMATCH[2]}
  known=0
  for f in "${files[@]}"; do test "$f" = "$name" && known=1; done
  test "$known" -eq 1 || refuse "SHA256SUMS lists an unexpected file: $name"
  for f in "${listed[@]}"; do test "$f" != "$name" || refuse "SHA256SUMS lists $name twice"; done
  listed+=("$name")
done < "$staging/SHA256SUMS"
test "${#listed[@]}" -eq "${#files[@]}" || refuse "SHA256SUMS does not list every file of the release" "run make agentgate again"
(cd "$staging" && sha256sum --quiet --strict -c SHA256SUMS) >/dev/null 2>&1 || refuse "a file does not match SHA256SUMS" "download or build the release again; do not install it"
say "every file matches SHA256SUMS"
"$staging/agentgate" version >/dev/null 2>&1 || refuse "the agentgate binary does not run on this machine (another architecture?)" "build it here with make agentgate"

# ---- destinations ----------------------------------------------------------
dest() { echo "$root${1}"; }
# A destination's existing ancestors must be root-owned (in a system
# install) and not writable by group or others, and the path itself must not
# be a symlink.
check_path() {
  local path=$1 dir
  if test -L "$path"; then refuse "$path is a symlink"; fi
  dir=$(dirname "$path")
  while :; do
    if test -e "$dir" || test -L "$dir"; then
      test ! -L "$dir" || refuse "$dir is a symlink"
      test -d "$dir" || refuse "$dir is not a directory"
      local mode owner
      mode=$(stat -c %a "$dir")
      owner=$(stat -c %u "$dir")
      if test "$system" -eq 1 && test "$owner" != 0; then refuse "$dir is not owned by root"; fi
      # Sticky world-writable directories (/tmp) are never a destination ancestor here.
      if (( (8#$mode & 8#022) != 0 )); then refuse "$dir is writable by group or others (mode $mode)"; fi
    fi
    test "$dir" != / && test "$dir" != "$root" || break
    dir=$(dirname "$dir")
  done
}
declare -A target
target[agentgate]=/usr/local/bin/agentgate
target[agentgate-hostd]=/usr/local/sbin/agentgate-hostd
target[agentgate-broker]=/usr/local/libexec/agentgate/agentgate-broker
target[community]=/usr/local/libexec/agentgate/community
target[agentgate-broker@.service]=/etc/systemd/system/agentgate-broker@.service
dirs=("/etc/agentgate 0755" "/etc/agentgate/broker 0700" "/var/lib/agentgate 0755" "/var/lib/agentgate/secrets 0700" "/var/lib/agentgate/broker 0711")
for name in "${files[@]}"; do check_path "$(dest "${target[$name]}")"; done
for entry in "${dirs[@]}"; do check_path "$(dest "${entry% *}")/x"; done

# The broker's run_as identity.
if test "$system" -eq 1; then
  if existing=$(getent passwd agentgate-broker); then
    test "$(echo "$existing" | cut -d: -f3)" = "$broker_uid" || refuse "the user agentgate-broker exists with uid $(echo "$existing" | cut -d: -f3), not $broker_uid" \
      "pass --broker-uid $(echo "$existing" | cut -d: -f3) here and to agentgate-hostd install --broker-uid"
  elif getent passwd "$broker_uid" >/dev/null; then
    refuse "uid $broker_uid already belongs to $(getent passwd "$broker_uid" | cut -d: -f1)" "pick a free id with --broker-uid N and pass the same to agentgate-hostd install"
  elif getent group "$broker_uid" >/dev/null && ! getent group agentgate-broker >/dev/null; then
    refuse "gid $broker_uid already belongs to group $(getent group "$broker_uid" | cut -d: -f1)" "pick a free id with --broker-uid N"
  fi
fi

# ---- install ---------------------------------------------------------------
changed_units=0
for entry in "${dirs[@]}"; do
  path=$(dest "${entry% *}")
  mode=${entry#* }
  if test -d "$path"; then
    current=$(stat -c %a "$path")
    if test "$current" != "${mode#0}"; then chmod "$mode" "$path"; say "set $path to $mode"; fi
  else
    install -d -m "$mode" "$path"
    say "created $path ($mode)"
  fi
  if test "$system" -eq 1; then chown root:root "$path"; fi
done
for name in "${files[@]}"; do
  path=$(dest "${target[$name]}")
  mode=0755
  case "$name" in *.service) mode=0644 ;; esac
  if test -f "$path" && cmp -s "$staging/$name" "$path" && test "$(stat -c %a "$path")" = "${mode#0}"; then
    say "unchanged ${target[$name]}"
    continue
  fi
  install -d -m 0755 "$(dirname "$path")"
  install -m "$mode" "$staging/$name" "$path.agentgate-new"
  if test "$system" -eq 1; then chown root:root "$path.agentgate-new"; fi
  mv -f "$path.agentgate-new" "$path"
  say "installed ${target[$name]} ($mode)"
  case "$name" in *.service) changed_units=1 ;; esac
done

run() {
  if test "$system" -eq 1; then "$@"; else say "would run: $*"; fi
}
if test "$system" -eq 1 && getent passwd agentgate-broker >/dev/null; then
  say "unchanged user agentgate-broker (uid $broker_uid)"
else
  if test "$system" -eq 0 || ! getent group agentgate-broker >/dev/null; then
    run groupadd --system --gid "$broker_uid" agentgate-broker
  fi
  run useradd --system --uid "$broker_uid" --gid agentgate-broker --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin agentgate-broker
fi
broker_gid=$broker_uid
if test "$system" -eq 1; then broker_gid=$(id -g agentgate-broker); fi
if test "$changed_units" -eq 1; then
  if test "$system" -eq 0 || test -d /run/systemd/system; then run systemctl daemon-reload; fi
fi

for w in "${warnings[@]+"${warnings[@]}"}"; do echo "install.sh: warning: $w" >&2; done
cat <<EOF
install.sh: done. Next:
  on a host:     sudo agentgate up --target NAME --service-url https://SERVICE:9443   (enrolls agentgate-hostd)
                 add --broker-image agentgate-broker@sha256:<digest> --broker-uid $broker_uid --broker-gid $broker_gid
                 to agentgate-hostd install for brokered secrets
  anywhere:      agentgate doctor --target NAME
EOF
