#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
# Fixed diagnostic only. This trusted setup runs before the SSH payload.
set -euo pipefail
poc=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python3 "$poc/prepare-policy.py"
eval "$(python3 "$poc/settings.py" "$poc/settings.json")"
if test -d "$domain"; then grep -qx 'populated 0' "$domain/cgroup.events"; fi
test ! -e "$pins" && test ! -e "$host_pins"
test ! -e "$root/guard-ready" && test ! -e "$root/config.json" && test ! -e "$root/guard-receipt.json"
if docker container inspect "$target" >/dev/null 2>&1; then echo target_still_present >&2; exit 1; fi
if test -e "$root/initialized"; then
  # A guest reboot clears cgroups; the protected settings name only this owned domain.
  test -d "$domain" || mkdir "$domain"
  "$poc/restart-target.sh"
else
  test ! -e "$domain"
  "$poc/start-target.sh"
  touch "$root/initialized"
fi
"$poc/start-guard.sh"
test -s "$root/config.json" && test -s "$root/guard-ready"
