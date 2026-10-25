// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// The change stream, pure logic (no React), so the node tests run it.
//
// GET /api/v1/events sends one "changed" event per merged batch of changes
// (at most one a second), naming the resources they touched: "launch:ID",
// "target:ID", "secret:ID", "profile:ID", "apitoken:ID", "identity:ID",
// "audit", "other" (records outside provisioning) and "self" (the signed-in
// account). Only resources the account may read are named. An event without
// resources means everything may have changed. Views reload only what an
// event names (pathTouched), never on a host heartbeat.

export type ChangeNotice = { resources?: string[] };

const changeListeners = new Set<(notice: ChangeNotice) => void>();

export function publishChange(notice: ChangeNotice) {
  for (const listener of [...changeListeners]) listener(notice);
}

export function subscribeChanges(listener: (notice: ChangeNotice) => void): () => void {
  changeListeners.add(listener);
  return () => changeListeners.delete(listener);
}

// parseChange reads a changed event's data; anything malformed means
// everything may have changed.
export function parseChange(data: string): ChangeNotice {
  try {
    const value = JSON.parse(data) as { resources?: unknown };
    if (Array.isArray(value.resources) && value.resources.every((r) => typeof r === "string")) return { resources: value.resources as string[] };
  } catch {
    /* fall through */
  }
  return {};
}

const pathKinds: Record<string, string> = {
  launches: "launch",
  targets: "target",
  secrets: "secret",
  profiles: "profile",
  "access-presets": "profile",
  "api-tokens": "apitoken",
  "identity-links": "identity",
  audit: "audit",
  "audit-catalog": "",
  "launch-spec-schema": "",
  "launch-plans": "",
};

// pathTouched reports whether a change naming resources can change what the
// API path shows: one record's path by its id, a list by its kind.
export function pathTouched(path: string, resources?: string[]): boolean {
  if (!resources) return true;
  const [area, id] = path.split("?")[0].replace(/^\/+/, "").split("/");
  if (!(area in pathKinds)) return resources.some((r) => r === "other" || r === "self");
  const kind = pathKinds[area];
  if (!kind) return false;
  if (kind === "audit") return resources.includes("audit");
  if (id && id !== "summary") {
    let key = id;
    try {
      key = decodeURIComponent(id);
    } catch {
      /* keep the raw segment */
    }
    return resources.includes(`${kind}:${key}`);
  }
  return resources.some((r) => r.startsWith(kind + ":"));
}

// Reload pacing: the first reload after a change waits 150 ms; while changes
// keep arriving the gap between reloads doubles from 0.5 s up to 8 s, and it
// falls back to 0.5 s after 10 s without one.
export const RELOAD_MIN_MS = 500;
export const RELOAD_MAX_MS = 8000;
const RELOAD_QUIET_MS = 10000;

export function pacedReload(reload: () => void) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let last = 0;
  let lastChange = 0;
  let gap = RELOAD_MIN_MS;
  return {
    hit() {
      const now = Date.now();
      if (lastChange && now - lastChange < gap) gap = Math.min(gap * 2, RELOAD_MAX_MS);
      else if (now - lastChange > RELOAD_QUIET_MS) gap = RELOAD_MIN_MS;
      lastChange = now;
      if (timer) return;
      timer = setTimeout(
        () => {
          timer = undefined;
          last = Date.now();
          reload();
        },
        Math.max(150, last + gap - now),
      );
    },
    cancel() {
      clearTimeout(timer);
      timer = undefined;
    },
  };
}

