// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Types and helpers for the provisioning API (/api/v1 targets, profiles,
// launches, secrets and API tokens). The shapes follow internal/control
// prov_*.go. Every permission check here only decides what the page offers;
// the service enforces every role again.

import { useEffect, useRef, useState } from "react";
import { Actor, ApiError, api } from "./api";

export type Target = {
  id: string;
  name: string;
  state: string;
  capabilities: string[];
  hostname: string;
  agent_version: string;
  host_key_id: string;
  encryption_key: string;
  job_key_id: string;
  last_seen_at?: string;
  online: boolean;
  heartbeat_seconds: number;
  created_at: string;
  created_by: string;
  updated_at: string;
  revision: number;
  kernel_verified: boolean;
  retiring_since?: string;
};
export type Enrollment = {
  token: string;
  expires_at: string;
  single_use: boolean;
  enroll_path: string;
};
export type Profile = {
  id: string;
  name: string;
  description: string;
  require_approval: boolean;
  created_at: string;
  created_by: string;
  revision: number;
  latest_version: number;
};
export type GrantEdit = {
  action: string;
  kind?: string;
  values?: string[];
  mode?: string;
  upgrade_to_v2?: boolean;
};
export type PolicyDocument = {
  version: string;
  default: string;
  ipv6: string;
  dns: { resolvers: string[]; protocols: string[]; port: number };
  web: { destination: string; rules: { protocol: string; port: number }[] };
  taskboard: { address: string; protocol: string; port: number; task_id: number };
  duration_seconds: number;
  mode?: string;
  filesystem?: {
    workspace: string;
    scratch: string[];
    read_only: string[];
    execute: string[];
    devices: string[];
    deny: string[];
    memory: { anonymous_execute: boolean };
  };
  process?: { signals: string[] };
};
export type ProfileVersion = {
  id: string;
  profile_id: string;
  number: number;
  parent_id: string;
  document: PolicyDocument;
  digest: string;
  edits: GrantEdit[];
  actor: string;
  reason: string;
  created_at: string;
};
export type Preset = {
  name: string;
  description: string;
  web: string[];
  filesystem: NonNullable<PolicyDocument["filesystem"]>;
  process: NonNullable<PolicyDocument["process"]>;
};
// PolicyChange is one row of the service's structured difference between a
// version and the grant result; access-model.ts diffDocuments computes the
// same rows (a unit test compares them on a real service answer).
export type PolicyChange = { area: string; field: string; change: "added" | "removed" | "changed"; before?: string; after?: string };
export type GrantResult = {
  changed: boolean;
  dry_run?: boolean;
  version?: ProfileVersion;
  document?: PolicyDocument;
  from_version: number;
  from_digest: string;
  digest: string;
  changes: PolicyChange[];
  messages: string[];
  notices: string[];
};
export type Permissions = {
  network_default: string;
  ipv6: string;
  web: string[];
  dns_resolvers: string[];
  taskboard: string;
  read_only: string[] | null;
  writable: string[] | null;
  execute: string[] | null;
  deny: string[] | null;
  devices: string[] | null;
  signals: string[] | null;
  anonymous_execute: boolean;
};
export type PlanMount = { name: string; source: string; mode: string; path: string };
export type PlanSecret = {
  ref: string;
  secret_id: string;
  env: string;
  upstreams: string[];
  header: string;
};
export type LaunchPlan = {
  spec_digest: string;
  policy_digest: string;
  target: { id: string; name: string };
  profile: Record<string, unknown>;
  mode: string;
  lifetime_seconds: number;
  expires_at?: string;
  expiry_rule: string;
  image: string;
  command: string[];
  workdir: string;
  approval: string;
  approval_reasons: string[];
  permissions: Permissions;
  mounts: PlanMount[];
  secrets: PlanSecret[];
  kernel_verified: boolean;
  notices: string[];
};
export type Launch = {
  id: string;
  name: string;
  spec_digest: string;
  target_id: string;
  profile_version_id?: string;
  policy_digest: string;
  mode: string;
  lifetime_seconds: number;
  approval_required: boolean;
  state: string;
  requested_by: string;
  decided_by?: string;
  decision_reason?: string;
  stop_reason?: string;
  terminal_reason?: string;
  evidence_missing?: string;
  kernel_verified: boolean;
  created_at: string;
  updated_at: string;
  queued_at?: string;
  expires_at?: string;
  started_at?: string;
  ended_at?: string;
  revision: number;
  plan?: LaunchPlan;
  receipt?: Receipt;
  spec?: Record<string, unknown>;
  policy?: PolicyDocument;
};
export type Job = {
  id: string;
  type: string;
  target_id: string;
  launch_id?: string;
  state: string;
  attempts: number;
  created_at: string;
  deadline: string;
  completed_at?: string;
  result?: unknown;
  key_id: string;
};
export type LaunchEvent = {
  seq: number;
  time: string;
  kind: string;
  from_state?: string;
  to_state?: string;
  actor: string;
  reason: string;
  data: Record<string, unknown> | null;
};
export type LogLine = { seq: number; time: string; stream: string; text: string };
export type LogPage = {
  items: LogLine[];
  bytes: number;
  limit_bytes: number;
  truncated: boolean;
};
export type Receipt = {
  version: string;
  launch_id: string;
  target_id: string;
  spec_digest: string;
  policy_digest: string;
  bpf_objects: Record<string, string>;
  guard_digest: string;
  network_evidence?: Record<string, unknown>;
  host_control_evidence?: Record<string, unknown>;
  mounts: { name: string; mode: string; identity: string }[];
  broker_counts: Record<string, number>;
  started_at_ms: number;
  ended_at_ms: number;
  exit_code?: number;
  reason: string;
  domain_empty: boolean;
  enforcement_released: boolean;
  kernel_verified: boolean;
};
export type Secret = {
  id: string;
  name: string;
  target_id: string;
  upstreams: string[];
  header: string;
  ciphertext_sha256: string;
  allowed_profiles: string[];
  allowed_launchers: string[];
  state: string;
  removal?: string;
  created_at: string;
  created_by: string;
  updated_at: string;
  revision: number;
};
// LauncherSecret is GET /targets/{id}/secrets for launchers: what a launch
// spec needs, never a fingerprint, envelope, rule path or scope list.
export type LauncherSecret = {
  name: string;
  state: string;
  upstreams: string[];
  rule_count: number;
  wildcard_rules: boolean;
  launcher_allowed: boolean;
  profile_allowed?: boolean;
  usable: boolean;
  reason?: string;
};
export type TargetSecrets = { target_id: string; target: string; profile?: string; items: LauncherSecret[] };
export type APIToken = {
  id: string;
  subject: string;
  name: string;
  roles: string[];
  created_at: string;
  expires_at: string;
  revoked_at?: string;
  last_used_at?: string;
};
export type Items<T> = { items: T[] };
// LaunchPage is GET /launches: one page, newest first, with an opaque cursor
// for the next page when more launches match the filters.
export type LaunchPage = { items: Launch[]; limit: number; next_cursor?: string };
export type LaunchSummary = {
  counts: Record<string, number>;
  total: number;
  active: number;
  awaiting_your_decision: { count: number; items: Launch[] };
  expiring_soon: { count: number; window_seconds: number; items: Launch[] };
};

export const LAUNCH_STATES = [
  "requested",
  "approval_pending",
  "approved",
  "queued",
  "provisioning",
  "running",
  "stopping",
  "stopped",
  "expired",
  "failed",
  "rejected",
  "cancelled",
];
export const TERMINAL_STATES = ["stopped", "expired", "failed", "rejected", "cancelled"];
export const isTerminal = (state: string) => TERMINAL_STATES.includes(state);
export const ROLES = ["viewer", "auditor", "editor", "launcher", "approver", "admin"];

// The honest wording every target and launch view uses. Protocol v1 carries
// no kernel verification report, so the API always reports false.
export const KERNEL_UNVERIFIED = "Kernel enforcement not yet verified on this host";

// Permissions mirrors Actor.Can in internal/control/models.go for a human
// actor. It decides what the page offers; the service decides what happens.
export function permissions(actor: Actor) {
  const roles = actor.roles || [];
  const admin = roles.includes("admin");
  const has = (role: string) => admin || roles.includes(role);
  return {
    admin,
    read: roles.length > 0,
    targetsAdmin: admin,
    secretsAdmin: admin,
    profilesAdmin: admin,
    editProfiles: has("editor"),
    launch: has("launcher"),
    approve: has("approver"),
    audit: has("auditor") || roles.length > 0,
    tokens: actor.kind === "human" && roles.length > 0,
  };
}
export type Perms = ReturnType<typeof permissions>;

export function roleText(actor: Actor) {
  return actor.roles?.length ? actor.roles.join(", ") : "no roles";
}

// useResource loads one API path and cancels the request when the path
// changes or the page unmounts, so leaving a page never applies a late reply.
export function useResource<T>(path: string | null, epoch = 0) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<unknown>();
  const [loading, setLoading] = useState(Boolean(path));
  const [tick, setTick] = useState(0);
  const loaded = useRef(false);
  useEffect(() => {
    if (!path) {
      setLoading(false);
      return;
    }
    const controller = new AbortController();
    setLoading(!loaded.current);
    api<T>(path, "GET", undefined, undefined, undefined, controller.signal)
      .then((value) => {
        loaded.current = true;
        setData(value);
        setError(undefined);
      })
      .catch((cause) => {
        if (!controller.signal.aborted) setError(cause);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [path, epoch, tick]);
  return { data, error, loading, reload: () => setTick((x) => x + 1), setData };
}

export function isApiError(error: unknown, code?: string): error is ApiError {
  return error instanceof ApiError && (code === undefined || error.code === code);
}

export function ago(date?: string, now = Date.now()) {
  if (!date) return "never";
  const ms = now - new Date(date).getTime();
  if (!Number.isFinite(ms)) return "unknown";
  if (ms < 0) return "just now";
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

export function duration(seconds: number) {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  if (seconds < 60) return `${seconds} s`;
  if (seconds < 3600) return `${Math.round((seconds / 60) * 10) / 10} min`;
  return `${Math.round((seconds / 3600) * 10) / 10} h`;
}

export const targetName = (targets: Target[] | undefined, id: string) =>
  targets?.find((t) => t.id === id)?.name || id.slice(0, 8);
