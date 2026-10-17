// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

export type Actor = {
  subject: string;
  kind: string;
  roles: string[];
  scopes: string[];
  name?: string;
};
export type Session = {
  actor: Actor;
  csrf_token: string;
  expires: number;
  fixture_label?: string;
  local_identity?: boolean;
  customer_policy?: boolean;
};
export type Rights = {
  workspace_write: boolean;
  tcp_address: string;
  tcp_port: number;
};
let customerPolicy = false;
export function setCustomerPolicy(value: boolean) { customerPolicy = value; }
export function isCustomerPolicy() { return customerPolicy; }
export type Policy = {
  id: string;
  name: string;
  description: string;
  created_at: string;
};
export type Version = {
  id: string;
  policy_id: string;
  number: number;
  parent_id: string;
  state: string;
  rights: Rights;
  digest: string;
  revision: number;
  actor: string;
  reason: string;
  created_at: string;
};
export type Request = {
  id: string;
  agent_id: string;
  requested_version: string;
  approved_version: string;
  state: string;
  reason: string;
  decision_reason: string;
  decided_by: string;
  revision: number;
  created_at: string;
};
export type Run = {
  id: string;
  agent_id: string;
  admission_id: string;
  version_id: string;
  policy_digest: string;
  verifier: string;
  evidence_digest: string;
  created_at: string;
};
export type Audit = {
  id: number;
  time: string;
  actor: string;
  actor_kind: string;
  action: string;
  resource: string;
  version: string;
  run: string;
  before: unknown;
  after: unknown;
  reason: string;
  request_id: string;
  correlation_id: string;
  result: string;
};
export type Page<T> = { items: T[]; next_cursor?: string };
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public requestID: string,
  ) {
    super(message);
  }
}
let csrf = "";
export function useCSRF(token: string) {
  csrf = token;
}
export async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
  match?: number,
  key?: string,
): Promise<T> {
  const headers: Record<string, string> = {
    "X-Request-ID": crypto.randomUUID(),
  };
  if (method !== "GET") {
    headers["Content-Type"] = "application/json";
    headers["X-CSRF-Token"] = csrf;
    headers["Idempotency-Key"] = key || crypto.randomUUID();
  }
  if (match !== undefined) headers["If-Match"] = `"revision-${match}"`;
  const res = await fetch(
    path.startsWith("/auth/") ? path : `/api/v1/${path}`,
    {
      method,
      headers,
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
    },
  );
  const data = await res.json().catch(() => ({}));
  if (!res.ok)
    throw new ApiError(
      res.status,
      data.error?.code || "request_failed",
      data.error?.message || "The request failed. Try again.",
      data.request_id || res.headers.get("X-Request-ID") || "",
    );
  return data as T;
}
export function can(actor: Actor, role: string) {
  return actor.roles?.includes("admin") || actor.roles?.includes(role);
}
export const short = (id: string) => (id ? `${id.slice(0, 8)}` : "—");
export const when = (date: string) =>
  new Date(date).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
