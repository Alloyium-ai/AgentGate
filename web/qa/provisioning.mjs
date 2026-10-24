// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Browser QA for the provisioning UI against an owned in-process API fixture.
// It builds nothing: run `npm run build` first. Flows: add target and approve
// its host key; create a profile from a preset, grant, dry run and plan;
// launch, wait for approval, approve as another person, run, follow live
// updates (resume and polling fallback), read logs and the receipt, stop;
// store a secret sealed in the browser and refuse substituted keys; API
// tokens; disabled controls for a viewer; session expiry; mobile layout;
// labelled inputs; CSRF on every write.
//
//   QA_OUTPUT=/path/to/owned/dir [QA_CHROMIUM=/path/to/chrome] node qa/provisioning.mjs
import { chromium } from "playwright";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { extname, join } from "node:path";
import { hostFingerprint, hostKeyID, makeRecord, newHost, openEnvelope, rfc3339 } from "./hpke-node.mjs";

const output = process.env.QA_OUTPUT;
if (!output) throw new Error("Set QA_OUTPUT to an owned artifact directory.");
await mkdir(output, { recursive: true });
const repoFile = async (p) => JSON.parse(await readFile(new URL(`../../${p}`, import.meta.url), "utf8"));
const fullExample = await repoFile("internal/access/policy.full.example.json");
const presetFile = await repoFile("internal/access/presets.json");

// ---- fixture state --------------------------------------------------------------
const sha = (s) => createHash("sha256").update(s).digest("hex");
let counter = 0;
const newID = () => (++counter).toString(16).padStart(32, "0");
const now = () => new Date().toISOString();
const actors = {
  alice: { subject: "local:alice", kind: "human", roles: ["admin", "launcher", "editor"], scopes: [], name: "Alice Admin" },
  bob: { subject: "local:bob", kind: "human", roles: ["approver"], scopes: [], name: "Bob Approver" },
  vic: { subject: "local:vic", kind: "human", roles: ["viewer"], scopes: [], name: "Vic Viewer" },
};
let who = "alice";
let expireSessionOnNextRead = false;
const host = newHost();
const attacker = newHost();
let sealMode = "missing";
let dryRun = false;
let streamMode = "ok";
const streamRequests = [];
const requests = [];
const opened = [];
const targets = [];
const profiles = [];
const versions = {};
const launches = [];
const events = {};
const logs = {};
const secrets = [];
const tokens = [];
const presets = Object.entries(presetFile.presets)
  .map(([name, p]) =>
    p.from_example
      ? { name, description: p.description, web: ["http", "https", "quic"], filesystem: fullExample.filesystem, process: fullExample.process }
      : { name, description: p.description, web: p.web, filesystem: p.filesystem, process: p.process },
  )
  .sort((a, b) => a.name.localeCompare(b.name));
const WEB = { http: { protocol: "tcp", port: 80 }, https: { protocol: "tcp", port: 443 }, quic: { protocol: "udp", port: 443 } };

class Fail extends Error {
  constructor(status, code, message) {
    super(message);
    Object.assign(this, { status, code });
  }
}
const can = (role) => actors[who].roles.includes("admin") || actors[who].roles.includes(role);
const need = (role) => {
  if (!can(role)) throw new Fail(403, "forbidden", "Your identity does not permit this operation.");
};

function docFromPreset(name) {
  const d = structuredClone(fullExample);
  if (!name) return d;
  const p = presets.find((x) => x.name === name);
  d.filesystem = structuredClone(p.filesystem);
  d.process = structuredClone(p.process);
  d.web.rules = p.web.map((w) => WEB[w]);
  return d;
}
function applyEdits(doc, edits) {
  const d = structuredClone(doc);
  const messages = [];
  const notices = [];
  for (const e of edits) {
    const v = e.values || [];
    const fs = d.filesystem;
    const writable = [fs.workspace, ...fs.scratch];
    const under = (list, p) => list.find((x) => p === x || p.startsWith(x + "/"));
    switch (e.action) {
      case "read":
        if (under([...fs.read_only, ...fs.execute, ...writable], v[0])) messages.push(`${v[0]} is already readable through ${under([...fs.read_only, ...fs.execute, ...writable], v[0])}`);
        else fs.read_only.push(v[0]), messages.push("read-only: added " + v[0]);
        break;
      case "exec":
        if (under(writable, v[0])) throw new Fail(409, "grant_conflict", `${v[0]} overlaps the writable tree ${under(writable, v[0])}; writable trees never run code`);
        fs.execute.push(v[0]);
        messages.push("executable: added " + v[0]);
        break;
      case "write":
        fs.scratch.push(v[0]);
        messages.push("writable (never executable): added " + v[0]);
        notices.push(`the container root is read-only: ${v[0]} is writable only below a writable mount (the workspace, /tmp, or a read-write host folder)`);
        break;
      case "deny":
        fs.deny.push(v[0]);
        messages.push("denied: added " + v[0]);
        break;
      case "allow-web":
      case "deny-web": {
        const names = new Set(Object.keys(WEB).filter((n) => d.web.rules.some((r) => r.protocol === WEB[n].protocol && r.port === WEB[n].port)));
        for (const n of v.length ? v : Object.keys(WEB)) e.action === "allow-web" ? names.add(n) : names.delete(n);
        d.web.rules = Object.keys(WEB).filter((n) => names.has(n)).map((n) => WEB[n]);
        messages.push(`public web: ${e.action === "allow-web" ? "allowed" : "denied"} ${v.join(", ")}`);
        break;
      }
      case "mount":
        (e.mode === "read-write" ? fs.scratch : fs.read_only).push("/var/lib/agentgate/mounts/" + v[0]);
        messages.push(`host folder: /var/lib/agentgate/mounts/${v[0]} (${e.mode || "read-only"})`);
        break;
      case "revoke":
        if (e.kind === "read") fs.read_only = fs.read_only.filter((x) => x !== v[0]);
        messages.push(`${e.kind}: removed ${v[0] || ""}`);
        break;
      default:
        messages.push(`${e.action}: applied`);
    }
  }
  return { d, messages, notices };
}
const findTarget = (ref) => targets.find((t) => t.id === ref || (t.name === ref && t.state !== "retired"));
const findProfile = (ref) => profiles.find((p) => p.id === ref || p.name === ref);
function transition(l, to, actor, reason, data = {}) {
  const list = events[l.id];
  list.push({ seq: list.length + 1, time: now(), kind: "state", from_state: l.state, to_state: to, actor, reason, data });
  l.state = to;
  l.updated_at = now();
  l.revision++;
}
function progress(l, kind, reason, data = {}) {
  const list = events[l.id];
  list.push({ seq: list.length + 1, time: now(), kind, from_state: l.state, to_state: l.state, actor: "hostd:" + l.target_id, reason, data });
}
function plan(spec, actor) {
  need("launcher");
  if (!/^[a-z0-9][a-z0-9-]{0,39}$/.test(spec.name || "")) throw new Fail(422, "invalid_launch_spec", "name must match ^[a-z0-9][a-z0-9-]{0,39}$");
  const target = findTarget(spec.target);
  if (!target || target.state !== "active") throw new Fail(422, "target_unavailable", "The launch target is not enrolled and active.");
  const p = findProfile(spec.access.profile);
  const v = p && versions[p.id].find((x) => x.number === spec.access.version);
  if (!v) throw new Fail(422, "profile_unavailable", "The access profile version does not exist.");
  const reasons = [];
  if (p.require_approval) reasons.push("the profile requires approval");
  if (spec.approval === "required") reasons.push("the spec requires approval");
  for (const m of spec.mounts) if (m.mode !== "snapshot") reasons.push((m.mode === "read-write" ? "read-write host folder " : "live host folder ") + m.name);
  const planned = [];
  for (const s of spec.secrets) {
    const sec = secrets.find((x) => x.target_id === target.id && x.name === s.ref && x.state === "stored");
    if (!sec) throw new Fail(422, "secret_unavailable", `Secret ${s.ref} is not stored on the launch target.`);
    if (!sec.allowed_launchers.includes(actor)) throw new Fail(403, "secret_scope", "The secret is not scoped to this launcher.");
    planned.push({ ref: s.ref, secret_id: sec.id, env: s.expose.env, upstreams: sec.upstreams, header: sec.header });
  }
  if (spec.secrets.length) reasons.push("brokered secrets " + spec.secrets.map((s) => s.ref).join(", "));
  const policy = structuredClone(v.document);
  for (const m of spec.mounts) (m.mode === "read-write" ? policy.filesystem.scratch : policy.filesystem.read_only).push("/var/lib/agentgate/mounts/" + m.name);
  if (policy.web.rules.length) reasons.push("public web access");
  policy.mode = spec.mode;
  policy.duration_seconds = spec.lifetime_seconds;
  const fs = policy.filesystem;
  return {
    policy,
    plan: {
      spec_digest: sha(JSON.stringify(spec)),
      policy_digest: sha(JSON.stringify(policy)),
      target: { id: target.id, name: target.name },
      profile: { id: p.id, name: p.name, version: v.number, version_id: v.id, digest: v.digest },
      mode: spec.mode,
      lifetime_seconds: spec.lifetime_seconds,
      expires_at: new Date(Date.now() + spec.lifetime_seconds * 1000).toISOString(),
      expiry_rule: "the lifetime starts when the launch is queued; the host and the kernel policy end it at expires_at",
      image: spec.agent.image,
      command: spec.agent.command,
      workdir: spec.agent.workdir || "/var/lib/agentgate/workspace",
      approval: reasons.length ? "required" : "auto",
      approval_reasons: reasons.sort(),
      permissions: { network_default: "deny", ipv6: "deny", web: Object.keys(WEB).filter((n) => policy.web.rules.some((r) => r.protocol === WEB[n].protocol && r.port === WEB[n].port)), dns_resolvers: policy.dns.resolvers, taskboard: "10.10.10.10:8080", read_only: fs.read_only, writable: [fs.workspace, ...fs.scratch], execute: fs.execute, deny: fs.deny, devices: fs.devices, signals: policy.process.signals, anonymous_execute: false },
      mounts: spec.mounts.map((m) => ({ ...m, path: "/var/lib/agentgate/mounts/" + m.name })),
      secrets: planned,
      kernel_verified: false,
      notices: ["kernel_verified is false: this enforcement has not been verified on a BPF LSM kernel"],
    },
  };
}
const summary = (l) => {
  const { plan: _p, receipt: _r, spec: _s, policy: _y, ...rest } = l;
  return rest;
};
const sse = (list, after) => "event: ready\ndata: {}\n\n" + list.filter((e) => e.seq > after).map((e) => `id: ${e.seq}\nevent: ${e.kind}\ndata: ${JSON.stringify(e)}\n\n`).join("");

function api(method, path, query, input, headers) {
  const parts = path.split("/");
  const [area, id, sub] = parts;
  if (path === "session") {
    if (expireSessionOnNextRead) throw new Fail(401, "session_expired", "The browser session expired or was revoked.");
    return { actor: actors[who], csrf_token: "fixture-csrf", expires: Math.floor(Date.now() / 1000) + 3600, local_identity: true, customer_policy: false };
  }
  if (expireSessionOnNextRead) throw new Fail(401, "session_expired", "The browser session expired or was revoked.");
  if (path === "overview") return {};
  if (path === "access-presets") return { items: presets, actions: ["read"], revoke_kinds: ["read"] };
  if (area === "targets") {
    if (method === "GET" && !id) return { items: targets };
    if (method === "POST" && !id) {
      need("admin");
      const t = { id: newID(), name: input.name, state: "pending", capabilities: [], hostname: "", agent_version: "", host_key_id: "", encryption_key: "", job_key_id: "", online: false, heartbeat_seconds: 10, created_at: now(), created_by: actors[who].subject, updated_at: now(), revision: 1, kernel_verified: false };
      targets.push(t);
      return { target: t, enrollment: { token: "agtenr_" + randomBytes(32).toString("base64url"), expires_at: new Date(Date.now() + 900000).toISOString(), single_use: true, enroll_path: "/api/v1/hostd/enroll" } };
    }
    const t = findTarget(id);
    if (!t) throw new Fail(404, "not_found", "The target does not exist.");
    if (method === "GET" && !sub) return t;
    if (method === "GET" && sub === "seal-key") {
      if (sealMode === "missing") throw new Fail(404, "not_found", "The API endpoint does not exist.");
      const nb = rfc3339(Date.now() - 3600000);
      const na = rfc3339(Date.now() + 30 * 86400000);
      if (sealMode === "good") return { record: makeRecord(host.signingKey, host.hostPub, host.sealPub, t.id, nb, na), host_public_key: host.hostPub.toString("base64url"), host_key_fingerprint: hostFingerprint(host.hostPub) };
      if (sealMode === "substituted") return { record: makeRecord(attacker.signingKey, attacker.hostPub, attacker.sealPub, t.id, nb, na), host_public_key: attacker.hostPub.toString("base64url"), host_key_fingerprint: hostFingerprint(attacker.hostPub) };
      if (sealMode === "forged") return { record: makeRecord(attacker.signingKey, attacker.hostPub, attacker.sealPub, t.id, nb, na), host_public_key: host.hostPub.toString("base64url"), host_key_fingerprint: hostFingerprint(host.hostPub) };
    }
    if (method === "POST" && sub === "approve-key") {
      need("admin");
      if (t.state !== "awaiting_key_approval") throw new Fail(409, "no_pending_key", "The target has no host key waiting for approval.");
      if (input.host_key_id !== t.host_key_id) throw new Fail(409, "fingerprint_mismatch", "The fingerprint differs from the key the host presented. Do not approve; issue a new token.");
      Object.assign(t, { state: "active", online: true, last_seen_at: now(), revision: t.revision + 1 });
      return t;
    }
    if (method === "DELETE") {
      need("admin");
      t.state = "retired";
      return t;
    }
  }
  if (area === "profiles") {
    if (method === "GET" && !id) return { items: profiles };
    if (method === "POST" && !id) {
      need("editor");
      if (input.require_approval === false) need("admin");
      const p = { id: newID(), name: input.name, description: input.description || "", require_approval: input.require_approval !== false, created_at: now(), created_by: actors[who].subject, revision: 1, latest_version: 1 };
      const d = docFromPreset(input.preset);
      profiles.push(p);
      versions[p.id] = [{ id: newID(), profile_id: p.id, number: 1, parent_id: "", document: d, digest: sha(JSON.stringify(d)), edits: input.preset ? [{ action: "preset", values: [input.preset] }] : [], actor: actors[who].subject, reason: input.reason, created_at: now() }];
      return { profile: p, version: versions[p.id][0] };
    }
    const p = findProfile(id);
    if (!p) throw new Fail(404, "not_found", "The profile does not exist.");
    const list = versions[p.id];
    if (method === "GET" && !sub) return p;
    if (method === "PATCH") {
      need("admin");
      p.require_approval = input.require_approval;
      return p;
    }
    if (method === "GET" && sub === "versions" && !parts[3]) return { items: [...list].reverse() };
    if (method === "POST" && sub === "versions" && parts[4] === "grants") {
      need("editor");
      if (input.dry_run && !dryRun) throw new Fail(422, "schema_constraint", "A request value does not match the API contract.");
      if (Number(parts[3]) !== p.latest_version) throw new Fail(409, "stale_parent", "Grants apply to the latest profile version only.");
      const parent = list.at(-1);
      const { d, messages, notices } = applyEdits(parent.document, input.edits);
      const digest = sha(JSON.stringify(d));
      if (input.dry_run) return { dry_run: true, changed: digest !== parent.digest, document: d, digest, messages, notices };
      if (digest === parent.digest) return { changed: false, version: parent, messages, notices };
      const v = { id: newID(), profile_id: p.id, number: parent.number + 1, parent_id: parent.id, document: d, digest, edits: input.edits, actor: actors[who].subject, reason: input.reason, created_at: now() };
      list.push(v);
      p.latest_version = v.number;
      return { changed: true, version: v, messages, notices };
    }
  }
  if (area === "launch-plans") {
    const out = plan(input, actors[who].subject);
    return { dry_run: true, plan: out.plan, spec: input, policy: out.policy };
  }
  if (area === "launches") {
    if (method === "GET" && !id) return { items: launches.filter((l) => !query.get("state") || l.state === query.get("state")).map(summary).reverse() };
    if (method === "POST" && !id) {
      const out = plan(input, actors[who].subject);
      const l = { id: newID(), name: input.name, spec_digest: out.plan.spec_digest, target_id: out.plan.target.id, policy_digest: out.plan.policy_digest, mode: input.mode, lifetime_seconds: input.lifetime_seconds, approval_required: out.plan.approval === "required", state: "requested", requested_by: actors[who].subject, kernel_verified: false, created_at: now(), updated_at: now(), revision: 1, plan: { ...out.plan, expires_at: undefined }, spec: input, policy: out.policy };
      launches.push(l);
      events[l.id] = [{ seq: 1, time: now(), kind: "state", from_state: "", to_state: "requested", actor: l.requested_by, reason: "Launch requested", data: { spec_digest: l.spec_digest, policy_digest: l.policy_digest } }];
      logs[l.id] = [];
      transition(l, out.plan.approval === "required" ? "approval_pending" : "approved", l.requested_by, out.plan.approval === "required" ? "Approval required: " + out.plan.approval_reasons.join("; ") : "Automatic approval");
      return { launch: summary(l), plan: out.plan };
    }
    const l = launches.find((x) => x.id === id);
    if (!l) throw new Fail(404, "not_found", "The launch does not exist.");
    if (method === "GET" && !sub) return { launch: l, jobs: [{ id: "job-" + l.id.slice(-6), type: "launch", target_id: l.target_id, launch_id: l.id, state: ["queued", "provisioning", "running", "stopping", "stopped"].includes(l.state) ? "delivered" : "queued", attempts: 1, created_at: l.created_at, deadline: new Date(Date.now() + 3600000).toISOString(), key_id: "ed25519:job" }] };
    if (method === "GET" && sub === "events") {
      const after = Number(query.get("after") || 0);
      if ((headers.accept || "").includes("text/event-stream")) {
        streamRequests.push({ id, after, lastEventID: headers["last-event-id"], mode: streamMode });
        if (streamMode === "fail") throw new Fail(503, "request_capacity", "Stream capacity reached.");
        return { __sse: sse(events[id], after) };
      }
      return { items: events[id].filter((e) => e.seq > after) };
    }
    if (method === "GET" && sub === "logs") {
      const after = Number(query.get("after") || 0);
      return { items: logs[id].filter((x) => x.seq > after), bytes: 1024, limit_bytes: 1 << 20, truncated: logs[id].some((x) => x.text.includes("[output truncated")) };
    }
    if (method === "POST" && (sub === "approve" || sub === "reject")) {
      need("approver");
      if (l.requested_by === actors[who].subject) throw new Fail(403, "self_approval", "A different human must decide this launch.");
      if (l.state !== "approval_pending") throw new Fail(409, "not_pending", "The launch is not waiting for approval.");
      l.decided_by = actors[who].subject;
      l.decision_reason = input.reason;
      if (sub === "reject") {
        transition(l, "rejected", actors[who].subject, input.reason);
        l.evidence_missing = "not_started";
        return summary(l);
      }
      transition(l, "approved", actors[who].subject, input.reason);
      l.queued_at = now();
      l.expires_at = new Date(Date.now() + l.lifetime_seconds * 1000).toISOString();
      transition(l, "queued", actors[who].subject, "Queued for the target", { expires_at: l.expires_at });
      return summary(l);
    }
    if (method === "POST" && sub === "stop") {
      need("launcher");
      if (["requested", "approval_pending", "approved"].includes(l.state)) {
        transition(l, "cancelled", actors[who].subject, input.reason);
        l.evidence_missing = "not_started";
      } else if (!["stopping", "stopped", "expired", "failed", "rejected", "cancelled"].includes(l.state)) {
        l.stop_reason = input.reason;
        transition(l, "stopping", actors[who].subject, input.reason);
      }
      return summary(l);
    }
  }
  if (area === "secrets") {
    need("admin");
    if (method === "GET") return { items: secrets };
    if (method === "POST") {
      let envelope;
      let raw;
      try {
        raw = Buffer.from(input.ciphertext, "base64url");
        envelope = JSON.parse(raw.toString());
      } catch {
        throw new Fail(422, "invalid_ciphertext", "Seal the value to the target's encryption key with the hostproto secret format.");
      }
      const t = findTarget(input.target);
      if (envelope.target_id !== t.id || envelope.name !== input.name) throw new Fail(422, "invalid_ciphertext", "The envelope is for another target or name.");
      opened.push(openEnvelope(host.sealPrivate, envelope).plaintext.toString());
      const s = { id: newID(), name: input.name, target_id: t.id, upstreams: input.upstreams, header: input.header, ciphertext_sha256: sha(raw), allowed_profiles: input.allowed_profiles, allowed_launchers: input.allowed_launchers, state: "pending", created_at: now(), created_by: actors[who].subject, updated_at: now(), revision: 1 };
      secrets.push(s);
      setTimeout(() => (s.state = "stored"), 1500);
      return s;
    }
  }
  if (area === "api-tokens") {
    if (method === "GET") return { items: tokens.filter((t) => actors[who].roles.includes("admin") || t.subject === actors[who].subject) };
    if (method === "POST") {
      const t = { id: newID(), subject: actors[who].subject, name: input.name, roles: input.roles, created_at: now(), expires_at: new Date(Date.now() + input.expires_in_seconds * 1000).toISOString() };
      tokens.push(t);
      return { ...t, token: "agt_" + randomBytes(32).toString("base64url") };
    }
    if (method === "DELETE") {
      const t = tokens.find((x) => x.id === id);
      t.revoked_at = now();
      return { id, revoked_at: t.revoked_at };
    }
  }
  throw new Fail(404, "not_found", "The API endpoint does not exist.");
}

// ---- host simulation --------------------------------------------------------------
function enrollHost(name) {
  const t = findTarget(name);
  Object.assign(t, { state: "awaiting_key_approval", hostname: "build-01.example", agent_version: "0.3.0-qa", host_key_id: hostKeyID(host.hostPub), encryption_key: host.sealPub.toString("base64url"), job_key_id: "ed25519:" + "9".repeat(32), capabilities: ["docker", "pocpolicy-v2", "live-mounts", "snapshot-mounts", "broker"] });
}
function hostRun(l) {
  transition(l, "provisioning", "hostd:" + l.target_id, "The host reports provisioning");
  transition(l, "running", "hostd:" + l.target_id, "The host reports running");
  l.started_at = now();
  const at = Date.now();
  logs[l.id].push(
    { seq: 1, time: new Date(at).toISOString(), stream: "stdout", text: "agent started <img src=x onerror=alert(1)>" },
    { seq: 2, time: new Date(at + 1).toISOString(), stream: "stderr", text: "warning \x1b[31mred\x1b[0m ‮evil" },
  );
}
function hostFinish(l) {
  logs[l.id].push({ seq: 3, time: now(), stream: "stdout", text: "[output truncated at the 1 MiB launch log limit]" });
  l.receipt = {
    version: "agentgate.receipt.v1",
    launch_id: l.id,
    target_id: l.target_id,
    spec_digest: l.spec_digest,
    policy_digest: l.policy_digest,
    bpf_objects: { "network.bpf.o": "1".repeat(64), "fs.bpf.o": "2".repeat(64) },
    guard_digest: "3".repeat(64),
    network_evidence: { state: "stopped", evidence_complete: true, guard: { network: { hooks: { connect4: { allowed: 7, denied: 2 } }, lost: 0, decisions: 9, observed: 9, complete: true } } },
    host_control_evidence: { filesystem: { lost: 0, decisions: 30, observed: 30, complete: true, operations: { open_read: { allowed: 25, denied: 3 }, exec: { allowed: 2, denied: 0 } }, denials: [{ sequence: 4, pid: 77, operation: "open_read", path: "/etc/shadow" }] }, process: { lost: 1, complete: false, operations: { signal: { allowed: 1, denied: 1 } }, denials: [] }, complete: false },
    mounts: [{ name: "repo", mode: "snapshot", identity: "sha256:" + "4".repeat(64) }],
    broker_counts: { "api.model.example": 3 },
    started_at_ms: Date.now() - 60000,
    ended_at_ms: Date.now(),
    exit_code: 0,
    reason: "stopped",
    domain_empty: true,
    enforcement_released: true,
    kernel_verified: false,
  };
  progress(l, "receipt", "The host attached the evidence receipt", { receipt_digest: "5".repeat(64) });
  transition(l, "stopped", "hostd:" + l.target_id, "The host confirmed an empty domain and released enforcement");
  l.ended_at = now();
}

// ---- browser ---------------------------------------------------------------------
const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, "http://fixture").pathname;
    const file = join(new URL("../dist/", import.meta.url).pathname, path === "/" ? "index.html" : path);
    response.setHeader("Content-Type", { ".html": "text/html", ".js": "application/javascript", ".css": "text/css" }[extname(file)] || "application/octet-stream");
    response.end(await readFile(file));
  } catch {
    response.writeHead(404);
    response.end();
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ headless: true, executablePath: process.env.QA_CHROMIUM || undefined });
const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, permissions: ["clipboard-read", "clipboard-write"] });
const pageErrors = [];
const consoleErrors = [];
await ctx.route("**/api/v1/**", async (route) => {
  const req = route.request();
  const url = new URL(req.url());
  const path = url.pathname.slice("/api/v1/".length);
  const headers = req.headers();
  const input = req.method() === "GET" ? undefined : req.postDataJSON();
  requests.push({ method: req.method(), path, url: req.url(), headers, body: req.postData() || "" });
  if (path === "events") return route.fulfill({ contentType: "text/event-stream", body: ": fixture\n\n" });
  try {
    const value = api(req.method(), path, url.searchParams, input, headers);
    if (value && value.__sse !== undefined) return route.fulfill({ status: 200, headers: { "Content-Type": "text/event-stream" }, body: value.__sse });
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(value) });
  } catch (e) {
    if (!(e instanceof Fail)) throw e;
    return route.fulfill({ status: e.status, contentType: "application/json", body: JSON.stringify({ error: { code: e.code, message: e.message }, request_id: "qa-" + requests.length }) });
  }
});
const page = await ctx.newPage();
page.on("pageerror", (e) => pageErrors.push(e.message));
page.on("console", (m) => {
  if (m.type() === "error" && !m.text().startsWith("Failed to load resource")) consoleErrors.push(m.text());
});
const report = { status: "FAIL", fixture: "isolated browser API fixture (owned mock, node:crypto host)", steps: {} };
const step = async (name, fn) => {
  const started = Date.now();
  await fn();
  report.steps[name] = { pass: true, ms: Date.now() - started };
  console.log("PASS", name);
};
let visit = 0;
const go = async (hash, as = who) => {
  who = as;
  // A changed query forces a full load, so the app reads the session again.
  await page.goto(`${base}/?visit=${++visit}#/${hash}`);
  await page.locator("main h1").first().waitFor();
};
const text = (t, o = {}) => page.getByText(t, { exact: false, ...o }).first();
// A <select> nested in its <label> has the option texts in the label text, so
// select controls are found by the label's leading text.
const pick = (label, scope = page) => scope.locator("label").filter({ hasText: new RegExp("^" + label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")) }).locator("select").first();
async function unlabeled() {
  return page.evaluate(() =>
    [...document.querySelectorAll("main input, main select, main textarea, dialog input, dialog select, dialog textarea")]
      .filter((el) => el.offsetParent !== null && el.type !== "hidden")
      .filter((el) => !(el.labels && el.labels.length) && !el.getAttribute("aria-label") && !el.getAttribute("aria-labelledby"))
      .map((el) => el.outerHTML.slice(0, 120)),
  );
}
const a11y = {};
async function checkLabels(name) {
  const missing = await unlabeled();
  a11y[name] = missing;
  assert.deepEqual(missing, [], `${name}: inputs without labels`);
}
async function noHorizontalScroll(name) {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForTimeout(150);
  const ok = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1);
  // The widest elements that reach past the viewport, outside scrollable
  // containers (tables and code blocks scroll inside their own box).
  const offenders = ok
    ? []
    : await page.evaluate(() =>
        [...document.querySelectorAll("main *")]
          .filter((el) => el.getBoundingClientRect().right > innerWidth + 1 && !el.closest(".table-wrap, pre, .log-view"))
          .slice(0, 6)
          .map((el) => `${el.tagName.toLowerCase()}.${el.className} right=${Math.round(el.getBoundingClientRect().right)}`),
      );
  await page.screenshot({ path: `${output}/${name}-mobile.png`, fullPage: true });
  await page.setViewportSize({ width: 1440, height: 1000 });
  assert.ok(ok, `${name}: horizontal scroll at 390 px: ${offenders.join("; ")}`);
}

let launchID = "";
const value = "sk-test-QA-browser-sealed-" + randomBytes(6).toString("hex");
try {
  await step("add target, show the token once, approve the host key", async () => {
    await go("targets", "alice");
    await text("Kernel enforcement not yet verified on this host").waitFor();
    await page.getByRole("button", { name: "Add target" }).click();
    await page.getByLabel("Target name").fill("build-host");
    await page.getByRole("textbox", { name: "Reason", exact: true }).fill("Enroll the build host");
    await page.getByRole("button", { name: "Create target and token" }).click();
    const tokenField = page.getByLabel("One-time enrollment token");
    await tokenField.waitFor();
    const token = await tokenField.inputValue();
    assert.match(token, /^agtenr_[A-Za-z0-9_-]{43}$/);
    const command = await page.locator("dialog pre").innerText();
    assert.ok(command.includes(`printf '%s\\n' '${token}' > agentgate-enroll.token`));
    assert.ok(command.includes("sudo agentgate-hostd install") && command.includes("--token-file agentgate-enroll.token") && command.includes(`--service-url ${base}`) && command.includes("--allow-loopback-http"));
    await checkLabels("enrollment dialog");
    await page.screenshot({ path: `${output}/target-enrollment.png` });
    await page.getByRole("button", { name: "I copied the token" }).click();
    await page.locator("dialog").waitFor({ state: "detached" });
    assert.ok(!(await page.content()).includes(token), "the token stays in the page after the dialog closed");
    enrollHost("build-host");
    await page.reload();
    await page.getByRole("button", { name: "build-host" }).click();
    await text("Awaiting host key approval").waitFor();
    await page.getByRole("button", { name: "Approve host key" }).click();
    const dialog = page.locator("dialog");
    await dialog.getByText(hostKeyID(host.hostPub)).waitFor();
    await page.getByLabel("Fingerprint shown on the host").fill("ed25519:" + "0".repeat(32));
    await dialog.getByText("No match. Do not approve").waitFor();
    assert.equal(await dialog.getByRole("button", { name: "Approve host key" }).isDisabled(), true);
    await page.getByLabel("Fingerprint shown on the host").fill(hostKeyID(host.hostPub));
    await dialog.getByText("Match: the fingerprints are identical.").waitFor();
    assert.equal(await dialog.getByRole("button", { name: "Approve host key" }).isDisabled(), true, "approval waits for the confirmation step");
    await dialog.getByLabel("I read this fingerprint on the host itself, not from a message or this page.").check();
    await dialog.getByRole("textbox", { name: "Reason", exact: true }).fill("Matches the host console");
    await checkLabels("approve key dialog");
    await dialog.getByRole("button", { name: "Approve host key" }).click();
    await page.locator("dialog").waitFor({ state: "detached" });
    await page.locator(".section-title .badge", { hasText: "active" }).waitFor();
    const approve = requests.find((r) => r.path.endsWith("/approve-key"));
    assert.equal(JSON.parse(approve.body).host_key_id, hostKeyID(host.hostPub));
    const pins = await page.evaluate(() => localStorage.getItem("agentgate.known-targets.v1"));
    assert.equal(JSON.parse(pins)[findTarget("build-host").id], hostKeyID(host.hostPub), "approval pins the host key in this browser");
    await text("no — not yet verified on this host").waitFor();
  });

  await step("create a profile from a preset, grant with dry run, and see validator errors verbatim", async () => {
    await go("profiles", "alice");
    await page.getByRole("button", { name: "New profile" }).click();
    await page.getByLabel("Profile name").fill("python-dev");
    await pick("Preset").selectOption("python-dev");
    await text("HTTP and HTTPS (no QUIC)").waitFor();
    await page.locator("dialog").getByRole("textbox", { name: "Reason", exact: true }).fill("Python work");
    await checkLabels("create profile");
    await page.getByRole("button", { name: "Create version 1" }).click();
    await page.getByRole("heading", { name: "python-dev", exact: true }).waitFor();
    await page.getByRole("heading", { name: "What can this agent do? (v1)" }).waitFor();
    await text("not limited to particular sites").waitFor();
    await page.getByRole("button", { name: "Show policy JSON" }).click();
    assert.ok((await page.getByLabel("Policy JSON (read-only)").innerText()).includes('"agentgate.poc.v2"'));
    const read = page.locator(".grant-list", { has: page.getByRole("heading", { name: "Read", exact: true }) });
    await read.getByRole("textbox").fill("/srv/data");
    await read.getByRole("button", { name: "Stage read" }).click();
    await text("Let the agent read /srv/data").waitFor();
    await page.locator(".access-editor").getByRole("textbox", { name: "Reason", exact: true }).fill("Read the data set");
    await page.getByRole("button", { name: "Preview (dry run)" }).click();
    await text("may not offer a grant dry run yet").waitFor();
    await text("schema_constraint").waitFor();
    assert.equal(versions[profiles[0].id].length, 1, "a refused dry run created nothing");
    dryRun = true;
    await page.getByRole("button", { name: "Preview (dry run)" }).click();
    await text("Dry run: the service's result (nothing was stored)").waitFor();
    await page.locator(".preview").getByRole("cell", { name: "/srv/data" }).waitFor();
    await page.locator(".preview").getByText("read-only: added /srv/data").waitFor();
    assert.equal(versions[profiles[0].id].length, 1, "a dry run created nothing");
    await checkLabels("access editor");
    await page.getByRole("button", { name: "Apply as version 2" }).click();
    await page.getByRole("heading", { name: "Version 2", exact: true }).waitFor();
    const applied = page.getByRole("region", { name: "Last applied change" });
    await applied.getByRole("heading", { name: "Applied: version 2 (from v1)" }).waitFor();
    await applied.getByRole("cell", { name: "/srv/data" }).waitFor();
    await applied.getByText("read-only: added /srv/data").waitFor();
    await page.getByRole("heading", { name: "Change access (rolls forward to version 3)" }).waitFor();
    await page.waitForURL(/#\/profiles\/python-dev\/2$/, { timeout: 5000 }).catch(() => { throw new Error("url " + page.url()); });
    await page.getByRole("heading", { name: "What can this agent do? (v2)" }).waitFor();
    await page.locator("text=Changes from v1").waitFor();
    const exec = page.locator(".grant-list", { has: page.getByRole("heading", { name: "Execute", exact: true }) });
    await exec.getByRole("textbox").fill("/var/lib/agentgate/workspace/bin");
    await exec.getByRole("button", { name: "Stage exec" }).click();
    await page.locator(".access-editor").getByRole("textbox", { name: "Reason", exact: true }).fill("Run built tools");
    await page.getByRole("button", { name: "Apply as version 3" }).click();
    await text("overlaps the writable tree /var/lib/agentgate/workspace; writable trees never run code").waitFor();
    await text("grant_conflict").waitFor();
    assert.equal(versions[profiles[0].id].length, 2);
    await page.locator(".version-list button", { hasText: "Version 1" }).click();
    await page.getByRole("heading", { name: "Version 1", exact: true }).waitFor();
    await pick("Compare v1 with").selectOption("2");
    await page.getByRole("heading", { name: "From v1 to v2" }).waitFor();
    await page.screenshot({ path: `${output}/profile-desktop.png`, fullPage: true });
    await noHorizontalScroll("profile");
  });

  await step("launch form: credential env refused, review and plan required, stale plan blocks launch", async () => {
    await go("launch", "alice");
    await page.getByLabel("Launch name").fill("repo-fixer");
    await pick("Target").selectOption("build-host");
    await page.getByLabel("Lifetime (hard cap)").fill("45");
    await page.getByLabel("Image (immutable digest)").fill("agentgate-coding@sha256:" + "a".repeat(64));
    await page.getByLabel("Command, one argument per line (no shell)").fill("claude\n--print\nfix the failing tests");
    await page.getByRole("button", { name: "Add variable" }).click();
    await page.locator(".row-edit").first().getByLabel("Name").fill("API_KEY");
    await text("API_KEY looks like a credential").waitFor();
    await page.locator(".row-edit").first().getByLabel("Name").fill("EDITOR");
    await page.locator(".row-edit").first().getByLabel("Value").fill("vi");
    await pick("Profile").selectOption("python-dev");
    await pick("Version").selectOption("2");
    await page.getByRole("heading", { name: /What can this agent do\? \(python-dev v2/ }).waitFor();
    await page.getByRole("button", { name: "Add host folder" }).click();
    await page.getByLabel("Name in the agent").fill("repo");
    await page.getByRole("textbox", { name: "Host folder", exact: true }).fill("/etc/app");
    await text("overlaps the protected host tree /etc").waitFor();
    await page.getByRole("textbox", { name: "Host folder", exact: true }).fill("/srv/repos/app");
    await pick("Mode").selectOption("snapshot");
    await text("This launch will probably need approval because:").waitFor();
    assert.equal(await page.getByRole("button", { name: /^Launch/ }).count(), 0, "no launch button before a plan");
    await checkLabels("launch form");
    await page.getByRole("button", { name: "Review & plan" }).click();
    await page.locator(".plan").waitFor();
    await page.locator(".plan").getByText("the profile requires approval").waitFor();
    await page.locator(".plan").getByText("kernel_verified is false: this enforcement has not been verified on a BPF LSM kernel").waitFor();
    await page.locator(".plan").getByRole("cell", { name: "/srv/repos/app" }).waitFor();
    await page.getByRole("heading", { name: "What can this agent do? (effective launch policy)" }).waitFor();
    const planned = JSON.parse(requests.filter((r) => r.path === "launch-plans").at(-1).body);
    assert.deepEqual(planned.agent.command, ["claude", "--print", "fix the failing tests"]);
    assert.equal(planned.lifetime_seconds, 2700);
    assert.deepEqual(planned.agent.env, { EDITOR: "vi" });
    await page.getByLabel("Launch name").fill("repo-fixer-2");
    await text("The form changed after this plan. Plan again before launching.").waitFor();
    assert.equal(await page.getByRole("button", { name: "Launch (waits for approval)" }).isDisabled(), true);
    await page.getByLabel("Launch name").fill("repo-fixer");
    await page.getByRole("button", { name: "Review & plan" }).click();
    await page.getByRole("button", { name: "Launch (waits for approval)" }).waitFor();
    await page.getByRole("button", { name: "Copy as CLI commands" }).click();
    const clip = await page.evaluate(() => navigator.clipboard.readText());
    assert.ok(clip.includes("agentgate launch -f repo-fixer.json") && clip.includes('"name": "repo-fixer"'));
    await page.screenshot({ path: `${output}/launch-plan-desktop.png`, fullPage: true });
    await noHorizontalScroll("launch-form");
    await page.getByRole("button", { name: "Launch (waits for approval)" }).click();
    await page.getByRole("heading", { name: "State timeline" }).waitFor();
    launchID = page.url().split("/").at(-1);
    const launched = JSON.parse(requests.filter((r) => r.path === "launches" && r.method === "POST").at(-1).body);
    assert.deepEqual(launched, planned, "the launch sends exactly the planned spec");
    await page.locator(".section-title .badge", { hasText: "Waiting for approval" }).waitFor();
  });

  await step("the requester cannot approve; another approver can; live updates follow the run", async () => {
    await text("You requested this launch. A different person must decide it.").waitFor();
    assert.equal(await page.getByRole("button", { name: "Approve", exact: true }).isDisabled(), true);
    await go(`launches/${launchID}`, "bob");
    await text("Stopping needs the launcher role").waitFor();
    await page.getByRole("button", { name: "Approve", exact: true }).click();
    await page.locator("dialog").getByText("the profile requires approval").waitFor();
    await page.locator("dialog").getByRole("textbox", { name: "Reason", exact: true }).fill("Reviewed the plan");
    await page.getByRole("button", { name: "Approve this exact plan" }).click();
    await page.locator(".section-title .badge", { hasText: "queued" }).waitFor();
    const before = streamRequests.length;
    hostRun(launches.find((l) => l.id === launchID));
    await page.locator(".section-title .badge", { hasText: "running" }).waitFor({ timeout: 10000 });
    await page.getByRole("status").filter({ hasText: "Launch is now running." }).waitFor({ state: "attached" });
    const resumed = streamRequests.slice(before).filter((r) => r.id === launchID && r.after > 0);
    assert.ok(resumed.length > 0, "the stream reconnected with after > 0");
    assert.equal(resumed[0].lastEventID, String(resumed[0].after));
    await text("Updates: Live").waitFor();
    const logView = page.getByRole("log", { name: "Agent output" });
    await logView.getByText("agent started <img src=x onerror=alert(1)>").waitFor({ timeout: 10000 });
    assert.equal(await logView.locator("img").count(), 0, "log text never becomes markup");
    await logView.getByText("\\x1b[31mred\\x1b[0m \\u202eevil").waitFor();
    await page.getByLabel("Search the output").fill("stderr");
    assert.equal(await logView.locator(".log-line").count(), 1);
    await page.getByLabel("Search the output").fill("");
    await page.getByRole("button", { name: "Pause" }).click();
    await page.getByRole("button", { name: "Follow" }).waitFor();
    await page.getByRole("button", { name: "Follow" }).click();
    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: "Download" }).click();
    const file = await (await download).path();
    assert.ok((await readFile(file, "utf8")).includes("stderr warning \\x1b[31mred"));
  });

  await step("SSE failures fall back to polling and still deliver events", async () => {
    streamMode = "fail";
    await text("Live updates are unavailable; checking every 5 s.").waitFor({ timeout: 25000 });
    progress(launches.find((l) => l.id === launchID), "progress", "QA progress while the stream is down");
    await text("QA progress while the stream is down").waitFor({ timeout: 10000 });
    assert.ok(requests.some((r) => r.path === `launches/${launchID}/events` && !r.headers.accept?.includes("text/event-stream") && r.url.includes("after=")));
    streamMode = "ok";
  });

  await step("stop with confirmation, pending state, receipt and evidence", async () => {
    await go(`launches/${launchID}`, "alice");
    await page.getByRole("button", { name: "Stop" }).click();
    await page.locator("dialog").getByRole("textbox", { name: "Reason", exact: true }).fill("Done");
    await page.getByRole("button", { name: "Stop launch" }).click();
    await page.locator(".section-title .badge", { hasText: "stopping" }).waitFor();
    await text("Stop requested at").waitFor();
    assert.equal(await page.getByRole("button", { name: "Stopping…" }).isDisabled(), true);
    hostFinish(launches.find((l) => l.id === launchID));
    await page.locator(".section-title .badge", { hasText: "stopped" }).waitFor({ timeout: 10000 });
    await page.getByRole("heading", { name: "Evidence receipt" }).waitFor();
    await page.getByRole("cell", { name: "open_read" }).waitFor();
    await text("/etc/shadow").waitFor();
    await text("api.model.example").waitFor();
    await text("Output truncated.").waitFor({ timeout: 10000 });
    await text("matches the launch").waitFor();
    await checkLabels("launch detail");
    await page.screenshot({ path: `${output}/launch-detail-desktop.png`, fullPage: true });
    await noHorizontalScroll("launch-detail");
  });

  await step("a terminal launch without evidence shows evidence_missing", async () => {
    await go("launch", "alice");
    await page.getByLabel("Launch name").fill("short-lived");
    await pick("Target").selectOption("build-host");
    await page.getByLabel("Image (immutable digest)").fill("agentgate-coding@sha256:" + "b".repeat(64));
    await pick("Profile").selectOption("python-dev");
    await pick("Version").selectOption("2");
    await page.getByRole("button", { name: "Review & plan" }).click();
    await page.getByRole("button", { name: "Launch (waits for approval)" }).click();
    await page.getByRole("heading", { name: "State timeline" }).waitFor();
    await page.getByRole("button", { name: "Stop" }).click();
    await page.locator("dialog").getByRole("textbox", { name: "Reason", exact: true }).fill("Not needed");
    await page.getByRole("button", { name: "Stop launch" }).click();
    await page.locator(".section-title .badge", { hasText: "cancelled" }).waitFor();
    await text("Evidence missing: not_started").waitFor();
    await text("The launch never reached its host").waitFor();
  });

  await step("secret sealing: missing, substituted and forged keys are refused; a verified seal stores ciphertext only", async () => {
    await go("secrets", "alice");
    // Start without the pin made at key approval, to test first use.
    await page.evaluate(() => localStorage.removeItem("agentgate.known-targets.v1"));
    const open = async () => {
      await page.getByRole("button", { name: "Store a secret" }).click();
      const d = page.locator("dialog");
      await pick("Target", d).selectOption({ label: "build-host" });
      await d.getByLabel("Secret name").fill("model-api");
      await d.getByLabel(/Upstreams/).fill("api.model.example");
      await d.getByLabel("python-dev").check();
      await d.getByRole("textbox", { name: "Reason", exact: true }).fill("Model access for the coding agent");
      return d;
    };
    const posts = () => requests.filter((r) => r.path === "secrets" && r.method === "POST").length;
    let d = await open();
    await checkLabels("secret dialog");
    assert.equal(await d.getByLabel("Secret value").isDisabled(), true, "no value field before verification");
    sealMode = "missing";
    await d.getByRole("button", { name: "Verify seal key" }).click();
    await d.getByText("does not publish a signed seal key").waitFor();
    sealMode = "substituted";
    await d.getByRole("button", { name: "Verify seal key" }).click();
    await d.getByText("is not the key an administrator approved").waitFor();
    sealMode = "forged";
    await d.getByRole("button", { name: "Verify seal key" }).click();
    await d.getByText("not signed by the target's approved host key").waitFor();
    assert.equal(await d.getByLabel("Secret value").isDisabled(), true);
    assert.equal(posts(), 0, "nothing was sent for a key that failed verification");
    sealMode = "good";
    await d.getByRole("button", { name: "Verify seal key" }).click();
    await d.getByText("Verified signature from host key").waitFor();
    await d.getByRole("textbox", { name: "Fingerprint on the host", exact: true }).fill("SHA256:wrong");
    await d.getByText("No match. Do not seal a secret to this key.").waitFor();
    assert.equal(await d.getByLabel("Secret value").isDisabled(), true);
    await d.getByRole("textbox", { name: "Fingerprint on the host", exact: true }).fill(hostFingerprint(host.hostPub));
    await d.getByLabel("I read this fingerprint on the host itself.").check();
    await d.getByLabel("Secret value").fill("short");
    await d.getByRole("button", { name: "Seal in this browser and store" }).click();
    await d.getByText("8 to 8192 visible ASCII characters (no spaces or line breaks). Nothing was sealed").waitFor();
    assert.equal(await d.getByLabel("Secret value").inputValue(), "", "the field is cleared even when refused");
    assert.equal(posts(), 0);
    await d.getByLabel("Secret value").fill(value);
    await d.getByRole("button", { name: "Seal in this browser and store" }).click();
    await page.getByRole("heading", { name: "Secret stored" }).waitFor();
    await text("matches the envelope this browser sent").waitFor();
    assert.deepEqual(opened, [value], "the host side opened exactly the typed value");
    const post = requests.filter((r) => r.path === "secrets" && r.method === "POST").at(-1);
    const body = JSON.parse(post.body);
    assert.deepEqual(Object.keys(body).sort(), ["allowed_launchers", "allowed_profiles", "ciphertext", "header", "name", "reason", "target", "upstreams"]);
    assert.equal(JSON.parse(Buffer.from(body.ciphertext, "base64url")).format, "agentgate.secretseal.v1");
    await page.waitForTimeout(3500);
    await text("stored").waitFor();
    await page.getByRole("button", { name: "Done" }).click();
    // The browser pinned the host key; a service that rewrites the target's
    // approved fingerprint to its own key is refused by the pin.
    const t = findTarget("build-host");
    const real = t.host_key_id;
    t.host_key_id = hostKeyID(attacker.hostPub);
    sealMode = "substituted";
    d = await open();
    await d.getByLabel("Secret name").fill("model-api-2");
    await d.getByRole("button", { name: "Verify seal key" }).click();
    await d.getByText("differs from the one this browser pinned").waitFor();
    assert.equal(await d.getByLabel("Secret value").isDisabled(), true);
    t.host_key_id = real;
    sealMode = "good";
    await d.getByRole("button", { name: "Verify seal key" }).click();
    await d.getByText("Matches the fingerprint this browser pinned for build-host.").waitFor();
    await d.getByRole("button", { name: "Cancel" }).click();
    for (const r of requests) assert.ok(!r.url.includes(value) && !r.body.includes(value) && !JSON.stringify(r.headers).includes(value), "the value appears in a request");
    const stored = await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }) + document.documentElement.outerHTML);
    assert.ok(!stored.includes(value), "the value persists in storage or the DOM");
    assert.ok(stored.includes("agentgate.known-targets.v1"), "the browser pinned the host key");
    assert.ok(!consoleErrors.join("\n").includes(value));
    await page.getByRole("cell", { name: "model-api" }).first().waitFor();
  });

  await step("brokered secrets are picked by name and planned without values", async () => {
    await go(`launch/from/${launchID}`, "alice");
    await page.getByLabel("Launch name").waitFor();
    assert.equal(await page.getByLabel("Launch name").inputValue(), "repo-fixer");
    await page.getByLabel(/model-api/).check();
    await text("The agent never sees a secret value").waitFor();
    await page.getByRole("button", { name: "Review & plan" }).click();
    await page.locator(".plan").getByText("brokered secrets model-api").waitFor();
    await page.locator(".plan").getByRole("cell", { name: "MODEL_API_BASE_URL" }).waitFor();
    const planned = requests.filter((r) => r.path === "launch-plans").at(-1).body;
    assert.ok(!planned.includes(value));
    assert.deepEqual(JSON.parse(planned).secrets, [{ ref: "model-api", expose: { env: "MODEL_API_BASE_URL" } }]);
  });

  await step("import a spec strictly", async () => {
    await page.getByRole("button", { name: "Import spec JSON" }).click();
    const d = page.locator("dialog");
    await d.getByLabel("Spec JSON").fill(JSON.stringify({ version: "agentgate.launch.v1", name: "x", secrets: [{ ref: "a", expose: { env: "A" }, value: "nope" }] }));
    await d.getByRole("button", { name: "Load into the form" }).click();
    await d.getByText("a spec never carries a secret value").waitFor();
    await d.getByLabel("Spec JSON").fill('{"version":"agentgate.launch.v1","name":"imported","target":"build-host","mode":"oneshot","lifetime_seconds":60,"agent":{"image":"agentgate-coding@sha256:' + "c".repeat(64) + '","command":["true"]},"access":{"profile":"python-dev","version":2},"approval":"required"}');
    await d.getByRole("button", { name: "Load into the form" }).click();
    await page.locator("dialog").waitFor({ state: "detached" });
    assert.equal(await page.getByLabel("Launch name").inputValue(), "imported");
  });

  await step("API tokens are shown once and revocable", async () => {
    await go("tokens", "alice");
    await page.getByRole("button", { name: "Create token" }).click();
    const d = page.locator("dialog");
    await d.getByLabel("Token name").fill("laptop");
    await d.getByRole("textbox", { name: "Reason", exact: true }).fill("CLI on my laptop");
    await checkLabels("token dialog");
    await d.getByRole("button", { name: "Create token" }).click();
    const token = await page.getByRole("textbox", { name: "API token", exact: true }).inputValue();
    assert.match(token, /^agt_[A-Za-z0-9_-]{43}$/);
    await text("--token-stdin").waitFor();
    await page.getByRole("button", { name: "I stored the token" }).click();
    await page.locator("dialog").waitFor({ state: "detached" });
    assert.ok(!(await page.content()).includes(token));
    await page.getByRole("cell", { name: "laptop" }).waitFor();
    await page.getByRole("button", { name: "Revoke" }).click();
    await page.locator("dialog").getByRole("textbox", { name: "Reason", exact: true }).fill("Lost laptop");
    await page.getByRole("button", { name: "Revoke token" }).click();
    await text("revoked").waitFor();
  });

  await step("overview shows targets, launches by state and approvals waiting for this person", async () => {
    await go("launch", "alice");
    await page.getByLabel("Launch name").fill("needs-bob");
    await pick("Target").selectOption("build-host");
    await page.getByLabel("Image (immutable digest)").fill("agentgate-coding@sha256:" + "d".repeat(64));
    await pick("Profile").selectOption("python-dev");
    await pick("Version").selectOption("2");
    await page.getByRole("button", { name: "Review & plan" }).click();
    await page.getByRole("button", { name: "Launch (waits for approval)" }).click();
    await page.getByRole("heading", { name: "State timeline" }).waitFor();
    await go("overview", "bob");
    await text("Waiting for your approval").waitFor();
    await page.getByRole("button", { name: "Approve or reject needs-bob" }).waitFor();
    await text("Targets online").waitFor();
    await page.locator(".state-counts").getByText("stopped").waitFor();
    await page.screenshot({ path: `${output}/overview-desktop.png`, fullPage: true });
  });

  await step("a viewer sees disabled controls with reasons and no launch or secret pages", async () => {
    await go("targets", "vic");
    assert.equal(await page.getByRole("button", { name: "Add target" }).isDisabled(), true);
    await text("Only an administrator adds targets. Your roles: viewer.").waitFor();
    const nav = await page.getByRole("navigation", { name: "Main navigation" }).innerText();
    assert.ok(!nav.includes("Secrets") && !/\bLaunch\b(?!es)/.test(nav) && nav.includes("Launches") && nav.includes("Targets"));
    await page.getByRole("button", { name: "build-host" }).click();
    assert.equal(await page.getByRole("button", { name: "Retire" }).isDisabled(), true);
    await go("profiles", "vic");
    assert.equal(await page.getByRole("button", { name: "New profile" }).isDisabled(), true);
    await go("profiles/python-dev", "vic");
    await text("Granting or revoking access needs the editor role").waitFor();
    assert.equal(await page.getByRole("button", { name: "Let launchers start alone…" }).isDisabled(), true);
    await go(`launches/${launches.at(-1).id}`, "vic");
    for (const name of ["Approve", "Reject", "Stop"]) assert.equal(await page.getByRole("button", { name, exact: true }).isDisabled(), true, name);
    await text("Deciding launches needs the approver role").waitFor();
    await go("launch", "vic");
    await text("Launching needs the launcher role").waitFor();
    await go("secrets", "vic");
    await text("Secrets are managed by administrators").waitFor();
    assert.ok(!requests.some((r) => r.path === "secrets" && r.headers["x-csrf-token"] === undefined && r.method !== "GET"));
  });

  await step("session expiry returns to sign-in", async () => {
    await go("launches", "alice");
    expireSessionOnNextRead = true;
    // Any read now fails with session_expired; a background request may get
    // there before this filter change does.
    await pick("State").selectOption("running", { timeout: 2000 }).catch(() => {});
    await page.getByRole("heading", { name: "Sign in to policy control" }).waitFor({ timeout: 10000 });
    expireSessionOnNextRead = false;
  });

  await step("every write carried the CSRF token and an idempotency key", async () => {
    const writes = requests.filter((r) => r.method !== "GET");
    assert.ok(writes.length > 15);
    for (const w of writes) {
      assert.equal(w.headers["x-csrf-token"], "fixture-csrf", `${w.method} ${w.path}`);
      assert.ok(w.headers["idempotency-key"], `${w.method} ${w.path}`);
      assert.match(w.headers["content-type"] || "", /application\/json/);
    }
  });

  assert.deepEqual(pageErrors, []);
  assert.deepEqual(consoleErrors, []);
  report.status = "PASS";
} catch (error) {
  report.error = String(error?.stack || error);
  await page.screenshot({ path: `${output}/failure.png`, fullPage: true }).catch(() => {});
  process.exitCode = 1;
} finally {
  report.page_errors = pageErrors;
  report.console_errors = consoleErrors;
  report.unlabeled_inputs = a11y;
  report.stream_requests = streamRequests.length;
  await writeFile(`${output}/provisioning-report.json`, JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ status: report.status, steps: Object.keys(report.steps).length, error: report.error?.split("\n")[0] }));
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}
