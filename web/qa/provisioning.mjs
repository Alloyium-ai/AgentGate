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
import { hostFingerprint, hostKeyID, hostReceipt, makeRecord, newHost, openEnvelope, rfc3339 } from "./hpke-node.mjs";
import { loadTS } from "./load-ts.mjs";
import { shapeIssues } from "./api-shapes.mjs";

// The fixture's grant change list uses the UI's own diff; the unit tests
// check that diff against the real service's answers.
const { diffDocuments } = await loadTS("access-model");
const SS = await loadTS("secretseal");
// mockPolicyDigest is the service's view of a secret's policy digest (the
// settings as stored: the wildcard expanded, wildcard_rules set).
const mockPolicyDigest = (s) =>
  sha(
    Buffer.from(
      SS.canonicalPolicy(
        SS.newSecretPolicy({ upstreams: s.upstreams, header: s.header, scheme: s.scheme, username: s.username, rules: s.rules, extra_headers: s.extra_headers, forward_headers: s.forward_headers, wildcard: s.wildcard_rules }),
      ),
    ),
  );

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
// policyMode "substitute" is a compromised service that stores another
// upstream than the one the browser sealed and answers with it.
let policyMode = "honest";
let streamMode = "ok";
const streamRequests = [];
const logStreams = [];
const requests = [];
const served = [];
// Changed events the fixture's /api/v1/events sends on the browser's next
// (re)connect, each {id, resources}, as the real change stream sends them.
const changeFeed = [];
const opened = [];
const targets = [];
// Subjects an administrator linked as one person (internal/control prov_identity.go).
const identityLinks = [{ person: "4".repeat(32), subjects: ["local:alice", "oidc:alice"], linked_by: "local:alice", linked_at: new Date().toISOString() }];
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
      case "device":
        if (!fs.devices.includes(v[0])) fs.devices.push(v[0]);
        messages.push("device: added " + v[0]);
        break;
      case "revoke":
        if (e.kind === "read") fs.read_only = fs.read_only.filter((x) => x !== v[0]);
        if (e.kind === "device") fs.devices = fs.devices.filter((x) => x !== v[0]);
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
// brokerSettings applies the service's checks of a secret's broker
// settings (internal/control secretInjection) that the UI must explain.
const BROKER_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
let sealRotated = false;
function brokerSettings(input) {
  const out = {
    scheme: input.scheme || "",
    rules: [],
    wildcard_rules: false,
    extra_headers: { ...(input.extra_headers || {}) },
    forward_headers: (input.forward_headers || []).map((h) => h.toLowerCase()).sort(),
  };
  if (input.username) out.username = input.username;
  if (!out.scheme && input.header.toLowerCase() === "authorization") out.scheme = "Bearer";
  if (out.scheme && input.header.toLowerCase() !== "authorization") throw new Fail(422, "invalid_secret", "Broker injection settings: a scheme needs the Authorization header.");
  if (out.scheme === "Basic" && !/^[\x21-\x39\x3b-\x7e]{1,64}$/.test(input.username || "")) throw new Fail(422, "invalid_secret", "Broker injection settings: Basic needs a user name.");
  const rules = input.rules || [];
  if (rules.some((r) => r.methods.includes("*"))) {
    if (rules.length !== 1 || rules[0].methods.length !== 1 || rules[0].path !== "/" || (rules[0].match && rules[0].match !== "prefix"))
      throw new Fail(422, "invalid_secret", 'The wildcard is exactly one rule {"methods":["*"],"path":"/"}: every method on every path of the upstreams.');
    return { ...out, wildcard_rules: true, rules: [{ methods: BROKER_METHODS, path: "/", match: "prefix" }] };
  }
  for (const r of rules) {
    if (!["exact", "prefix"].includes(r.match)) throw new Fail(422, "invalid_secret", "Broker injection settings: a rule match is exact or prefix.");
    if (!r.methods.length || r.methods.some((m) => !BROKER_METHODS.includes(m))) throw new Fail(422, "invalid_secret", "Broker injection settings: a rule method is not allowed.");
  }
  for (const k of Object.keys(out.extra_headers)) if (["authorization", "x-api-key", "host", "cookie", input.header.toLowerCase()].includes(k.toLowerCase())) throw new Fail(422, "invalid_secret", "Broker injection settings: an extra header names a header the broker never injects.");
  out.rules = rules.map((r) => ({ methods: r.methods, path: r.path, match: r.match }));
  return out;
}
const BROKER = { address: "172.30.25.218", port: 8443, subnet: "172.30.25.216/29", target_address: "172.30.25.219" };
// hostproto.ProtectedMountTrees, for the fixture's mount root check.
const PROTECTED = ["/proc", "/sys", "/dev", "/run", "/var/run", "/etc", "/root", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
  "/var/lib/docker", "/var/lib/containerd", "/var/lib/cloud", "/var/lib/kubelet", "/snap", "/var/lib/agentgate", "/var/lib/containers", "/var/lib/rancher",
  "/var/lib/systemd", "/var/lib/private", "/var/lib/libvirt", "/var/lib/lxd", "/var/lib/incus", "/var/lib/sss", "/var/lib/polkit-1", "/var/lib/sudo",
  "/var/backups", "/var/log", "/var/mail", "/var/spool", "/lost+found"];
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
  else if (!p.approved_digest) reasons.push(`no version of profile ${p.name} is approved by an administrator for launches without approval`);
  else if (p.approved_digest !== v.digest) reasons.push(`profile ${p.name} version ${v.number} (digest ${v.digest.slice(0, 12)}) is not the administrator-approved version ${p.approved_version} (digest ${p.approved_digest.slice(0, 12)})`);
  if (spec.approval === "required") reasons.push("the spec requires approval");
  for (const m of spec.mounts) {
    if (!(target.mount_roots || []).some((r) => m.source === r || m.source.startsWith(r + "/")))
      throw new Fail(422, "mount_root_not_allowed", `Mount ${m.name}: ${m.source} is not inside a host folder target ${target.name} allows (mount roots: ${(target.mount_roots || []).join(", ") || "none"}). An administrator lists the folders launches may mount with POST /targets/{id}/mount-roots.`);
    if (target.host_mount_roots && !target.host_mount_roots.some((r) => m.source === r || m.source.startsWith(r + "/")))
      throw new Fail(422, "mount_root_not_on_host", `Mount ${m.name}: ${m.source} is not inside a host folder the host of target ${target.name} allows (its own mount roots: ${target.host_mount_roots.join(", ") || "none"}). The host's operator lists them on the host with agentgate-hostd mount-roots --root PATH; this service cannot change them.`);
    reasons.push((m.mode === "read-write" ? "read-write host folder " : m.mode === "snapshot" ? "snapshot of host folder " : "live host folder ") + m.name + " (" + m.source + ")");
  }
  const planned = [];
  for (const s of spec.secrets) {
    const sec = secrets.find((x) => x.target_id === target.id && x.name === s.ref && x.state === "stored");
    if (!sec) throw new Fail(422, "secret_unavailable", `Secret ${s.ref} is not stored on the launch target.`);
    if (!sec.rules?.length)
      throw new Fail(422, "secret_rules_missing", `Secret ${s.ref} has no broker rules, so it allows nothing (deny by default). Recreate it with explicit rules, or with the wildcard [{"methods":["*"],"path":"/"}] to allow every method and path of its upstreams.`);
    if (!sec.allowed_launchers.includes(actor)) throw new Fail(403, "secret_scope", "The secret is not scoped to this launcher.");
    const item = {
      ref: s.ref,
      secret_id: sec.id,
      env: s.expose.env,
      upstreams: sec.upstreams,
      header: sec.header,
      scheme: sec.scheme,
      rules: sec.rules,
      wildcard_rules: sec.wildcard_rules,
      extra_headers: sec.extra_headers,
      forward_headers: sec.forward_headers,
      policy_digest: sec.policy_digest,
      base_url: `http://${BROKER.address}:${BROKER.port}/${s.ref}`,
      value_fingerprint: sec.value_fingerprint,
    };
    if (sec.username) item.username = sec.username;
    planned.push(item);
    if (sec.wildcard_rules) reasons.push(`secret ${s.ref} has wildcard broker rules`);
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
      permissions: { network_default: "deny", ipv6: "deny", web: Object.keys(WEB).filter((n) => policy.web.rules.some((r) => r.protocol === WEB[n].protocol && r.port === WEB[n].port)), dns_resolvers: policy.dns.resolvers, taskboard: planned.length ? "" : "10.10.10.10:8080", ...(planned.length ? { broker: `${BROKER.address}:${BROKER.port}` } : {}), read_only: fs.read_only, writable: [fs.workspace, ...fs.scratch], execute: fs.execute, deny: fs.deny, devices: fs.devices, signals: policy.process.signals, anonymous_execute: false },
      mounts: spec.mounts.map((m) => ({ ...m, path: "/var/lib/agentgate/mounts/" + m.name })),
      secrets: planned,
      ...(planned.length ? { broker: BROKER } : {}),
      kernel_verified: false,
      notices: [
        ...planned.filter((x) => x.wildcard_rules).map((x) => `WARNING: secret ${x.ref} uses wildcard rules: the broker forwards every method on every path of ${x.upstreams.join(", ")} with the credential`),
        ...(planned.length ? [`the agent reaches its secrets only through the broker at ${BROKER.address}:${BROKER.port}; the taskboard TCP endpoint is not allowed in this launch`] : []),
        "kernel_verified is false: this enforcement has not been verified on a BPF LSM kernel",
      ],
    },
  };
}
const summary = (l) => {
  const { plan: _p, receipt: _r, spec: _s, policy: _y, ...rest } = l;
  return rest;
};
const sse = (list, after) => "event: ready\ndata: {}\n\n" + list.filter((e) => e.seq > after).map((e) => `id: ${e.seq}\nevent: ${e.kind}\ndata: ${JSON.stringify(e)}\n\n`).join("");

// The service's roots the host does not allow (internal/control Target.hostReport).
function hostRootsMismatch(t) {
  if (!t.host_mount_roots) return;
  const missing = (t.mount_roots || []).filter((r) => !t.host_mount_roots.some((h) => r === h || r.startsWith(h + "/")));
  if (missing.length) t.mount_roots_not_on_host = missing;
  else delete t.mount_roots_not_on_host;
}

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
      const t = { id: newID(), name: input.name, state: "pending", capabilities: [], hostname: "", agent_version: "", host_key_id: "", encryption_key: "", job_key_id: "", online: false, heartbeat_seconds: 10, created_at: now(), created_by: actors[who].subject, updated_at: now(), revision: 1, kernel_verified: false, mount_roots: [] };
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
      // GET /targets/{id}/seal-key as the service answers it; the record's
      // signer and the host key it sends vary with the attack being tested.
      const answer = (signer, recordHostPub, sealPub, sentHostPub) => {
        const record = makeRecord(signer, recordHostPub, sealPub, t.id, nb, na);
        return { target_id: t.id, host_key_id: hostKeyID(sentHostPub), host_public_key: sentHostPub.toString("base64url"), host_key_fingerprint: hostFingerprint(sentHostPub), seal_key_id: record.record.key_id, not_after: na, record };
      };
      if (sealMode === "good") return answer(host.signingKey, host.hostPub, host.sealPub, host.hostPub);
      if (sealMode === "substituted") return answer(attacker.signingKey, attacker.hostPub, attacker.sealPub, attacker.hostPub);
      if (sealMode === "forged") return answer(attacker.signingKey, attacker.hostPub, attacker.sealPub, host.hostPub);
    }
    if (method === "GET" && sub === "secrets") {
      need("launcher");
      if (t.state !== "active") throw new Fail(409, "target_unavailable", "The target is not enrolled and active.");
      const profile = query.get("profile") || "";
      const items = secrets
        .filter((x) => x.target_id === t.id && ["pending", "stored"].includes(x.state))
        .sort((a, b) => a.name.localeCompare(b.name))
        .map((x) => {
          const item = { name: x.name, state: x.state, upstreams: x.upstreams, rule_count: x.rules ? x.rules.length : 0, wildcard_rules: Boolean(x.wildcard_rules), launcher_allowed: x.allowed_launchers.includes(actors[who].subject), usable: false };
          if (profile) item.profile_allowed = x.allowed_profiles.includes(profile);
          if (x.state !== "stored") item.reason = `the host has not confirmed it yet (${x.state})`;
          else if (!item.rule_count) item.reason = "it has no broker rules, so no launch can use it (secret_rules_missing)";
          else if (!item.launcher_allowed) item.reason = "it is not scoped to you";
          else if (item.profile_allowed === false) item.reason = "it is not scoped to profile " + profile;
          else item.usable = true;
          return item;
        });
      return { target_id: t.id, target: t.name, ...(profile ? { profile } : {}), items };
    }
    if (method === "POST" && sub === "mount-roots") {
      need("admin");
      const roots = input.mount_roots;
      if (!Array.isArray(roots) || roots.length > 16 || new Set(roots).size !== roots.length || roots.some((r) => !/^\/[A-Za-z0-9._@+/-]+$/.test(r) || r === "/" || PROTECTED.some((p) => r === p || r.startsWith(p + "/") || p.startsWith(r + "/"))))
        throw new Fail(422, "invalid_mount_roots", "mount source must be a canonical absolute path of safe characters.");
      Object.assign(t, { mount_roots: roots, updated_at: now(), revision: t.revision + 1 });
      hostRootsMismatch(t);
      return t;
    }
    if (method === "POST" && sub === "approve-key") {
      need("admin");
      if (t.state !== "awaiting_key_approval") throw new Fail(409, "no_pending_key", "The target has no host key waiting for approval.");
      if (input.host_key_id !== t.host_key_id) throw new Fail(409, "fingerprint_mismatch", "The fingerprint differs from the key the host presented. Do not approve; issue a new token.");
      // As if the host polled once: its own mount roots and its clock.
      Object.assign(t, { state: "active", online: true, last_seen_at: now(), revision: t.revision + 1, host_mount_roots: ["/srv/repos/app"], host_clock_skew_ms: 1200, host_clock_measured_at: now() });
      hostRootsMismatch(t);
      return t;
    }
    if (method === "DELETE") {
      need("admin");
      if (launches.some((l) => l.target_id === t.id && !["stopped", "expired", "failed", "rejected", "cancelled"].includes(l.state))) throw new Fail(409, "launches_active", "Stop every launch on this target before retiring it.");
      const held = secrets.filter((x) => x.target_id === t.id && x.state !== "deleted");
      if (held.length && !input.force) {
        for (const x of held) x.state = "deleting";
        Object.assign(t, { state: "retiring", retiring_since: now() });
        return t;
      }
      for (const x of held) Object.assign(x, { state: "deleted", removal: "unconfirmed" });
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
      if (!p.require_approval) Object.assign(p, { approved_version: 1, approved_digest: versions[p.id][0].digest, approved_by: actors[who].subject, approved_at: now() });
      return { profile: p, version: versions[p.id][0] };
    }
    const p = findProfile(id);
    if (!p) throw new Fail(404, "not_found", "The profile does not exist.");
    const list = versions[p.id];
    if (method === "GET" && !sub) return p;
    if (method === "PATCH") {
      need("admin");
      if (input.require_approval) {
        p.require_approval = true;
        for (const k of ["approved_version", "approved_digest", "approved_by", "approved_at"]) delete p[k];
        return p;
      }
      const v = list.find((x) => x.number === input.version);
      if (!v || !/^[a-f0-9]{64}$/.test(input.digest || "")) throw new Fail(422, "approved_version_required", "Letting launchers start alone approves one reviewed version: give its number as version and its SHA-256 as digest.");
      if (v.digest !== input.digest) throw new Fail(409, "digest_mismatch", `Version ${v.number} has digest ${v.digest}, not the one you reviewed. Review the version again.`);
      Object.assign(p, { require_approval: false, approved_version: v.number, approved_digest: v.digest, approved_by: actors[who].subject, approved_at: now() });
      return p;
    }
    if (method === "GET" && sub === "versions" && !parts[3]) return { items: [...list].reverse() };
    if (method === "POST" && sub === "versions" && parts[4] === "grants") {
      need("editor");
      if (Number(parts[3]) !== p.latest_version) throw new Fail(409, "stale_parent", "Grants apply to the latest profile version only.");
      const parent = list.at(-1);
      const { d, messages, notices } = applyEdits(parent.document, input.edits);
      const digest = sha(JSON.stringify(d));
      const answer = { changed: digest !== parent.digest, from_version: parent.number, from_digest: parent.digest, digest, changes: diffDocuments(parent.document, d), messages, notices };
      if (input.dry_run) return { ...answer, dry_run: true, document: d };
      if (digest === parent.digest) return { ...answer, version: parent };
      const v = { id: newID(), profile_id: p.id, number: parent.number + 1, parent_id: parent.id, document: d, digest, edits: input.edits, actor: actors[who].subject, reason: input.reason, created_at: now() };
      list.push(v);
      p.latest_version = v.number;
      return { ...answer, version: v };
    }
  }
  if (area === "launch-plans") {
    const out = plan(input, actors[who].subject);
    return { dry_run: true, plan: out.plan, spec: input, policy: out.policy };
  }
  if (area === "launches") {
    if (method === "GET" && !id) {
      const terminal = ["stopped", "expired", "failed", "rejected", "cancelled"];
      const state = query.get("state") || "";
      const t = query.get("target") ? findTarget(query.get("target")) : undefined;
      if (query.get("target") && !t) throw new Fail(404, "not_found", "The target does not exist.");
      const name = query.get("name") || "";
      if (name && !/^[a-z0-9-]{1,40}$/.test(name)) throw new Fail(422, "invalid_filter", "name is 1 to 40 of a-z, 0-9 and -.");
      const requester = query.get("mine") === "true" ? actors[who].subject : query.get("requester") || "";
      const limit = Number(query.get("limit") || 100);
      const key = JSON.stringify([state, t?.id || "", name, requester]);
      let offset = 0;
      if (query.get("cursor")) {
        const c = JSON.parse(Buffer.from(query.get("cursor"), "base64url").toString());
        if (c.k !== key) throw new Fail(422, "invalid_cursor", "The cursor is not one this service issued for these filters; start again without it.");
        offset = c.o;
      }
      const all = launches
        .filter((l) => !state || (state === "active" ? !terminal.includes(l.state) : state === "ended" ? terminal.includes(l.state) : l.state === state))
        .filter((l) => (!t || l.target_id === t.id) && (!name || l.name.includes(name)) && (!requester || l.requested_by === requester))
        .map(summary)
        .reverse();
      const items = all.slice(offset, offset + limit);
      const page = { items, limit };
      if (offset + limit < all.length) page.next_cursor = Buffer.from(JSON.stringify({ k: key, o: offset + limit })).toString("base64url");
      return page;
    }
    if (method === "GET" && id === "summary") {
      const counts = Object.fromEntries(["requested", "approval_pending", "approved", "queued", "provisioning", "running", "stopping", "stopped", "expired", "failed", "rejected", "cancelled"].map((s) => [s, launches.filter((l) => l.state === s).length]));
      const terminal = ["stopped", "expired", "failed", "rejected", "cancelled"];
      const awaiting = can("approver") ? launches.filter((l) => l.state === "approval_pending" && l.requested_by !== actors[who].subject) : [];
      const soon = launches.filter((l) => !terminal.includes(l.state) && l.expires_at && new Date(l.expires_at).getTime() - Date.now() <= 1800000);
      return {
        counts,
        total: launches.length,
        active: launches.filter((l) => !terminal.includes(l.state)).length,
        awaiting_your_decision: { count: awaiting.length, items: awaiting.slice(0, 8).map(summary) },
        expiring_soon: { count: soon.length, window_seconds: 1800, items: soon.slice(0, 8).map(summary) },
      };
    }
    if (method === "POST" && !id) {
      const out = plan(input, actors[who].subject);
      const l = { id: newID(), name: input.name, spec_digest: out.plan.spec_digest, target_id: out.plan.target.id, policy_digest: out.plan.policy_digest, mode: input.mode, lifetime_seconds: input.lifetime_seconds, approval_required: out.plan.approval === "required", state: "requested", requested_by: actors[who].subject, kernel_verified: false, created_at: now(), updated_at: now(), revision: 1, profile_version_id: out.plan.profile.version_id, plan: { ...out.plan, expires_at: undefined }, spec: input, policy: out.policy };
      launches.push(l);
      events[l.id] = [{ seq: 1, time: now(), kind: "state", from_state: "", to_state: "requested", actor: l.requested_by, reason: "Launch requested", data: { spec_digest: l.spec_digest, policy_digest: l.policy_digest } }];
      logs[l.id] = [];
      transition(l, out.plan.approval === "required" ? "approval_pending" : "approved", l.requested_by, out.plan.approval === "required" ? "Approval required: " + out.plan.approval_reasons.join("; ") : "Automatic approval");
      // The plan of a created launch has no expiry yet: it starts when queued.
      const created = JSON.parse(JSON.stringify(l.plan));
      return { launch: { ...summary(l), plan: created }, plan: created };
    }
    const l = launches.find((x) => x.id === id);
    if (!l) throw new Fail(404, "not_found", "The launch does not exist.");
    if (method === "GET" && !sub) return { launch: l, jobs: [{ id: "job-" + l.id.slice(-6), type: "launch", target_id: l.target_id, launch_id: l.id, state: ["queued", "provisioning", "running", "stopping", "stopped"].includes(l.state) ? "delivered" : "queued", attempts: 1, created_at: l.created_at, deadline: new Date(Date.now() + 3600000).toISOString(), key_id: "ed25519:job", event_seq: events[l.id].length, spec_digest: l.spec_digest, policy_digest: l.policy_digest }] };
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
      const after = Number(query.get("after") || headers["last-event-id"] || 0);
      if ((headers.accept || "").includes("text/event-stream")) {
        logStreams.push({ id, after, lastEventID: headers["last-event-id"] });
        const body = logs[id].filter((x) => x.seq > after).map((x) => `id: ${x.seq}\nevent: log\ndata: ${JSON.stringify(x)}\n\n`).join("");
        const ended = ["stopped", "expired", "failed", "rejected", "cancelled"].includes(l.state);
        const truncated = logs[id].some((x) => x.text.includes("[output truncated"));
        return { __sse: `retry: 2000\nevent: ready\ndata: ${JSON.stringify({ after })}\n\n` + body + (ended ? `event: end\ndata: ${JSON.stringify({ state: l.state, last_seq: logs[id].at(-1)?.seq || 0, truncated })}\n\n` : "") };
      }
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
    if (method === "GET" && id && sub === "receipt") {
      const x = secrets.find((y) => y.id === id);
      if (!x) throw new Fail(404, "not_found", "The secret does not exist.");
      if (!x.receipt) throw new Fail(404, "receipt_unavailable", `The host has not returned a receipt for this secret (state ${x.state}).`);
      return { secret_id: x.id, target_id: x.target_id, name: x.name, state: x.state, ciphertext_sha256: x.ciphertext_sha256, value_fingerprint: x.value_fingerprint, receipt: x.receipt };
    }
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
      if (sealRotated) throw new Fail(409, "seal_key_changed", "The envelope is sealed to another seal key than the one the target publishes; fetch the seal key again and reseal.");
      const inject = brokerSettings(input);
      // The settings must be the policy the browser sealed (the host checks
      // the same and the HPKE associated data binds it).
      if (mockPolicyDigest({ ...inject, upstreams: input.upstreams, header: input.header }) !== envelope.policy_digest)
        throw new Fail(422, "policy_mismatch", `The broker settings (upstreams, header, scheme, username, extra headers, forward headers, rules) differ from the policy sealed in the envelope (${envelope.policy_digest}). Seal the value again for exactly these settings.`);
      const { plaintext, confirm } = openEnvelope(host.sealPrivate, envelope);
      opened.push(plaintext.toString());
      const s = {
        id: newID(),
        name: input.name,
        target_id: t.id,
        upstreams: policyMode === "substitute" ? ["collect.attacker.example"] : input.upstreams,
        header: input.header,
        ...inject,
        policy_digest: envelope.policy_digest,
        ciphertext_sha256: sha(raw),
        envelope: { format: envelope.format, key_id: envelope.key_id, version: envelope.version, nonce: envelope.nonce, policy_digest: envelope.policy_digest },
        allowed_profiles: input.allowed_profiles,
        allowed_launchers: input.allowed_launchers,
        state: "pending",
        created_at: now(),
        created_by: actors[who].subject,
        updated_at: now(),
        revision: 1,
      };
      secrets.push(s);
      // The host accepts the value; the service relays its receipt.
      setTimeout(() => Object.assign(s, { state: "stored", value_fingerprint: "sfp1_" + "ab".repeat(16), receipt: hostReceipt(envelope, confirm, "sfp1_" + "ab".repeat(16)) }), 1500);
      return s;
    }
  }
  if (area === "identity-links") {
    need("admin");
    if (method === "GET") return { items: identityLinks };
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
  if (path === "events") {
    const frames = changeFeed.splice(0);
    for (const data of frames) served.push({ method: "SSE", path, status: 200, event: "changed", body: data });
    const body = ": fixture\n\n" + frames.map((data) => `id: ${data.id}\nevent: changed\ndata: ${JSON.stringify(data)}\n\n`).join("");
    return route.fulfill({ contentType: "text/event-stream", body });
  }
  try {
    const value = api(req.method(), path, url.searchParams, input, headers);
    if (value && value.__sse !== undefined) {
      // Each frame's data, by event name, for the shape check.
      for (const frame of value.__sse.split("\n\n")) {
        const ev = /^event: (.*)$/m.exec(frame)?.[1];
        const data = /^data: (.*)$/m.exec(frame)?.[1];
        if (ev && data) served.push({ method: "SSE", path, status: 200, event: ev, body: JSON.parse(data) });
      }
      return route.fulfill({ status: 200, headers: { "Content-Type": "text/event-stream" }, body: value.__sse });
    }
    const body = JSON.stringify(value);
    served.push({ method: req.method(), path, status: 200, input, body: JSON.parse(body) });
    return route.fulfill({ status: 200, contentType: "application/json", body });
  } catch (e) {
    if (!(e instanceof Fail)) throw e;
    const body = { error: { code: e.code, message: e.message }, request_id: "qa-" + requests.length };
    served.push({ method: req.method(), path, status: e.status, input, body });
    return route.fulfill({ status: e.status, contentType: "application/json", body: JSON.stringify(body) });
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
    await text("none: every host folder mount is refused").waitFor();
    await text("/srv/repos/app").waitFor();
    await text("+1.2 s against the service").waitFor();
    await page.getByRole("button", { name: "Mount roots…" }).click();
    await page.getByLabel("Mount roots, one absolute path per line").fill("/srv/repos");
    await page.locator("dialog").getByRole("textbox", { name: "Reason", exact: true }).fill("Launches may mount the repositories");
    await page.getByRole("button", { name: "Save mount roots" }).click();
    await page.locator("dialog").waitFor({ state: "detached" });
    await text("/srv/repos", { exact: true }).waitFor();
    assert.deepEqual(JSON.parse(requests.filter((r) => r.path.endsWith("/mount-roots")).at(-1).body).mount_roots, ["/srv/repos"]);
    // The host allows only /srv/repos/app: the page names the mismatch and who can change it.
    await text("The host does not allow /srv/repos: launches there are refused at planning.", { exact: false }).waitFor();
  });

  await step("create a profile from a preset, preview a grant with the service's dry run, apply it, and see validator errors verbatim", async () => {
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
    await pick("Allow a device").selectOption("/dev/tty");
    await page.getByRole("button", { name: "Stage device" }).click();
    await text("Let the agent open the character device /dev/tty.").waitFor();
    await page.locator(".access-editor").getByRole("textbox", { name: "Reason", exact: true }).fill("Read the data set");
    await page.getByRole("button", { name: "Preview (dry run)" }).click();
    await text("Dry run: the service's result (nothing was stored)").waitFor();
    await page.locator(".preview").getByRole("cell", { name: "/srv/data" }).waitFor();
    await page.locator(".preview").getByText("read-only: added /srv/data").waitFor();
    await page.locator(".preview").getByText("Version 1 would become version 2.").waitFor();
    await page.locator(".preview").getByRole("cell", { name: "/dev/tty" }).waitFor();
    const preview = requests.filter((r) => r.path.endsWith("/grants")).at(-1);
    assert.equal(JSON.parse(preview.body).dry_run, true, "the preview asks the service for a dry run");
    assert.deepEqual(JSON.parse(preview.body).edits[1], { action: "device", values: ["/dev/tty"] });
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
    // Relaxing approval approves exactly the version on screen, with its digest.
    await page.getByRole("button", { name: "Let launchers start v1 alone…" }).click();
    await page.getByRole("dialog").getByText("Its digest (sent with the approval; a different one is refused)").waitFor();
    await page.getByRole("dialog").getByRole("textbox", { name: "Reason" }).fill("Reviewed version 1");
    await page.getByRole("button", { name: "Approve version 1" }).click();
    await text("A launcher may start version 1 alone").waitFor();
    const relaxed = JSON.parse(requests.filter((r) => r.method === "PATCH" && r.path === `profiles/${profiles[0].id}`).at(-1).body);
    assert.deepEqual([relaxed.require_approval, relaxed.version, relaxed.digest], [false, 1, versions[profiles[0].id][0].digest]);
    assert.equal(await page.getByRole("button", { name: "Let launchers start v1 alone…" }).isDisabled(), true, "the approved version is approved already");
    await page.getByRole("button", { name: "Require a second person…" }).click();
    await page.getByRole("dialog").getByRole("textbox", { name: "Reason" }).fill("Back to two people");
    await page.getByRole("button", { name: "Require approval" }).click();
    await text("Every launch of this profile waits for a second person").waitFor();
    assert.deepEqual(JSON.parse(requests.filter((r) => r.method === "PATCH").at(-1).body), { require_approval: true, reason: "Back to two people" });
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
    assert.ok(logStreams.some((s) => s.id === launchID), "the output is followed over the service's stream");
    assert.ok(!requests.some((r) => r.path === `launches/${launchID}/logs` && !(r.headers.accept || "").includes("text/event-stream")), "the output is not polled while it streams");

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
    await text("The launch ended; this is all of its output.").waitFor({ timeout: 10000 });
    const resumedLogs = logStreams.filter((s) => s.id === launchID && s.after > 0);
    assert.ok(resumedLogs.length > 0 && resumedLogs.every((s) => s.lastEventID === String(s.after)), "the output stream resumes after the last line with Last-Event-ID");
    await text("matches the launch").waitFor();
    await checkLabels("launch detail");
    await page.screenshot({ path: `${output}/launch-detail-desktop.png`, fullPage: true });
    await noHorizontalScroll("launch-detail");
  });

  await step("an idle tab on an ended launch sends nothing and reloads only what a change names", async () => {
    await go(`launches/${launchID}`, "alice");
    await page.locator(".section-title .badge", { hasText: "stopped" }).waitFor();
    await text("Ended; the timeline is complete").waitFor();
    const idleFrom = requests.length;
    await page.waitForTimeout(6000);
    // The fixture ends every /events response at once (the service keeps a
    // stream open five minutes), so the browser reconnects every few seconds
    // and checks its session once per reconnect; nothing else may load.
    const reconnects = requests.slice(idleFrom).filter((r) => r.path === "events").length;
    const checks = requests.slice(idleFrom).filter((r) => r.path === "session").length;
    assert.ok(checks <= reconnects, `${checks} session checks for ${reconnects} reconnects`);
    const idle = requests.slice(idleFrom).filter((r) => r.path !== "events" && r.path !== "session");
    assert.deepEqual(idle.map((r) => r.path), [], `an idle tab on an ended launch made requests: ${idle.map((r) => r.method + " " + r.url).join(", ")}`);
    // Changes naming other records do not reload this launch.
    const before = requests.length;
    changeFeed.push({ id: 900, resources: ["audit", `launch:${"f".repeat(32)}`] }, { id: 901, resources: ["secret:qa-secret"] });
    const reconnected = () => requests.slice(before).filter((r) => r.path === "events").length;
    for (let i = 0; i < 100 && (changeFeed.length || reconnected() < 2); i++) await page.waitForTimeout(100);
    await page.waitForTimeout(1000);
    assert.equal(requests.slice(before).filter((r) => r.path === `launches/${launchID}` || r.path === `launches/${launchID}/events`).length, 0, "a change naming another launch reloaded this one");
    // A change naming this launch reloads it, once.
    const named = requests.length;
    changeFeed.push({ id: 902, resources: ["audit", `launch:${launchID}`] });
    for (let i = 0; i < 100 && !requests.slice(named).some((r) => r.path === `launches/${launchID}`); i++) await page.waitForTimeout(100);
    await page.waitForTimeout(1000);
    assert.equal(requests.slice(named).filter((r) => r.path === `launches/${launchID}` && r.method === "GET").length, 1, "the named launch was not reloaded exactly once");
    report.idle_tab = { seconds: 6, requests: idle.length, change_stream_reconnects: requests.slice(idleFrom).filter((r) => r.path === "events").length };
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
    // Broker settings: deny by default, explicit rules, a non-secret header.
    await d.getByRole("button", { name: "Remove rule 1" }).click();
    await d.getByText("The broker forwards nothing by default").waitFor();
    await d.getByRole("button", { name: "Add a rule" }).click();
    await d.getByLabel("Methods", { exact: true }).fill("POST");
    await d.getByLabel("Path", { exact: true }).fill("/v1/messages");
    await pick("Match", d).selectOption("exact");
    await d.getByRole("button", { name: "Add an extra header" }).click();
    await d.getByLabel("Header name").fill("x-api-key");
    await d.getByLabel("Header value").fill("2023-06-01");
    await d.getByText("Extra header 1: a header name the broker may set").waitFor();
    await d.getByLabel("Header name").fill("anthropic-version");
    // The policy is shown before the value is sealed, with the digest the
    // envelope will carry.
    const review = d.locator("[data-policy-review]");
    await review.getByText("https://api.model.example:443").waitFor();
    await review.getByText("POST /v1/messages (exact)").waitFor();
    await review.getByText("anthropic-version: 2023-06-01").waitFor();
    const shownDigest = mockPolicyDigest({ upstreams: ["api.model.example"], header: "x-api-key", scheme: "", rules: [{ methods: ["POST"], path: "/v1/messages", match: "exact" }], extra_headers: { "anthropic-version": "2023-06-01" } });
    await review.getByText(shownDigest).waitFor();
    await d.getByLabel("Secret value").fill(value);
    await d.getByRole("button", { name: "Seal in this browser and store" }).click();
    await page.getByRole("heading", { name: "Secret stored" }).waitFor();
    await text("matches the envelope this browser sent").waitFor();
    await text(`The service recorded exactly the sealed policy ${shownDigest}.`).waitFor();
    assert.deepEqual(opened, [value], "the host side opened exactly the typed value");
    const post = requests.filter((r) => r.path === "secrets" && r.method === "POST").at(-1);
    const body = JSON.parse(post.body);
    assert.deepEqual(Object.keys(body).sort(), ["allowed_launchers", "allowed_profiles", "ciphertext", "extra_headers", "header", "name", "reason", "rules", "target", "upstreams"]);
    assert.deepEqual(body.rules, [{ methods: ["POST"], path: "/v1/messages", match: "exact" }]);
    assert.deepEqual(body.extra_headers, { "anthropic-version": "2023-06-01" });
    const sentEnvelope = JSON.parse(Buffer.from(body.ciphertext, "base64url"));
    assert.equal(sentEnvelope.format, "agentgate.secretseal.v2");
    assert.equal(sentEnvelope.policy_digest, shownDigest, "the envelope seals the policy the dialog showed");
    await text(`The host proved it opened exactly this envelope and stored it under the sealed policy ${shownDigest}. Value fingerprint sfp1_` + "ab".repeat(16)).waitFor({ timeout: 10000 });
    assert.ok(requests.some((r) => r.method === "GET" && /^secrets\/[0-9a-f]+\/receipt$/.test(r.path)), "the dialog reads the receipt from GET /secrets/{id}/receipt");
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

  await step("broker rules: the wildcard needs confirmation, Basic needs a user, and every refusal is explained", async () => {
    await go("secrets", "alice");
    await page.getByRole("button", { name: "Store a secret" }).click();
    const d = page.locator("dialog");
    await pick("Target", d).selectOption({ label: "build-host" });
    await d.getByLabel("Secret name").fill("wide-api");
    await d.getByLabel(/Upstreams/).fill("api.wide.example");
    await d.getByLabel("python-dev").check();
    await d.getByRole("textbox", { name: "Reason", exact: true }).fill("A key the agent may use fully");
    await d.getByRole("textbox", { name: "Header the broker sets" }).fill("Authorization");
    await pick("Scheme", d).selectOption("Basic");
    await d.getByText("The Basic scheme needs a user name").waitFor();
    await d.getByLabel("Basic user name").fill("agent");
    await d.getByLabel("Allow every method on every path (wildcard)").check();
    await d.getByText("with the wildcard the broker forwards every method on every path of api.wide.example").waitFor();
    await d.getByText("Confirm that the wildcard lets the broker forward every method").waitFor();
    await checkLabels("secret dialog with broker rules");
    await d.locator("fieldset").filter({ hasText: "Requests the broker may forward" }).screenshot({ path: `${output}/secret-broker-rules.png` });
    await d.getByLabel("I understand, and I want the wildcard for this secret.").check();
    await d.getByRole("button", { name: "Verify seal key" }).click();
    await d.getByText("Matches the fingerprint this browser pinned for build-host.").waitFor();
    // The host published a new seal key after the verification.
    sealRotated = true;
    await d.getByLabel("Secret value").fill(value);
    await d.getByRole("button", { name: "Seal in this browser and store" }).click();
    await d.getByText("The target published a new seal key after this browser verified it.").waitFor();
    assert.equal(await d.getByLabel("Secret value").isDisabled(), true, "a changed seal key needs a new verification");
    sealRotated = false;
    await d.getByRole("button", { name: "Verify seal key" }).click();
    await d.getByText("Matches the fingerprint this browser pinned for build-host.").waitFor();
    await d.getByLabel("Secret value").fill(value);
    await d.getByRole("button", { name: "Seal in this browser and store" }).click();
    await page.getByRole("heading", { name: "Secret stored" }).waitFor();
    const body = JSON.parse(requests.filter((r) => r.path === "secrets" && r.method === "POST").at(-1).body);
    assert.deepEqual(body.rules, [{ methods: ["*"], path: "/" }]);
    assert.equal(body.scheme, "Basic");
    assert.equal(body.username, "agent");
    assert.equal(body.extra_headers, undefined);
    await page.getByRole("button", { name: "Done" }).click();
    await text("Wildcard rules: every method on every path.").waitFor();
    // A secret stored without rules (an older client) is listed as unusable.
    const bare = { ...structuredClone(secrets.find((x) => x.name === "model-api")), id: newID(), name: "bare-key", rules: [], wildcard_rules: false, state: "stored" };
    bare.policy_digest = bare.envelope.policy_digest = mockPolicyDigest(bare);
    secrets.push(bare);
    await go("secrets", "alice");
    await text("No broker rules: no launch can use it (secret_rules_missing).").waitFor();
    await go(`launch/from/${launchID}`, "alice");
    await page.getByLabel("Launch name").waitFor();
    const spec = { ...structuredClone(launches.find((l) => l.id === launchID).spec), secrets: [{ ref: "bare-key", expose: { env: "BARE_BASE_URL" } }] };
    await page.getByRole("button", { name: "Import spec JSON" }).click();
    await page.locator("dialog").getByLabel("Spec JSON").fill(JSON.stringify(spec));
    await page.locator("dialog").getByRole("button", { name: "Load into the form" }).click();
    await page.locator("dialog").waitFor({ state: "detached" });
    await page.getByRole("button", { name: "Review & plan" }).click();
    await text("The secret was stored without broker rules, so the broker would forward nothing with it.").waitFor();
    secrets.splice(secrets.findIndex((x) => x.name === "bare-key"), 1);
  });

  await step("brokered secrets are picked by name and planned without values", async () => {
    await go(`launch/from/${launchID}`, "alice");
    await page.getByLabel("Launch name").waitFor();
    // The form fills from the launch's spec once it loads.
    for (let i = 0; i < 50 && (await page.getByLabel("Launch name").inputValue()) !== "repo-fixer"; i++) await page.waitForTimeout(100);
    assert.equal(await page.getByLabel("Launch name").inputValue(), "repo-fixer");
    await page.getByLabel(/model-api/).check();
    await text("The agent never sees a secret value").waitFor();
    assert.ok(requests.some((r) => r.method === "GET" && r.path === `targets/${findTarget("build-host").id}/secrets` && r.url.includes("profile=python-dev")), "the form lists the target's secrets for launchers");
    await page.getByRole("button", { name: "Review & plan" }).click();
    await page.locator(".plan").getByText("brokered secrets model-api").waitFor();
    await page.locator(".plan").getByText("MODEL_API_BASE_URL=http://172.30.25.218:8443/model-api").waitFor();
    await page.locator(".plan").getByText("172.30.25.218:8443").first().waitFor();
    await page.locator(".plan").getByText("POST /v1/messages").waitFor();
    await page.locator(".plan").getByText("also sets anthropic-version: 2023-06-01").waitFor();
    await page.locator(".plan h3", { hasText: "Brokered secrets" }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${output}/launch-plan-secrets.png` });
    await noHorizontalScroll("launch-plan-secrets");
    const planned = requests.filter((r) => r.path === "launch-plans").at(-1).body;
    assert.ok(!planned.includes(value));
    assert.deepEqual(JSON.parse(planned).secrets, [{ ref: "model-api", expose: { env: "MODEL_API_BASE_URL" } }]);
  });

  await step("an approver sees each secret's sealed policy and cannot approve a plan whose settings do not make it", async () => {
    // From the brokered plan of the previous step.
    const sec = secrets.find((x) => x.name === "model-api" && x.state === "stored");
    await page.locator(".plan").getByText("These settings make the policy digest the plan names. The host enforces the policy it sealed with the value.").waitFor();
    await page.locator(".plan").getByText(sec.policy_digest).waitFor();
    await page.getByRole("button", { name: "Launch (waits for approval)" }).click();
    await page.getByRole("heading", { name: "State timeline" }).waitFor();
    const id = page.url().split("/").at(-1);
    const l = launches.find((x) => x.id === id);
    // The service shows the approver other settings than the sealed policy.
    const honest = l.plan.secrets[0].upstreams;
    l.plan.secrets[0].upstreams = ["api.model.example", "collect.attacker.example"];
    await go(`launches/${id}`, "bob");
    await page.locator(".plan").getByText("These settings do not make the policy digest the plan names: do not approve.").waitFor();
    await text("do not make the policy digest the plan names: the plan contradicts itself. Reject the launch and report it.").waitFor();
    assert.equal(await page.getByRole("button", { name: "Approve", exact: true }).isDisabled(), true, "a plan that is not its sealed policy cannot be approved");
    l.plan.secrets[0].upstreams = honest;
    await go(`launches/${id}`, "bob");
    await page.locator(".plan").getByText("These settings make the policy digest the plan names. The host enforces the policy it sealed with the value.").waitFor();
    await page.getByRole("button", { name: "Approve", exact: true }).click();
    await page.locator("dialog").getByText(sec.policy_digest).waitFor();
    await page.locator("dialog").getByRole("button", { name: "Cancel" }).click();
    await page.getByRole("button", { name: "Reject", exact: true }).click();
    await page.locator("dialog").getByRole("textbox", { name: "Reason", exact: true }).fill("Checked the sealed policy display");
    await page.getByRole("button", { name: "Reject launch" }).click();
    await page.locator(".section-title .badge", { hasText: "rejected" }).waitFor();
  });

  await step("a service that records other settings than the sealed policy is caught", async () => {
    await go("secrets", "alice");
    await page.getByRole("button", { name: "Store a secret" }).click();
    const d = page.locator("dialog");
    await pick("Target", d).selectOption({ label: "build-host" });
    await d.getByLabel("Secret name").fill("redirect-api");
    await d.getByLabel(/Upstreams/).fill("api.model.example");
    await d.getByLabel("python-dev").check();
    await d.getByRole("textbox", { name: "Reason", exact: true }).fill("Model access for the coding agent");
    await d.getByLabel(/Request headers to forward/).fill("X-Request-Id");
    await d.locator("[data-policy-review]").getByText("x-request-id").waitFor();
    await d.getByRole("button", { name: "Verify seal key" }).click();
    await d.getByText("Matches the fingerprint this browser pinned for build-host.").waitFor();
    policyMode = "substitute";
    await d.getByLabel("Secret value").fill(value);
    await d.getByRole("button", { name: "Seal in this browser and store" }).click();
    await page.getByRole("heading", { name: "Secret stored" }).waitFor();
    await text("The service recorded other broker settings").waitFor();
    policyMode = "honest";
    const body = JSON.parse(requests.filter((r) => r.path === "secrets" && r.method === "POST").at(-1).body);
    assert.deepEqual(body.forward_headers, ["X-Request-Id"]);
    await page.getByRole("button", { name: "Done" }).click();
    await text("The settings shown differ from the policy sealed with the value: no launch can use it. Delete it.").waitFor();
    secrets.splice(secrets.findIndex((x) => x.name === "redirect-api"), 1);
    // Back to the launch form, where the next step imports a spec.
    await go(`launch/from/${launchID}`, "alice");
    await page.getByLabel("Launch name").waitFor();
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
    await text("Counts cover all").waitFor();
    assert.ok(requests.some((r) => r.method === "GET" && r.path === "launches/summary"), "the overview reads the service's summary");
    await page.screenshot({ path: `${output}/overview-desktop.png`, fullPage: true });
  });

  await step("the launch list is filtered and paged by the service", async () => {
    const t = findTarget("build-host");
    for (let i = 0; i < 30; i++) {
      const l = { id: newID(), name: `batch-${String(i).padStart(2, "0")}`, spec_digest: "e".repeat(64), target_id: t.id, profile_version_id: "d".repeat(32), policy_digest: "f".repeat(64), mode: "oneshot", lifetime_seconds: 60, approval_required: false, state: "stopped", requested_by: "local:bob", kernel_verified: false, created_at: new Date(Date.now() - 86400000 + i * 1000).toISOString(), updated_at: now(), revision: 4 };
      events[l.id] = [];
      logs[l.id] = [];
      launches.unshift(l);
    }
    await go("launches", "alice");
    const rows = page.locator("tbody tr");
    await rows.first().waitFor();
    assert.equal(await rows.count(), 25, "the first page holds 25 launches");
    await text("Page 1 · 25 of at most 25 per page").waitFor();
    await page.getByRole("button", { name: "Next" }).click();
    await text("Page 2").waitFor();
    const second = await rows.count();
    assert.ok(second > 0 && second <= 25);
    const paged = requests.filter((r) => r.method === "GET" && r.path === "launches" && r.url.includes("cursor="));
    assert.ok(paged.length > 0, "the next page is asked for with the service's cursor");
    await page.getByRole("button", { name: "Previous" }).click();
    await text("Page 1 ·").waitFor();
    await page.getByLabel("Name contains").fill("batch-1");
    await page.getByRole("button", { name: "batch-19" }).waitFor();
    for (let i = 0; i < 50 && (await rows.count()) !== 10; i++) await page.waitForTimeout(100);
    assert.equal(await rows.count(), 10, "the service filters by name");
    await page.getByLabel("Only mine").check();
    await text("No launches match").waitFor();
    const last = new URL(requests.filter((r) => r.method === "GET" && r.path === "launches").at(-1).url);
    assert.equal(last.searchParams.get("mine"), "true");
    assert.equal(last.searchParams.get("name"), "batch-1");
    await page.getByLabel("Name contains").fill("Batch 1");
    await text("A name filter is 1 to 40 of a-z, 0-9 and -.").waitFor();
    await page.getByLabel("Only mine").uncheck();
    await page.getByLabel("Name contains").fill("");
    await pick("State").selectOption("active");
    await page.getByRole("button", { name: "needs-bob" }).waitFor();
    assert.equal(new URL(requests.filter((r) => r.method === "GET" && r.path === "launches").at(-1).url).searchParams.get("state"), "active");
    await noHorizontalScroll("launches");
  });

  await step("an administrator lists linked identities; nobody else has the page", async () => {
    await go("identities", "alice");
    await page.getByRole("cell", { name: "local:alice, oidc:alice" }).waitFor();
    await text("agentgate identity link SUBJECT SUBJECT").waitFor();
    await go("identities", "vic");
    await text("Only an administrator sees linked identities. Your roles: viewer.").waitFor();
    const nav = await page.getByRole("navigation", { name: "Main navigation" }).innerText();
    assert.ok(!nav.includes("Linked identities"), "a viewer's navigation offers linked identities");
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
    assert.equal(await page.getByRole("button", { name: /Let launchers start v\d+ alone…/ }).isDisabled(), true);
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

  await step("retiring a target waits for its host to remove the secrets, or is forced", async () => {
    const spare = { ...structuredClone(findTarget("build-host")), id: newID(), name: "spare-host" };
    targets.push(spare);
    secrets.push({ ...structuredClone(secrets[0]), id: newID(), name: "spare-key", target_id: spare.id, state: "stored" });
    await go(`targets/${spare.id}`, "alice");
    await page.getByRole("button", { name: "Retire", exact: true }).click();
    const d = page.locator("dialog");
    await d.getByText("the target is retiring").waitFor();
    await d.getByRole("textbox", { name: "Reason", exact: true }).fill("Decommission the spare host");
    await d.getByLabel(/Type spare-host/).fill("spare-host");
    await d.getByRole("button", { name: "Retire target" }).click();
    await page.locator("dialog").waitFor({ state: "detached" });
    await page.locator(".section-title .badge", { hasText: "Retiring: removing secrets" }).waitFor();
    await text("waiting for the host to confirm the removal of its secrets").waitFor();
    assert.equal(JSON.parse(requests.filter((r) => r.method === "DELETE").at(-1).body).force, undefined);
    await page.getByRole("button", { name: "Retire without the host's confirmation…" }).click();
    await d.getByText("removal unconfirmed").waitFor();
    await d.getByRole("textbox", { name: "Reason", exact: true }).fill("The spare host is gone");
    await d.getByLabel(/Type spare-host/).fill("spare-host");
    await d.getByRole("button", { name: "Retire and leave the values on the host" }).click();
    await page.locator("dialog").waitFor({ state: "detached" });
    await page.locator(".section-title .badge", { hasText: "retired" }).waitFor();
    assert.equal(JSON.parse(requests.filter((r) => r.method === "DELETE").at(-1).body).force, true);
    await go("secrets", "alice");
    await page.getByLabel("Show deleted").check();
    await text("Removal unconfirmed: the value may remain on the retired host.").waitFor();
  });

  await step("the fixture answers with the real service's shapes", async () => {
    const real = async (name) => JSON.parse(await readFile(new URL(`./fixtures/api/${name}`, import.meta.url), "utf8"));
    const errors = Object.values(await real("errors.json")).map((e) => e.body);
    const ok = (method, re) => (r) => r.status === 200 && r.method === method && re.test(r.path);
    const checks = [
      ["GET targets", ok("GET", /^targets$/), [await real("targets.json")]],
      [
        "GET targets/{id}",
        ok("GET", /^targets\/[0-9a-f]+$/),
        await Promise.all(["target.json", "target-new.json", "target-awaiting.json", "target-unpolled.json", "target-retiring.json"].map(real)),
      ],
      ["POST targets", ok("POST", /^targets$/), [await real("target-created.json")]],
      ["GET targets/{id}/seal-key", ok("GET", /^targets\/[0-9a-f]+\/seal-key$/), [await real("seal-key.json")]],
      ["GET targets/{id}/secrets", ok("GET", /^targets\/[0-9a-f]+\/secrets$/), [await real("target-secrets.json")]],
      ["POST secrets", ok("POST", /^secrets$/), [(await real("secret-created.json")).response, (await real("secret-wildcard.json")).response]],
      ["GET secrets", ok("GET", /^secrets$/), [await real("secrets.json")]],
      ["GET secrets/{id}/receipt", ok("GET", /^secrets\/[0-9a-f]+\/receipt$/), [await real("secret-receipt.json")]],
      ["POST launch-plans", ok("POST", /^launch-plans$/), [(await real("launch-plan.json")).response, (await real("launch-plan-plain.json")).response]],
      ["POST launches", ok("POST", /^launches$/), [await real("launch-created.json"), await real("launch-created-plain.json")]],
      ["GET launches/{id}", ok("GET", /^launches\/[0-9a-f]+$/), await Promise.all(["launch-detail.json", "launch-detail-pending.json", "launch-detail-stopped.json"].map(real))],
      ["GET launches", ok("GET", /^launches$/), [await real("launches-page.json"), await real("launches-all.json")]],
      ["GET identity-links", ok("GET", /^identity-links$/), [await real("identity-links.json")]],
      ["GET launches/summary", ok("GET", /^launches\/summary$/), [await real("launches-summary.json")]],
      ["GET launches/{id}/logs (stream: ready)", (r) => r.method === "SSE" && /\/logs$/.test(r.path) && r.event === "ready", [(await real("launch-log-stream.json")).ready]],
      ["GET launches/{id}/logs (stream: log)", (r) => r.method === "SSE" && /\/logs$/.test(r.path) && r.event === "log", [(await real("launch-log-stream.json")).log, ...(await real("launch-logs.json")).items]],
      ["GET launches/{id}/logs (stream: end)", (r) => r.method === "SSE" && /\/logs$/.test(r.path) && r.event === "end", [(await real("launch-log-stream.json")).end]],
      ["GET events (stream: changed)", (r) => r.method === "SSE" && r.path === "events" && r.event === "changed", [await real("change-event.json")]],
      ["POST grants (dry run)", (r) => ok("POST", /\/grants$/)(r) && r.input?.dry_run, [(await real("grant-dry-run.json")).response]],
      ["POST grants", (r) => ok("POST", /\/grants$/)(r) && !r.input?.dry_run, [(await real("grant-applied.json")).response]],
      ["errors", (r) => r.status >= 400, errors],
    ];
    const options = {
      maps: [".extra_headers", ".items[].extra_headers", ".plan.secrets[].extra_headers", ".launch.plan.secrets[].extra_headers", ".counts", ".launch.receipt.bpf_objects", ".launch.receipt.broker_counts"],
      // The spec is the client's own document, echoed.
      skip: [".spec", ".launch.spec"],
      // Fields the service omits when empty, in states the samples do not
      // all cover.
      // Sent only in states the recorded samples do not reach: removal after a
      // forced retirement, evidence_missing after a launch ended without a
      // receipt, the receipt's evidence blocks from a real host.
      optional: [".items[].removal", ".launch.evidence_missing", ".items[].evidence_missing", ".launch.receipt.network_evidence", ".launch.receipt.host_control_evidence", ".next_cursor", ".profile", ".items[].profile_allowed"],
    };
    const found = {};
    for (const [name, match, samples] of checks) {
      const answers = served.filter(match);
      assert.ok(answers.length, `the QA never exercised ${name}`);
      const issues = [...new Set(answers.flatMap((a) => shapeIssues(a.body, samples, options)))];
      found[name] = { answers: answers.length, issues };
    }
    report.shapes = found;
    const bad = Object.entries(found).filter(([, v]) => v.issues.length);
    assert.deepEqual(bad, [], "the fixture's answers differ from the real service's");
    // The UI's secret request has only fields the real request has.
    const sent = requests.filter((r) => r.path === "secrets" && r.method === "POST").map((r) => JSON.parse(r.body));
    const reqs = [(await real("secret-created.json")).request, (await real("secret-wildcard.json")).request];
    for (const b of sent) assert.deepEqual(shapeIssues(b, reqs, { required: false, maps: [".extra_headers"] }), []);
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
