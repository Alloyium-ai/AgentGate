// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Pure helpers that explain an agentgate.poc.v2 access document in plain
// language, compare two versions, and describe typed grant edits before
// they are sent. They read documents; internal/access decides every edit.

import type { GrantEdit, PolicyDocument } from "./prov-api";

export type Risk = "low" | "medium" | "high" | "protective";
export type Row = { area: string; permission: string; value: string; meaning: string; risk: Risk };
export type DiffRow = { area: string; field: string; change: "added" | "removed" | "changed"; before?: string; after?: string };

export const MOUNT_ROOT = "/var/lib/agentgate/mounts";
export const SIGNALS = ["SIGHUP", "SIGINT", "SIGQUIT", "SIGKILL", "SIGUSR1", "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGWINCH"];
const WEB: Record<string, { protocol: string; port: number; label: string }> = {
  http: { protocol: "tcp", port: 80, label: "HTTP (TCP 80)" },
  https: { protocol: "tcp", port: 443, label: "HTTPS (TCP 443)" },
  quic: { protocol: "udp", port: 443, label: "QUIC / HTTP/3 (UDP 443)" },
};
export const WEB_PROTOCOLS = Object.keys(WEB);

// The plain-language meaning and risk of each kind of permission.
export const EXPLAIN = {
  web: {
    title: "Public web",
    plain: "The agent can connect to any public IPv4 address on this port. It is not limited to particular sites, so it can reach any website or API, including ones that could receive copied data.",
    risk: "high" as Risk,
  },
  noWeb: { title: "No public web", plain: "The agent cannot reach internet hosts.", risk: "low" as Risk },
  dns: {
    title: "DNS resolvers",
    plain: "The agent can send DNS queries to these resolvers (port 53, UDP and TCP). DNS lookups can carry small amounts of data out.",
    risk: "medium" as Risk,
  },
  taskboard: { title: "Task board", plain: "The agent can reach the AgentGate task board at this one address.", risk: "low" as Risk },
  defaultDeny: { title: "Everything else", plain: "Any connection or file not listed here is denied.", risk: "protective" as Risk },
  workspace: {
    title: "Workspace (write)",
    plain: "The agent can create, change and delete files in its workspace. It is always writable and never executable.",
    risk: "medium" as Risk,
  },
  write: {
    title: "Write",
    plain: "The agent can create, change and delete files here. Writable folders can never be executable.",
    risk: "medium" as Risk,
  },
  read: { title: "Read", plain: "The agent can read files here but cannot change them or run them.", risk: "low" as Risk },
  exec: {
    title: "Execute",
    plain: "The agent can run programs here. Writable folders can never be executable, so it cannot run code it wrote.",
    risk: "medium" as Risk,
  },
  devices: { title: "Devices", plain: "The agent can open these character devices.", risk: "low" as Risk },
  deny: { title: "Deny", plain: "Every operation is refused here, even inside a folder that is otherwise allowed.", risk: "protective" as Risk },
  mountRO: {
    title: "Host folder (read-only)",
    plain: "A folder from the host appears inside the agent. The agent can read it but not change it. Which host folder is bound is chosen at launch.",
    risk: "medium" as Risk,
  },
  mountRW: {
    title: "Host folder (read-write)",
    plain: "A folder from the host appears inside the agent and the agent can change real host files there. Changes stay after the launch ends. Never executable.",
    risk: "high" as Risk,
  },
  signals: {
    title: "Signals",
    plain: "Processes may send these signals within the agent's own process tree. Tracing other processes is always denied.",
    risk: "low" as Risk,
  },
  anonOn: {
    title: "Executable anonymous memory",
    plain: "ON: programs may generate and run code in memory (a JIT or libffi needs this). This weakens write-xor-execute protection.",
    risk: "high" as Risk,
  },
  anonOff: { title: "Executable anonymous memory", plain: "Off: code cannot be generated and run in memory (write-xor-execute holds).", risk: "protective" as Risk },
};

export function webOf(doc?: PolicyDocument): string[] {
  const rules = doc?.web?.rules || [];
  return WEB_PROTOCOLS.filter((n) => rules.some((r) => r.protocol === WEB[n].protocol && r.port === WEB[n].port));
}
export const webLabel = (n: string) => WEB[n]?.label || n;

export function mountsOf(doc?: PolicyDocument): { name: string; mode: "read-only" | "read-write"; path: string }[] {
  const fs = doc?.filesystem;
  if (!fs) return [];
  const out: { name: string; mode: "read-only" | "read-write"; path: string }[] = [];
  for (const p of fs.read_only || []) if (p.startsWith(MOUNT_ROOT + "/")) out.push({ name: p.slice(MOUNT_ROOT.length + 1), mode: "read-only", path: p });
  for (const p of fs.scratch || []) if (p.startsWith(MOUNT_ROOT + "/")) out.push({ name: p.slice(MOUNT_ROOT.length + 1), mode: "read-write", path: p });
  return out;
}
const notMount = (p: string) => !p.startsWith(MOUNT_ROOT + "/");

// rows is the "What can this agent do?" table for one document.
export function rows(doc: PolicyDocument): Row[] {
  const out: Row[] = [];
  const push = (area: string, e: { title: string; plain: string; risk: Risk }, value: string) => out.push({ area, permission: e.title, value, meaning: e.plain, risk: e.risk });
  const web = webOf(doc);
  if (web.length) for (const n of web) push("Network", EXPLAIN.web, `${webLabel(n)} to any public IPv4 address`);
  else push("Network", EXPLAIN.noWeb, "none");
  if (doc.dns?.resolvers?.length) push("Network", EXPLAIN.dns, doc.dns.resolvers.join(", "));
  if (doc.taskboard?.address) push("Network", EXPLAIN.taskboard, `${doc.taskboard.address}:${doc.taskboard.port}`);
  push("Network", EXPLAIN.defaultDeny, `default ${doc.default || "deny"}, IPv6 ${doc.ipv6 || "deny"}`);
  const fs = doc.filesystem;
  if (!fs) {
    out.push({ area: "Files", permission: "Not controlled", value: "version one document", meaning: "This version has no filesystem or process controls and cannot be launched. Add a version two document.", risk: "high" });
    return out;
  }
  push("Files", EXPLAIN.workspace, fs.workspace);
  for (const p of (fs.scratch || []).filter(notMount)) push("Files", EXPLAIN.write, p);
  for (const p of (fs.read_only || []).filter(notMount)) push("Files", EXPLAIN.read, p);
  for (const p of fs.execute || []) push("Files", EXPLAIN.exec, p);
  if (fs.devices?.length) push("Files", EXPLAIN.devices, fs.devices.join(", "));
  for (const p of fs.deny || []) push("Files", EXPLAIN.deny, p);
  for (const m of mountsOf(doc)) push("Mounts", m.mode === "read-write" ? EXPLAIN.mountRW : EXPLAIN.mountRO, `${m.name} at ${m.path}`);
  push("Processes", EXPLAIN.signals, doc.process?.signals?.length ? doc.process.signals.join(", ") : "none");
  push("Memory", fs.memory?.anonymous_execute ? EXPLAIN.anonOn : EXPLAIN.anonOff, fs.memory?.anonymous_execute ? "on" : "off");
  return out;
}

// sentences is the short plain-language summary above the table.
export function sentences(doc: PolicyDocument): string[] {
  const out: string[] = [];
  const web = webOf(doc);
  out.push(web.length ? `It can reach any public IPv4 address over ${web.map(webLabel).join(", ")}; this is not limited to particular sites.` : "It cannot reach the public internet.");
  if (doc.dns?.resolvers?.length) out.push(`It can look up names through ${doc.dns.resolvers.join(", ")}.`);
  const fs = doc.filesystem;
  if (!fs) {
    out.push("This version has no filesystem or process controls, so it cannot be used for a launch.");
    return out;
  }
  const writable = [fs.workspace, ...(fs.scratch || []).filter(notMount)];
  out.push(`It can change files only in ${writable.join(", ")}, and can never run programs from a writable folder.`);
  if (fs.execute?.length) out.push(`It can run programs from ${fs.execute.join(", ")}.`);
  const ro = (fs.read_only || []).filter(notMount);
  if (ro.length) out.push(`It can read ${ro.join(", ")} without changing them.`);
  if (fs.deny?.length) out.push(`It is refused everything in ${fs.deny.join(", ")}.`);
  const mounts = mountsOf(doc);
  if (mounts.length) out.push(`Host folders: ${mounts.map((m) => `${m.name} (${m.mode})`).join(", ")}. The launch chooses which host folder is bound.`);
  out.push(fs.memory?.anonymous_execute ? "It may generate and run code in memory (write-xor-execute is weakened)." : "It cannot generate and run code in memory.");
  out.push("Everything else is denied.");
  return out;
}

export function riskCount(doc: PolicyDocument) {
  return rows(doc).filter((r) => r.risk === "high").length;
}

// ---- diff -------------------------------------------------------------------

function listDiff(out: DiffRow[], area: string, field: string, a: string[] = [], b: string[] = []) {
  for (const v of b) if (!a.includes(v)) out.push({ area, field, change: "added", after: v });
  for (const v of a) if (!b.includes(v)) out.push({ area, field, change: "removed", before: v });
}
function scalarDiff(out: DiffRow[], area: string, field: string, a: unknown, b: unknown) {
  const s = (v: unknown) => (v === undefined || v === null ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v));
  if (s(a) !== s(b)) out.push({ area, field, change: "changed", before: s(a), after: s(b) });
}

// diffDocuments lists what changed from a to b in the same terms as rows.
export function diffDocuments(a: PolicyDocument | undefined, b: PolicyDocument): DiffRow[] {
  const out: DiffRow[] = [];
  scalarDiff(out, "Policy", "version", a?.version, b.version);
  scalarDiff(out, "Network", "default", a?.default, b.default);
  scalarDiff(out, "Network", "IPv6", a?.ipv6, b.ipv6);
  listDiff(out, "Network", "public web", webOf(a).map(webLabel), webOf(b).map(webLabel));
  listDiff(out, "Network", "DNS resolvers", a?.dns?.resolvers, b.dns?.resolvers);
  scalarDiff(out, "Network", "task board", a?.taskboard && `${a.taskboard.address}:${a.taskboard.port}`, b.taskboard && `${b.taskboard.address}:${b.taskboard.port}`);
  const fa = a?.filesystem;
  const fb = b.filesystem;
  scalarDiff(out, "Files", "workspace", fa?.workspace, fb?.workspace);
  listDiff(out, "Files", "write", fa?.scratch?.filter(notMount), fb?.scratch?.filter(notMount));
  listDiff(out, "Files", "read", fa?.read_only?.filter(notMount), fb?.read_only?.filter(notMount));
  listDiff(out, "Files", "execute", fa?.execute, fb?.execute);
  listDiff(out, "Files", "devices", fa?.devices, fb?.devices);
  listDiff(out, "Files", "deny", fa?.deny, fb?.deny);
  listDiff(out, "Mounts", "host folder", mountsOf(a).map((m) => `${m.name} (${m.mode})`), mountsOf(b).map((m) => `${m.name} (${m.mode})`));
  listDiff(out, "Processes", "signals", a?.process?.signals, b.process?.signals);
  scalarDiff(out, "Memory", "executable anonymous memory", fa ? (fa.memory?.anonymous_execute ? "on" : "off") : undefined, fb ? (fb.memory?.anonymous_execute ? "on" : "off") : undefined);
  return out;
}

// ---- typed edits -------------------------------------------------------------

export function describeEdit(e: GrantEdit): { text: string; risk: Risk } {
  const v = e.values || [];
  const one = v[0] || "";
  switch (e.action) {
    case "read":
      return { text: `Let the agent read ${one} (no changes, no running programs).`, risk: "low" };
    case "write":
      return { text: `Let the agent create, change and delete files in ${one}. Writable folders can never be executable.`, risk: "medium" };
    case "exec":
      return { text: `Let the agent run programs from ${one}. It must not overlap a writable folder.`, risk: "medium" };
    case "deny":
      return { text: `Refuse every operation in ${one}, even inside allowed folders.`, risk: "protective" };
    case "allow-web":
      return { text: `Allow public web ${(v.length ? v : ["all"]).join(", ")} to any public IPv4 address (not limited to particular sites).`, risk: "high" };
    case "deny-web":
      return { text: `Remove public web ${(v.length ? v : ["all"]).join(", ")}.`, risk: "protective" };
    case "dns":
      return { text: `Replace the DNS resolvers with ${v.join(", ")}.`, risk: "medium" };
    case "signal":
      return { text: `Allow the signals ${v.join(", ")} within the agent's own process tree.`, risk: "low" };
    case "anon-exec":
      return { text: "Turn on executable anonymous memory (a JIT needs it; weakens write-xor-execute).", risk: "high" };
    case "mount":
      return e.mode === "read-write"
        ? { text: `Add host folder ${one} at ${MOUNT_ROOT}/${one}, read-write: the agent can change real host files there (never executable).`, risk: "high" }
        : { text: `Add host folder ${one} at ${MOUNT_ROOT}/${one}, read-only.`, risk: "medium" };
    case "unmount":
      return { text: `Remove host folder ${one}.`, risk: "protective" };
    case "preset":
      return { text: `Replace the web, filesystem and process sections with the preset ${one}.`, risk: "medium" };
    case "revoke":
      switch (e.kind) {
        case "web":
          return { text: `Remove public web ${(v.length ? v : ["all"]).join(", ")}.`, risk: "protective" };
        case "anon-exec":
          return { text: "Turn off executable anonymous memory.", risk: "protective" };
        case "mount":
          return { text: `Remove host folder ${one}.`, risk: "protective" };
        case "dns":
          return { text: `Remove the DNS resolver ${v.join(", ")}.`, risk: "protective" };
        case "signal":
          return { text: `Remove the signals ${v.join(", ")}.`, risk: "protective" };
        case "deny":
          return { text: `Remove the deny entry ${one}; the folder becomes reachable again if an allowed folder covers it.`, risk: "medium" };
        default:
          return { text: `Remove ${e.kind} ${one}.`, risk: "protective" };
      }
  }
  return { text: `${e.action} ${v.join(" ")}`, risk: "medium" };
}

// containerPathIssue mirrors access.ContainerPath for early feedback.
export function containerPathIssue(value: string): string | undefined {
  if (!value.startsWith("/") || /[\0\n]/.test(value)) return "Use an absolute path inside the agent, such as /srv/data.";
  const stripped = value.replace(/\/+$/, "") || "/";
  const parts = stripped.split("/").slice(1);
  if (stripped === "/" || parts.some((p) => p === "" || p === "." || p === "..")) return "Use a canonical absolute path other than / (no ., .. or //).";
  if (new TextEncoder().encode(stripped).length > 160) return "A policy path is at most 160 bytes.";
  return undefined;
}

export function editIssue(e: GrantEdit): string | undefined {
  const v = e.values || [];
  switch (e.action) {
    case "read":
    case "write":
    case "exec":
    case "deny":
      return v.length !== 1 ? "Enter one path." : containerPathIssue(v[0]);
    case "dns":
      if (v.length < 1 || v.length > 3) return "Enter one to three IPv4 resolvers.";
      return v.find((ip) => !/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(ip)) ? "A resolver is a public IPv4 address such as 1.1.1.1." : undefined;
    case "signal":
      return v.length < 1 || v.some((s) => !SIGNALS.includes(s.toUpperCase().startsWith("SIG") ? s.toUpperCase() : "SIG" + s.toUpperCase())) ? `Choose signals from ${SIGNALS.join(", ")}.` : undefined;
    case "mount":
    case "unmount":
      return v.length !== 1 || !/^[a-z0-9][a-z0-9_-]{0,31}$/.test(v[0]) ? "A host folder name is 1 to 32 of a-z 0-9 _ -, starting with a letter or digit." : undefined;
  }
  return undefined;
}
