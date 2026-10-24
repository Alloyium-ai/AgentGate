// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Pure helpers for agentgate.launch.v1: build a spec from the guided form,
// check it with the same rules as internal/control/prov_launchspec.go so the
// operator sees problems early, import a spec strictly, and print the CLI
// commands that send the same document. The service validates every spec
// again; these checks never replace that.

export const SPEC_VERSION = "agentgate.launch.v1";
export const NAME_PATTERN = /^[a-z0-9][a-z0-9-]{0,39}$/;
export const MOUNT_NAME_PATTERN = /^[a-z0-9][a-z0-9_-]{0,31}$/;
export const IMAGE_PATTERN = /^[a-z0-9][a-z0-9._/-]{0,199}(:[A-Za-z0-9._-]{1,64})?@sha256:[a-f0-9]{64}$/;
export const BIND_SOURCE_PATTERN = /^\/[A-Za-z0-9._@+/-]+$/;
export const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
// The source text of secretEnvPattern and reservedEnvPattern in
// internal/control/prov_launchspec.go, without Go's (?i) prefix. The unit
// tests read the Go file and fail if they drift.
export const SECRET_ENV_SOURCE =
  "(^(KEY|TOKEN|SECRET|PAT)$|_(KEY|PAT|AUTH)$|PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY|CREDENTIAL|AUTHORIZATION|COOKIE)";
export const RESERVED_ENV_SOURCE = "^(LD_|AGENTGATE_|DYLD_)";
const SECRET_ENV = new RegExp(SECRET_ENV_SOURCE, "i");
const RESERVED_ENV = new RegExp(RESERVED_ENV_SOURCE, "i");
// ProtectedMountTrees and secretComponents in internal/hostproto/jobs.go.
export const PROTECTED_MOUNT_TREES = [
  "/proc", "/sys", "/dev", "/run", "/var/run", "/etc", "/root", "/boot", "/usr", "/bin",
  "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/var/lib/docker", "/var/lib/containerd",
  "/var/lib/cloud", "/var/lib/kubelet", "/snap", "/var/lib/agentgate",
];
export const CREDENTIAL_COMPONENTS = [
  ".ssh", ".gnupg", ".aws", ".azure", ".config", ".docker", ".kube", ".netrc",
  ".git-credentials", ".password-store", ".vault-token", ".local",
];
export const LIFETIME = {
  oneshot: { min: 1, max: 3600 },
  session: { min: 60, max: 86400 },
} as const;
export const DEFAULT_WORKDIR = "/var/lib/agentgate/workspace";
export const MOUNT_ROOT = "/var/lib/agentgate/mounts";
export const LIMITS = {
  commandArgs: 128,
  commandBytes: 32 << 10,
  argBytes: 4096,
  envEntries: 64,
  envBytes: 32 << 10,
  envValueBytes: 4096,
  mounts: 8,
  secrets: 8,
  specBytes: 64 << 10,
  workdirBytes: 160,
};

export type Mode = "oneshot" | "session";
export type MountMode = "read-only" | "snapshot" | "read-write";
export type LaunchForm = {
  name: string;
  target: string;
  mode: Mode;
  lifetime_seconds: number;
  image: string;
  command: string[];
  workdir: string;
  env: { name: string; value: string }[];
  access: { kind: "profile"; profile: string; version: number } | { kind: "inline"; document: string };
  mounts: { name: string; source: string; mode: MountMode }[];
  secrets: { ref: string; env: string }[];
  approval: "auto" | "required";
};
export type LaunchSpec = {
  version: string;
  name: string;
  target: string;
  mode: Mode;
  lifetime_seconds: number;
  agent: { image: string; command: string[]; env: Record<string, string>; workdir?: string };
  access: { profile: string; version: number } | { inline: unknown };
  mounts: { name: string; source: string; mode: MountMode }[];
  secrets: { ref: string; expose: { env: string } }[];
  approval: "auto" | "required";
};
export type Issue = { field: string; message: string };

export function emptyForm(): LaunchForm {
  return {
    name: "",
    target: "",
    mode: "session",
    lifetime_seconds: 3600,
    image: "",
    command: [],
    workdir: "",
    env: [],
    access: { kind: "profile", profile: "", version: 0 },
    mounts: [],
    secrets: [],
    approval: "auto",
  };
}

const bytes = (s: string) => new TextEncoder().encode(s).length;
const within = (parent: string, child: string) => child === parent || child.startsWith(parent + "/");
const overlaps = (a: string, b: string) => within(b, a) || within(a, b);

// cleanPath is Go's path.Clean for absolute paths.
export function cleanPath(p: string): string {
  const out: string[] = [];
  for (const part of p.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") out.pop();
    else out.push(part);
  }
  return "/" + out.join("/");
}

// secretLikeEnv is SecretLikeEnv: a variable name that looks like it holds a
// credential. Such names are refused in agent.env; secrets arrive only through
// the broker.
export const secretLikeEnv = (name: string) => SECRET_ENV.test(name);
export const reservedEnv = (name: string) => RESERVED_ENV.test(name);

export function envNameIssue(name: string): string | undefined {
  if (!ENV_NAME_PATTERN.test(name)) return `${name || "(empty)"} is not a valid variable name (letters, digits and _; not starting with a digit).`;
  if (secretLikeEnv(name)) return `${name} looks like a credential. Put secrets in the brokered secrets list; the agent then sees only the broker address.`;
  if (reservedEnv(name)) return `${name} is reserved (LD_*, DYLD_* and AGENTGATE_* control how programs load or belong to the runtime).`;
  return undefined;
}

// mountSourceIssue applies hostproto.CheckMountSource. The host applies its
// own home-directory and filesystem checks on top.
export function mountSourceIssue(source: string): string | undefined {
  if (source.length > 4096 || !BIND_SOURCE_PATTERN.test(source) || cleanPath(source) !== source || source === "/")
    return "Use a canonical absolute path of letters, digits and . _ @ + - / (no trailing /, no . or ..).";
  const tree = PROTECTED_MOUNT_TREES.find((p) => overlaps(source, p));
  if (tree) return `The folder overlaps the protected host tree ${tree}.`;
  if (source.startsWith("/var/lib/agentgate-")) return "The folder overlaps an AgentGate instance directory.";
  const parts = source.slice(1).split("/");
  const store = parts.find((p) => CREDENTIAL_COMPONENTS.includes(p));
  if (store) return `The folder passes through the credential store ${store}.`;
  if (parts[0] === "home" && parts.length <= 2) return "The folder is a home directory or contains one; choose a project folder inside it.";
  return undefined;
}

export function lifetimeIssue(mode: Mode, seconds: number): string | undefined {
  const b = LIFETIME[mode];
  if (!Number.isInteger(seconds) || seconds < b.min || seconds > b.max)
    return mode === "oneshot" ? "A one-shot lifetime is 1 to 3600 seconds (one hour)." : "A session lifetime is 60 seconds to 86400 seconds (24 hours).";
  return undefined;
}

// buildSpec turns the form into a spec and lists every rule it breaks.
export function buildSpec(form: LaunchForm): { spec: LaunchSpec; issues: Issue[] } {
  const issues: Issue[] = [];
  const add = (field: string, message: string) => issues.push({ field, message });
  if (!NAME_PATTERN.test(form.name)) add("name", "A name is 1 to 40 lowercase letters, digits and -, starting with a letter or digit.");
  if (!NAME_PATTERN.test(form.target)) add("target", "Choose a target.");
  if (form.mode !== "oneshot" && form.mode !== "session") add("mode", "Choose one-shot or session.");
  else {
    const l = lifetimeIssue(form.mode, form.lifetime_seconds);
    if (l) add("lifetime_seconds", l);
  }
  if (!IMAGE_PATTERN.test(form.image)) add("image", "Use an immutable image digest: name[:tag]@sha256:<64 lowercase hex>.");
  if (form.mode === "oneshot" && form.command.length === 0) add("command", "A one-shot launch needs a command.");
  if (form.command.length > LIMITS.commandArgs) add("command", "A command has at most 128 arguments.");
  let total = 0;
  for (const arg of form.command) {
    total += bytes(arg);
    if (bytes(arg) > LIMITS.argBytes || arg.includes("\0")) add("command", "Each argument is at most 4096 bytes without NUL characters.");
  }
  if (total > LIMITS.commandBytes) add("command", "The command is at most 32 KiB.");
  const env: Record<string, string> = {};
  if (form.env.length > LIMITS.envEntries) add("env", "At most 64 environment variables.");
  total = 0;
  form.env.forEach((e, i) => {
    const issue = envNameIssue(e.name);
    if (issue) add(`env.${i}`, issue);
    if (Object.prototype.hasOwnProperty.call(env, e.name)) add(`env.${i}`, `${e.name} is set twice.`);
    if (bytes(e.value) > LIMITS.envValueBytes || e.value.includes("\0")) add(`env.${i}`, `The value of ${e.name} is at most 4096 bytes without NUL characters.`);
    total += bytes(e.name) + bytes(e.value);
    env[e.name] = e.value;
  });
  if (total > LIMITS.envBytes) add("env", "The environment is at most 32 KiB.");
  if (form.mounts.length > LIMITS.mounts) add("mounts", "At most 8 host folders.");
  const mountNames = new Set<string>();
  form.mounts.forEach((m, i) => {
    if (!MOUNT_NAME_PATTERN.test(m.name) || mountNames.has(m.name)) add(`mounts.${i}.name`, "A mount name is unique: 1 to 32 of a-z 0-9 _ -, starting with a letter or digit.");
    mountNames.add(m.name);
    if (!["read-only", "snapshot", "read-write"].includes(m.mode)) add(`mounts.${i}.mode`, "Choose read-only, snapshot or read-write.");
    const s = mountSourceIssue(m.source);
    if (s) add(`mounts.${i}.source`, s);
    for (const other of form.mounts.slice(0, i))
      if (other.source && m.source && overlaps(other.source, m.source)) add(`mounts.${i}.source`, `The folder overlaps the mount ${other.name}.`);
  });
  const workdir = form.workdir.trim();
  if (workdir) {
    if (workdir[0] !== "/" || cleanPath(workdir) !== workdir || workdir === "/" || bytes(workdir) > LIMITS.workdirBytes || /[\0\n]/.test(workdir))
      add("workdir", "The working directory is a canonical absolute path of at most 160 bytes.");
    else if (!within(DEFAULT_WORKDIR, workdir) && !within("/tmp", workdir) && !form.mounts.some((m) => within(`${MOUNT_ROOT}/${m.name}`, workdir)))
      add("workdir", `The working directory must be inside ${DEFAULT_WORKDIR}, /tmp or ${MOUNT_ROOT}/<a mount name>.`);
  }
  let access: LaunchSpec["access"];
  if (form.access.kind === "profile") {
    if (!NAME_PATTERN.test(form.access.profile)) add("access.profile", "Choose an access profile.");
    if (!Number.isInteger(form.access.version) || form.access.version < 1) add("access.version", "Choose a profile version.");
    access = { profile: form.access.profile, version: form.access.version };
  } else {
    let doc: unknown;
    try {
      doc = JSON.parse(form.access.document);
    } catch {
      add("access.inline", "The inline access document is not valid JSON.");
    }
    const d = doc as Record<string, unknown> | undefined;
    if (doc !== undefined && (typeof d !== "object" || d === null || Array.isArray(d) || d.version !== "agentgate.poc.v2" || !d.filesystem || !d.process))
      add("access.inline", "An inline document is a complete agentgate.poc.v2 policy with filesystem and process sections.");
    if (form.secrets.length) add("secrets", "Brokered secrets need a stored profile; an inline access document cannot reference secrets.");
    access = { inline: doc ?? {} };
  }
  if (form.secrets.length > LIMITS.secrets) add("secrets", "At most 8 brokered secrets.");
  const refs = new Set<string>();
  const exposed = new Set<string>();
  form.secrets.forEach((s, i) => {
    if (!NAME_PATTERN.test(s.ref) || refs.has(s.ref)) add(`secrets.${i}.ref`, "Choose each secret once.");
    refs.add(s.ref);
    if (!ENV_NAME_PATTERN.test(s.env) || exposed.has(s.env) || reservedEnv(s.env)) add(`secrets.${i}.env`, "The broker address variable is a unique, unreserved variable name.");
    if (Object.prototype.hasOwnProperty.call(env, s.env)) add(`secrets.${i}.env`, `${s.env} is also set in the environment list.`);
    exposed.add(s.env);
  });
  if (form.approval !== "auto" && form.approval !== "required") add("approval", "Choose automatic or required approval.");
  const spec: LaunchSpec = {
    version: SPEC_VERSION,
    name: form.name,
    target: form.target,
    mode: form.mode,
    lifetime_seconds: form.lifetime_seconds,
    agent: { image: form.image, command: form.command, env, ...(workdir ? { workdir } : {}) },
    access,
    mounts: form.mounts.map((m) => ({ name: m.name, source: m.source, mode: m.mode })),
    secrets: form.secrets.map((s) => ({ ref: s.ref, expose: { env: s.env } })),
    approval: form.approval,
  };
  if (bytes(specJSON(spec)) > LIMITS.specBytes) add("spec", "The launch spec is at most 64 KiB.");
  return { spec, issues };
}

export const specJSON = (spec: LaunchSpec) => JSON.stringify(spec, null, 2);

// Approval reasons the operator can predict from the form. The plan is the
// authority; this only explains in advance why a second human may be needed.
export function predictApproval(form: LaunchForm, profileRequiresApproval?: boolean, publicWeb?: boolean): string[] {
  const reasons: string[] = [];
  if (form.approval === "required") reasons.push("you asked for approval");
  if (form.access.kind === "inline") reasons.push("an inline access document is not a reviewed profile");
  else if (profileRequiresApproval) reasons.push("the profile requires approval");
  for (const m of form.mounts) {
    if (m.mode === "read-write") reasons.push(`read-write host folder ${m.name}`);
    if (m.mode === "read-only") reasons.push(`live host folder ${m.name}`);
  }
  if (form.secrets.length) reasons.push(`brokered secrets ${form.secrets.map((s) => s.ref).join(", ")}`);
  if (publicWeb) reasons.push("public web access");
  return reasons;
}

// ---- strict import -------------------------------------------------------------

const KEYS: Record<string, string[]> = {
  "": ["version", "name", "target", "mode", "lifetime_seconds", "agent", "access", "mounts", "secrets", "approval"],
  agent: ["image", "command", "env", "workdir"],
  access: ["profile", "version", "inline"],
  mount: ["name", "source", "mode"],
  secret: ["ref", "expose"],
  expose: ["env"],
};

// duplicateKey finds the first object key that appears twice in one object,
// which JSON.parse would silently collapse but the service refuses.
export function duplicateKey(text: string): string | undefined {
  const stack: Set<string>[] = [];
  const containers: string[] = [];
  let expectKey = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      let raw = "";
      while (j < text.length && text[j] !== '"') {
        if (text[j] === "\\") {
          raw += text.slice(j, j + 2);
          j += 2;
        } else raw += text[j++];
      }
      if (containers.at(-1) === "{" && expectKey) {
        let key = raw;
        try {
          key = JSON.parse(`"${raw}"`);
        } catch {
          /* JSON.parse reports the error */
        }
        const seen = stack.at(-1)!;
        if (seen.has(key)) return key;
        seen.add(key);
        expectKey = false;
      }
      i = j;
    } else if (c === "{") {
      containers.push("{");
      stack.push(new Set());
      expectKey = true;
    } else if (c === "[") containers.push("[");
    else if (c === "}" || c === "]") {
      if (containers.pop() === "{") stack.pop();
      expectKey = false;
    } else if (c === ",") expectKey = containers.at(-1) === "{";
  }
  return undefined;
}

function unknownKeys(value: unknown, allowed: string[], where: string): string | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return `${where || "The spec"} must be a JSON object.`;
  const extra = Object.keys(value).find((k) => !allowed.includes(k));
  return extra ? `${where ? where + "." : ""}${extra} is not a field of ${SPEC_VERSION}${extra === "value" ? "; a spec never carries a secret value" : ""}.` : undefined;
}

// parseSpec reads a spec document strictly (one object, no unknown fields, no
// duplicate keys) and returns the form that produces it.
export function parseSpec(text: string): { form?: LaunchForm; error?: string } {
  if (bytes(text) > LIMITS.specBytes) return { error: "A launch spec is at most 64 KiB." };
  let raw: any;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    return { error: `The spec is not valid JSON: ${(e as Error).message}` };
  }
  const dup = duplicateKey(text);
  if (dup) return { error: `The key ${dup} appears twice in one object.` };
  const problem =
    unknownKeys(raw, KEYS[""], "") ||
    unknownKeys(raw.agent ?? {}, KEYS.agent, "agent") ||
    unknownKeys(raw.access ?? {}, KEYS.access, "access") ||
    (raw.mounts ?? []).map((m: unknown, i: number) => unknownKeys(m, KEYS.mount, `mounts[${i}]`)).find(Boolean) ||
    (raw.secrets ?? []).map((s: any, i: number) => unknownKeys(s, KEYS.secret, `secrets[${i}]`) || unknownKeys(s?.expose ?? {}, KEYS.expose, `secrets[${i}].expose`)).find(Boolean);
  if (problem) return { error: problem };
  if (raw.version !== SPEC_VERSION) return { error: `version must be ${SPEC_VERSION}.` };
  const strings = (v: unknown) => Array.isArray(v) && v.every((x) => typeof x === "string");
  if (raw.agent?.command !== undefined && raw.agent.command !== null && !strings(raw.agent.command)) return { error: "agent.command is a list of strings." };
  const env = raw.agent?.env ?? {};
  if (typeof env !== "object" || Array.isArray(env) || Object.values(env).some((v) => typeof v !== "string")) return { error: "agent.env maps names to string values." };
  const inline = raw.access?.inline !== undefined;
  return {
    form: {
      name: String(raw.name ?? ""),
      target: String(raw.target ?? ""),
      mode: raw.mode === "oneshot" ? "oneshot" : "session",
      lifetime_seconds: Number(raw.lifetime_seconds ?? 0),
      image: String(raw.agent?.image ?? ""),
      command: raw.agent?.command ?? [],
      workdir: String(raw.agent?.workdir ?? ""),
      env: Object.entries(env as Record<string, string>).map(([name, value]) => ({ name, value })),
      access: inline
        ? { kind: "inline", document: JSON.stringify(raw.access.inline, null, 2) }
        : { kind: "profile", profile: String(raw.access?.profile ?? ""), version: Number(raw.access?.version ?? 0) },
      mounts: (raw.mounts ?? []).map((m: any) => ({ name: String(m.name ?? ""), source: String(m.source ?? ""), mode: m.mode })),
      secrets: (raw.secrets ?? []).map((s: any) => ({ ref: String(s.ref ?? ""), env: String(s.expose?.env ?? "") })),
      approval: raw.approval === "required" ? "required" : "auto",
    },
  };
}

// ---- command lines ----------------------------------------------------------------

// The CLI reads the same document: what the UI plans and launches is exactly
// what `agentgate launch -f` sends.
export function cliCommands(spec: LaunchSpec) {
  const doc = specJSON(spec);
  return {
    write: `cat > ${spec.name || "launch"}.json <<'SPEC'\n${doc}\nSPEC`,
    plan: `agentgate launch --dry-run -f ${spec.name || "launch"}.json`,
    launch: `agentgate launch -f ${spec.name || "launch"}.json`,
  };
}

export function lifetimeText(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "—";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return [h && `${h} h`, m && `${m} min`, s && `${s} s`].filter(Boolean).join(" ");
}
