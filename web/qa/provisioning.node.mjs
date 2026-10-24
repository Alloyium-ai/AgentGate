// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Unit tests for the pure provisioning logic of the web UI: the launch spec
// builder and importer, access summaries and diffs, the launch event stream
// client, the log buffer and the receipt reader. Parity tests read the Go
// sources so the browser's early checks cannot drift from the service.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { loadTS } from "./load-ts.mjs";

const M = await loadTS("launch-spec", "access-model", "launch-stream", "log-view", "evidence");
const repo = (p) => {
  try {
    return readFileSync(new URL(`../../${p}`, import.meta.url), "utf8");
  } catch {
    return undefined;
  }
};
const goString = (source, name) => source.match(new RegExp(`${name}\\s*=\\s*regexp\\.MustCompile\\(\`([^\`]+)\`\\)`))?.[1];
const fullExample = JSON.parse(repo("internal/access/policy.full.example.json") ?? "null");

function goodForm() {
  return {
    ...M.emptyForm(),
    name: "repo-fixer",
    target: "local",
    mode: "session",
    lifetime_seconds: 3600,
    image: "agentgate-coding@sha256:" + "a".repeat(64),
    command: ["claude", "--print", "fix the failing tests"],
    env: [{ name: "EDITOR", value: "vi" }],
    access: { kind: "profile", profile: "python-dev", version: 3 },
    mounts: [{ name: "repo", source: "/srv/repos/app", mode: "read-only" }],
    secrets: [{ ref: "anthropic", env: "ANTHROPIC_BASE_URL" }],
    approval: "auto",
  };
}

// ---- parity with the Go validators -------------------------------------------------
test("credential and reserved env rules are the service's rules", (t) => {
  const go = repo("internal/control/prov_launchspec.go");
  if (!go) return t.skip("Go sources not present");
  assert.equal(goString(go, "secretEnvPattern"), "(?i)" + M.SECRET_ENV_SOURCE);
  assert.equal(goString(go, "reservedEnvPattern"), "(?i)" + M.RESERVED_ENV_SOURCE);
  assert.equal(goString(go, "envNamePattern"), M.ENV_NAME_PATTERN.source);
});

test("name, image, mount and source patterns and protected trees match hostproto", (t) => {
  const go = repo("internal/hostproto/jobs.go");
  if (!go) return t.skip("Go sources not present");
  assert.equal(goString(go, "NamePattern"), M.NAME_PATTERN.source);
  assert.equal(goString(go, "MountNamePattern"), M.MOUNT_NAME_PATTERN.source);
  // RegExp.source escapes "/" as "\/"; the patterns are otherwise identical.
  const src = (re) => re.source.replaceAll("\\/", "/");
  assert.equal(goString(go, "BindSourcePattern"), src(M.BIND_SOURCE_PATTERN));
  assert.equal(goString(go, "ImagePattern"), src(M.IMAGE_PATTERN));
  const list = (name) => [...go.match(new RegExp(`var ${name} = \\[\\]string\\{([^}]+)\\}`))[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  assert.deepEqual(list("ProtectedMountTrees"), M.PROTECTED_MOUNT_TREES);
  assert.deepEqual(list("secretComponents"), M.CREDENTIAL_COMPONENTS);
});

test("lifetime bounds match the service", (t) => {
  const go = repo("internal/control/prov_launchspec.go");
  if (!go) return t.skip("Go sources not present");
  const c = (n) => Number(go.match(new RegExp(`${n}\\s*=\\s*(\\d+)`))[1]);
  assert.deepEqual(M.LIFETIME, { oneshot: { min: c("oneshotMin"), max: c("oneshotMax") }, session: { min: c("sessionMin"), max: c("sessionMax") } });
});

// ---- spec builder --------------------------------------------------------------------
test("the guided form builds the contract's example spec", () => {
  const { spec, issues } = M.buildSpec(goodForm());
  assert.deepEqual(issues, []);
  assert.deepEqual(spec, {
    version: "agentgate.launch.v1",
    name: "repo-fixer",
    target: "local",
    mode: "session",
    lifetime_seconds: 3600,
    agent: { image: "agentgate-coding@sha256:" + "a".repeat(64), command: ["claude", "--print", "fix the failing tests"], env: { EDITOR: "vi" } },
    access: { profile: "python-dev", version: 3 },
    mounts: [{ name: "repo", source: "/srv/repos/app", mode: "read-only" }],
    secrets: [{ ref: "anthropic", expose: { env: "ANTHROPIC_BASE_URL" } }],
    approval: "auto",
  });
  assert.deepEqual(M.parseSpec(M.specJSON(spec)).form, { ...goodForm(), workdir: "" });
});

test("every rule the form enforces reports a field", () => {
  const issue = (change) => M.buildSpec({ ...goodForm(), ...change }).issues.map((i) => i.field);
  assert.ok(issue({ name: "Bad_Name" }).includes("name"));
  assert.ok(issue({ mode: "oneshot", lifetime_seconds: 3601 }).includes("lifetime_seconds"));
  assert.ok(issue({ mode: "session", lifetime_seconds: 59 }).includes("lifetime_seconds"));
  assert.ok(issue({ mode: "oneshot", lifetime_seconds: 60, command: [] }).includes("command"));
  assert.ok(issue({ image: "agentgate-coding:latest" }).includes("image"));
  for (const name of ["API_KEY", "GITHUB_TOKEN", "TOKEN", "MY_PAT", "DB_PASSWORD", "aws_secret_access_key", "OPENAI_APIKEY", "X_AUTH", "SESSION_COOKIE"])
    assert.ok(issue({ env: [{ name, value: "x" }] }).includes("env.0"), name);
  for (const name of ["LD_PRELOAD", "AGENTGATE_X", "DYLD_INSERT_LIBRARIES", "1BAD"]) assert.ok(issue({ env: [{ name, value: "x" }] }).includes("env.0"), name);
  for (const name of ["EDITOR", "PATH", "KEYBOARD", "PATTERN", "HOME"]) assert.deepEqual(issue({ env: [{ name, value: "x" }] }), [], name);
  for (const source of ["/etc/app", "/home/alice", "/home", "/srv/x/.ssh/keys", "/var/lib/agentgate/x", "/var/lib/agentgate-demo", "/srv/a/", "/srv/../etc", "/srv/a b", "/"])
    assert.ok(issue({ mounts: [{ name: "repo", source, mode: "snapshot" }] }).includes("mounts.0.source"), source);
  assert.deepEqual(issue({ mounts: [{ name: "repo", source: "/home/alice/project", mode: "snapshot" }] }), []);
  assert.ok(issue({ mounts: [{ name: "a", source: "/srv/x", mode: "snapshot" }, { name: "b", source: "/srv/x/y", mode: "snapshot" }] }).includes("mounts.1.source"));
  assert.ok(issue({ mounts: [{ name: "a", source: "/srv/x", mode: "snapshot" }, { name: "a", source: "/srv/y", mode: "snapshot" }] }).includes("mounts.1.name"));
  assert.ok(issue({ workdir: "/srv/elsewhere" }).includes("workdir"));
  assert.deepEqual(issue({ workdir: "/var/lib/agentgate/mounts/repo/src" }), []);
  assert.ok(issue({ secrets: [{ ref: "anthropic", env: "EDITOR" }] }).includes("secrets.0.env"));
  assert.ok(issue({ secrets: [{ ref: "a", env: "LD_X" }] }).includes("secrets.0.env"));
  assert.ok(issue({ access: { kind: "inline", document: JSON.stringify(fullExample ?? { version: "agentgate.poc.v2", filesystem: {}, process: {} }) } }).includes("secrets"));
  assert.ok(issue({ access: { kind: "inline", document: "{" }, secrets: [] }).includes("access.inline"));
  assert.ok(issue({ access: { kind: "profile", profile: "", version: 0 } }).includes("access.profile"));
});

test("approval predictions name every reason the contract lists", () => {
  const reasons = M.predictApproval({ ...goodForm(), approval: "required", mounts: [{ name: "a", source: "/srv/a", mode: "read-write" }] }, true, true);
  assert.deepEqual(reasons, ["you asked for approval", "the profile requires approval", "read-write host folder a", "brokered secrets anthropic", "public web access"]);
  assert.deepEqual(M.predictApproval({ ...goodForm(), secrets: [], mounts: [{ name: "s", source: "/srv/s", mode: "snapshot" }] }, false, false), []);
});

test("import is strict: unknown fields, duplicate keys and a secret value are refused", () => {
  const doc = JSON.parse(M.specJSON(M.buildSpec(goodForm()).spec));
  assert.match(M.parseSpec(JSON.stringify({ ...doc, extra: 1 })).error, /extra is not a field/);
  assert.match(M.parseSpec(JSON.stringify({ ...doc, secrets: [{ ref: "x", expose: { env: "X" }, value: "s3cret" }] })).error, /never carries a secret value/);
  assert.match(M.parseSpec(JSON.stringify({ ...doc, agent: { ...doc.agent, user: "root" } })).error, /agent\.user/);
  assert.match(M.parseSpec('{"version":"agentgate.launch.v1","name":"a","name":"b"}').error, /appears twice/);
  assert.equal(M.duplicateKey('{"a":{"b":1},"c":{"b":2},"s":"\\"a\\""}'), undefined);
  assert.equal(M.duplicateKey('{"a":[{"x":1,"x":2}]}'), "x");
  assert.match(M.parseSpec("{").error, /not valid JSON/);
  assert.match(M.parseSpec(JSON.stringify({ ...doc, version: "agentgate.launch.v2" })).error, /version must be/);
  const inline = M.parseSpec(JSON.stringify({ ...doc, secrets: [], access: { inline: { version: "agentgate.poc.v2" } } })).form;
  assert.equal(inline.access.kind, "inline");
});

test("CLI commands send the same document", () => {
  const { spec } = M.buildSpec(goodForm());
  const c = M.cliCommands(spec);
  assert.equal(c.launch, "agentgate launch -f repo-fixer.json");
  assert.equal(c.plan, "agentgate launch --dry-run -f repo-fixer.json");
  const body = c.write.split("\n").slice(1, -1).join("\n");
  assert.deepEqual(JSON.parse(body), spec);
  assert.ok(c.write.startsWith("cat > repo-fixer.json <<'SPEC'"));
  assert.equal(M.lifetimeText(3725), "1 h 2 min 5 s");
});

// ---- access model ---------------------------------------------------------------------
test("the full example explains public web as high risk and keeps write-xor-execute", (t) => {
  if (!fullExample) return t.skip("example not present");
  const rows = M.rows(fullExample);
  const web = rows.filter((r) => r.permission === "Public web");
  assert.equal(web.length, 3);
  assert.ok(web.every((r) => r.risk === "high" && r.value.includes("any public IPv4 address")));
  assert.ok(rows.some((r) => r.permission === "Execute" && r.value === "/usr" && /Writable folders can never be executable/.test(r.meaning)));
  assert.ok(rows.some((r) => r.permission === "Executable anonymous memory" && r.value === "off"));
  const text = M.sentences(fullExample).join(" ");
  assert.match(text, /not limited to particular sites/);
  assert.match(text, /never run programs from a writable folder/);
  assert.match(text, /Everything else is denied/);
});

test("a version one document is shown as unable to launch", () => {
  const v1 = { version: "agentgate.network-poc.v1", default: "deny", ipv6: "deny", dns: { resolvers: [], protocols: [], port: 53 }, web: { destination: "public-ipv4", rules: [] }, taskboard: { address: "10.10.10.10", protocol: "tcp", port: 8080, task_id: 1 }, duration_seconds: 25 };
  assert.ok(M.rows(v1).some((r) => r.permission === "Not controlled" && r.risk === "high"));
  assert.match(M.sentences(v1).join(" "), /cannot be used for a launch/);
});

test("version diffs list added, removed and changed permissions", (t) => {
  if (!fullExample) return t.skip("example not present");
  const next = structuredClone(fullExample);
  next.filesystem.read_only.push("/srv/data");
  next.filesystem.scratch.push("/var/lib/agentgate/mounts/repo");
  next.web.rules = next.web.rules.filter((r) => r.protocol !== "udp");
  next.filesystem.memory.anonymous_execute = true;
  const d = M.diffDocuments(fullExample, next);
  assert.deepEqual(
    d.map((r) => [r.area, r.field, r.change, r.before ?? r.after]),
    [
      ["Network", "public web", "removed", "QUIC / HTTP/3 (UDP 443)"],
      ["Files", "read", "added", "/srv/data"],
      ["Mounts", "host folder", "added", "repo (read-write)"],
      ["Memory", "executable anonymous memory", "changed", "off"],
    ],
  );
  assert.deepEqual(M.diffDocuments(fullExample, fullExample), []);
  assert.ok(M.diffDocuments(undefined, fullExample).length > 5);
});

// The service computes the grant change list in Go (internal/control
// PolicyChanges). These fixtures are answers of the real service, recorded by
// TestWebFixturesAreRealServiceAnswers; the UI's own diff must agree.
const fixture = (name) => JSON.parse(repo(`web/qa/fixtures/api/${name}`) ?? "null");
const rowsOf = (list) => list.map(({ area, field, change, before, after }) => ({ area, field, change, ...(before !== undefined ? { before } : {}), ...(after !== undefined ? { after } : {}) }));

test("the service's grant change list equals the UI's diff (real service answers)", () => {
  const dry = fixture("grant-dry-run.json");
  assert.equal(dry.response.dry_run, true);
  assert.equal(dry.response.from_digest, dry.parent.digest);
  assert.ok(dry.response.changes.length >= 3, "the fixture exercises several areas");
  assert.deepEqual(rowsOf(M.diffDocuments(dry.parent.document, dry.response.document)), rowsOf(dry.response.changes));
  const applied = fixture("grant-applied.json");
  assert.equal(applied.response.version.digest, dry.response.digest, "the preview predicts the stored version");
  assert.deepEqual(rowsOf(M.diffDocuments(applied.parent.document, applied.response.version.document)), rowsOf(applied.response.changes));
});

test("typed edits are described with their risk and pre-checked", () => {
  assert.equal(M.describeEdit({ action: "exec", values: ["/opt/tool"] }).risk, "medium");
  assert.match(M.describeEdit({ action: "write", values: ["/data"] }).text, /never be executable/);
  assert.equal(M.describeEdit({ action: "allow-web", values: ["https"] }).risk, "high");
  assert.equal(M.describeEdit({ action: "mount", values: ["repo"], mode: "read-write" }).risk, "high");
  assert.equal(M.describeEdit({ action: "revoke", kind: "deny", values: ["/etc/shadow"] }).risk, "medium");
  assert.equal(M.editIssue({ action: "read", values: ["/srv/data"] }), undefined);
  for (const bad of ["relative", "/", "/a//b", "/a/../b", "/a/./b"]) assert.ok(M.editIssue({ action: "read", values: [bad] }), bad);
  assert.ok(M.editIssue({ action: "dns", values: ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1"] }));
  assert.ok(M.editIssue({ action: "dns", values: ["999.1.1.1"] }));
  assert.equal(M.editIssue({ action: "signal", values: ["term"] }), undefined);
  assert.ok(M.editIssue({ action: "signal", values: ["SIGSEGV"] }));
  assert.ok(M.editIssue({ action: "mount", values: ["Repo"] }));
});

// ---- event stream ---------------------------------------------------------------------
test("the SSE parser handles chunks, CRLF, comments, ids and multi-line data", () => {
  const p = new M.SSEParser();
  assert.deepEqual(p.push("event: ready\r\ndata: {}\r\n\r\n: keepalive\n\nid: 7\nevent: sta"), [{ id: undefined, event: "ready", data: "{}" }]);
  assert.deepEqual(p.push('te\ndata: {"seq":7,\ndata: "kind":"state"}\n\n'), [{ id: "7", event: "state", data: '{"seq":7,\n"kind":"state"}' }]);
});

const sse = (body, status = 200) => new Response(body, { status, headers: { "Content-Type": status === 200 ? "text/event-stream" : "application/json" } });
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
const ev = (seq, to) => `id: ${seq}\nevent: state\ndata: ${JSON.stringify({ seq, kind: "state", to_state: to })}\n\n`;
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

test("the stream resumes after the last sequence when the service ends it", async () => {
  const urls = [];
  const got = [];
  let n = 0;
  const fetchImpl = async (url, init) => {
    urls.push([url, init.headers["Last-Event-ID"]]);
    n++;
    if (n === 1) return sse("event: ready\ndata: {}\n\n" + ev(1, "approval_pending") + ev(2, "approved"));
    if (n === 2) return sse("event: ready\ndata: {}\n\n" + ev(2, "approved") + ev(3, "queued"));
    return new Promise(() => {});
  };
  const h = M.followLaunch("L1", { fetchImpl, onEvent: (e) => got.push(e.seq), maxBackoffMs: 10 });
  await wait(1300);
  h.stop();
  assert.deepEqual(got, [1, 2, 3]);
  assert.equal(urls[0][0], "/api/v1/launches/L1/events?after=0");
  assert.deepEqual(urls[1], ["/api/v1/launches/L1/events?after=2", "2"]);
});

test("repeated stream failures fall back to polling and a 401 ends following", async () => {
  const got = [];
  const statuses = [];
  const calls = [];
  let polls = 0;
  const fetchImpl = async (url, init) => {
    calls.push(url);
    if (init.headers.Accept === "text/event-stream") return sse("", 503);
    polls++;
    if (polls === 1) return json({ items: [{ seq: 1, kind: "state", to_state: "queued" }, { seq: 2, kind: "progress" }] });
    return json({ error: { code: "session_expired" } }, 401);
  };
  let ended = false;
  const h = M.followLaunch("L2", { fetchImpl, onEvent: (e) => got.push(e.seq), onStatus: (s) => statuses.push(s.mode), onSessionEnded: () => (ended = true), maxBackoffMs: 5, failuresBeforePoll: 2, pollMs: 20, sseRetryWhilePollingMs: 100000 });
  await wait(200);
  h.stop();
  assert.deepEqual(got, [1, 2]);
  assert.ok(statuses.includes("reconnecting") && statuses.includes("polling"));
  assert.ok(ended, "a 401 while polling ends the session");
  assert.ok(calls.some((u) => u.includes("after=2&limit=200")) || polls === 2);
  assert.equal(M.backoff(1), 1000);
  assert.equal(M.backoff(10), 30000);
});

// ---- logs and receipts -----------------------------------------------------------------
test("log text keeps control characters and bidi overrides visible", () => {
  assert.equal(M.visible("ok\x1b[31mred‮evil\tend\n"), "ok\\x1b[31mred\\u202eevil\tend\n");
  assert.equal(M.visible("<script>alert(1)</script>"), "<script>alert(1)</script>");
  const b = new M.LogBuffer(3);
  b.append([1, 2, 3, 4].map((seq) => ({ seq, time: "2026-10-24T00:00:00.000Z", stream: seq % 2 ? "stdout" : "stderr", text: `line ${seq}` })));
  b.append([{ seq: 4, time: "", stream: "stdout", text: "duplicate" }]);
  assert.deepEqual(b.lines.map((l) => l.seq), [2, 3, 4]);
  assert.equal(b.dropped, 1);
  assert.deepEqual(M.filterLines(b.lines, "stderr").map((l) => l.seq), [2, 4]);
  assert.deepEqual(M.filterLines(b.lines, "LINE 3").map((l) => l.seq), [3]);
  b.append([{ seq: 5, time: "t", stream: "stdout", text: M.TRUNCATION_MARKER }]);
  assert.ok(b.hasMarker());
  assert.equal(M.toText([{ seq: 1, time: "t", stream: "stdout", text: "a\x07" }]), "t stdout a\\x07\n");
});

test("the receipt reader summarizes guard evidence and tolerates anything else", () => {
  const host = {
    filesystem: { object: "fs.bpf.o", lost: 0, decisions: 12, observed: 12, complete: true, operations: { open_read: { allowed: 10, denied: 1 }, open_write: { allowed: 0, denied: 1 } }, denials: [{ sequence: 3, pid: 41, operation: "open_read", path: "/etc/shadow" }], denials_truncated: false },
    process: { lost: 2, complete: false, operations: {}, denials: [] },
    complete: false,
  };
  const network = { state: "stopped", evidence_complete: false, evidence_missing: ["network"], guard: { network: { hooks: { connect4: { allowed: 3, denied: 2 } }, lost: 0, complete: true } } };
  const e = M.readEvidence(network, host);
  assert.equal(e.rings.length, 2);
  assert.deepEqual(e.rings[0].operations[0], { operation: "open_read", allowed: 10, denied: 1 });
  assert.equal(e.rings[0].denials[0].path, "/etc/shadow");
  assert.equal(e.rings[1].lost, 2);
  assert.deepEqual(e.network.operations, [{ operation: "connect4", allowed: 3, denied: 2 }]);
  assert.ok(e.networkFacts.some((f) => f.label === "Evidence missing" && f.value === "network"));
  const empty = M.readEvidence("not an object", [1, 2]);
  assert.deepEqual(empty.rings, []);
  assert.equal(empty.network, undefined);
  assert.match(M.missingText("lost_host"), /heartbeats/);
  assert.match(M.missingText("weird_code"), /weird_code/);
});
