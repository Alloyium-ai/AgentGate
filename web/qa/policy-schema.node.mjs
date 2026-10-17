// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import ts from "typescript";
const helpers = ts.transpileModule(
  readFileSync(new URL("../src/policy-schema.ts", import.meta.url), "utf8"),
  {
    compilerOptions: {
      module: ts.ModuleKind.ES2022,
      target: ts.ScriptTarget.ES2022,
    },
  },
).outputText;
const {
  emptyKernelDocument,
  fieldIssues,
  initialValue,
  requiredCapabilities,
  requestedAllowances,
  resolveSchema,
  toPolicyYAML,
  withRequirements,
} = await import(
  `data:text/javascript;base64,${Buffer.from(helpers).toString("base64")}`
);
const schema = JSON.parse(
  readFileSync(
    new URL("../../internal/policy/schema.v2.json", import.meta.url),
  ),
);
const contract = { schema, kernel_profile: "kernel-policy.v2" };
function fixture() {
  const doc = emptyKernelDocument(contract);
  doc.lifecycle.baseline_version = "reviewed-baseline";
  return doc;
}
test("empty full policy keeps every permission and runtime template empty", () => {
  const doc = fixture();
  assert.deepEqual(doc.files.rules, []);
  assert.deepEqual(doc.programs.rules, []);
  assert.deepEqual(doc.network.rules, []);
  assert.deepEqual(doc.sockets.rules, []);
  assert.equal(doc.sockets.default, "deny");
  assert.deepEqual(doc.runtime.seccomp.allow_syscalls, []);
  assert.deepEqual(doc.runtime_templates, []);
  assert.deepEqual(doc.runtime.capabilities, []);
  assert.deepEqual(doc.runtime.supplementary_groups, []);
  assert.deepEqual(doc.defaults, {
    registered_operations: "deny",
    unmatched_resources: "deny",
    missing_managed_policy: "deny",
  });
  assert.equal(doc.files.defaults.read, "deny");
  assert.equal(doc.runtime.seccomp.default, "deny");
  assert.deepEqual(requestedAllowances(doc), []);
  assert.deepEqual(fieldIssues(doc, schema), []);
});

test("socket permissions expose local and option sources without implicit allows", () => {
  const doc = fixture();
  doc.sockets.rules = [
    {
      id: "client",
      family: "ipv4",
      protocol: "tcp",
      operations: ["create", "get_option"],
      effect: "allow",
      options: [{ level: 1, name: 4 }],
    },
  ];
  const normalized = withRequirements(doc, schema);
  assert.ok(normalized.required_capabilities.includes("socket.get_option.v1"));
  assert.deepEqual(fieldIssues(normalized, schema), []);
  const rows = requestedAllowances(normalized);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].source, "sockets.rules.client");
  assert.match(rows[0].resource, /Owned ipv4 tcp sockets/);
  assert.match(rows[0].permission, /options 1\/4/);
  doc.sockets.rules[0].operations = ["bind"];
  assert.ok(
    fieldIssues(withRequirements(doc, schema), schema).some((issue) =>
      issue.path.endsWith(".local"),
    ),
  );
  doc.sockets.rules[0].operations = ["get_option"];
  delete doc.sockets.rules[0].options;
  assert.ok(
    fieldIssues(withRequirements(doc, schema), schema).some((issue) =>
      issue.path.endsWith(".options"),
    ),
  );
});
test("the guided builder reaches every full schema section and optional approval field", () => {
  const doc = fixture();
  const branch = schema.oneOf.find(
    (branch) => branch.properties.profile.const === doc.profile,
  );
  for (const name of branch.required) assert.ok(Object.hasOwn(doc, name), name);
  const programs = resolveSchema(schema.properties.programs, schema);
  const rule = initialValue(programs.properties.rules.items, schema);
  assert.equal(rule.effect, "deny");
  const approval = initialValue(
    programs.properties.rules.items.properties.approval,
    schema,
  );
  assert.deepEqual(approval.argv1, []);
  assert.equal(approval.scope, "one-shot-actual-executable");
  assert.equal(approval.argument_assurance, "observed");
});
test("explicit allows produce their capabilities and permission source without implicit runtime permissions", () => {
  const doc = fixture();
  doc.files.rules.push({
    id: "one-read",
    selector: { kind: "exact", path: "/work/input" },
    operations: ["read"],
    effect: "allow",
  });
  doc.programs.rules.push({
    id: "git",
    selector: { kind: "exact", path: "/usr/bin/git" },
    effect: "allow",
    approval: {
      argv1: ["push"],
      timeout_seconds: 30,
      scope: "one-shot-actual-executable",
      argument_assurance: "observed",
    },
  });
  doc.network.rules.push({
    id: "one-target",
    family: "ipv6",
    protocol: "udp",
    destination: { kind: "hostname", value: "example.test" },
    port_from: 443,
    port_to: 443,
    effect: "allow",
  });
  const next = withRequirements(doc, schema);
  for (const capability of [
    "fs.rules.v1",
    "exec.approval.v1",
    "net.ipv6.v1",
    "net.udp.v1",
    "net.dns-ttl.v1",
    "runtime.explicit-syscalls.v2",
    "policy.default-deny.v2",
  ])
    assert.ok(next.required_capabilities.includes(capability), capability);
  assert.equal(
    new Set(next.required_capabilities).size,
    next.required_capabilities.length,
  );
  assert.equal(requestedAllowances(doc).length, 3);
  assert.equal(requestedAllowances(doc)[0].source, "files.rules.one-read");
  assert.equal(requestedAllowances(doc)[0].resource, "exact: /work/input");
  assert.match(requestedAllowances(doc)[1].permission, /push; timeout 30s/);
  assert.deepEqual(doc.runtime.seccomp.allow_syscalls, []);
  assert.deepEqual(
    next.required_capabilities,
    requiredCapabilities(next, schema),
  );
});
test("feedback identifies unknown fields, changed deny defaults, absent sections and reversed ports", () => {
  const doc = fixture();
  doc.defaults.registered_operations = "allow";
  doc.files.unknown = true;
  delete doc.identity;
  doc.network.rules.push({
    id: "bad-port",
    family: "ipv4",
    protocol: "tcp",
    destination: { kind: "ip", value: "192.0.2.1" },
    port_from: 443,
    port_to: 80,
    effect: "allow",
  });
  const paths = fieldIssues(doc, schema).map((issue) => issue.path);
  for (const path of [
    "policy.defaults.registered_operations",
    "policy.files.unknown",
    "policy.identity",
    "policy.network.rules.0.port_to",
  ])
    assert.ok(paths.includes(path), path);
});
test("YAML export quotes all scalar text and preserves empty deny permissions", () => {
  const yaml = toPolicyYAML(fixture());
  assert.ok(yaml.includes('"rules": []'));
  assert.ok(yaml.includes('"read": "deny"'));
  assert.equal(
    toPolicyYAML({
      text: 'yes: # keep\nquotes "x"',
      rows: [{ value: "null" }],
    }),
    '"text": "yes: # keep\\nquotes \\"x\\""\n"rows":\n  -\n    "value": "null"',
  );
});

test("memory preview lists only explicit anonymous and heap permissions", () => {
  const doc = fixture();
  assert.deepEqual(requestedAllowances(doc), []);
  doc.runtime.memory = { default: "deny", anonymous: [], heap: "deny" };
  assert.deepEqual(requestedAllowances(doc), []);
  doc.runtime.memory.anonymous = ["map", "read", "write", "execute", "protect"];
  doc.runtime.memory.heap = "allow";
  const rows = requestedAllowances(doc);
  assert.deepEqual(
    rows.slice(0, 5).map((row) => row.permission),
    doc.runtime.memory.anonymous,
  );
  assert.ok(
    rows.slice(0, 5).every((row) => row.source === "runtime.memory.anonymous"),
  );
  assert.deepEqual(rows[5], {
    resource: "Process heap",
    permission: "Adjust heap break",
    source: "runtime.memory.heap",
  });
});

test("pipe, signal and bootstrap origins require explicit permissions", () => {
  const doc = fixture();
  doc.runtime.ipc = { default: "deny", pipes: [] };
  doc.runtime.signals = [];
  assert.deepEqual(requestedAllowances(doc), []);
  doc.runtime.ipc.pipes = ["create", "read", "write"];
  doc.runtime.signals = [1, 64];
  doc.runtime.bootstrap = {
    profile: "measured-held-exec.v1",
    helper_digest: "9".repeat(64),
    operations: ["barrier_read"],
    max_hold_seconds: 7,
  };
  const normalized = withRequirements(doc, schema);
  assert.deepEqual(fieldIssues(normalized, schema), []);
  const rows = requestedAllowances(doc);
  assert.deepEqual(
    rows.slice(0, 3).map((row) => row.permission),
    ["create", "read", "write"],
  );
  assert.ok(
    rows.slice(0, 3).every((row) => row.source === "runtime.ipc.pipes"),
  );
  assert.deepEqual(
    rows.slice(3, 5).map((row) => row.resource),
    ["Linux signal 1", "Linux signal 64"],
  );
  assert.ok(
    rows
      .slice(3, 5)
      .every(
        (row) =>
          row.source === "runtime.signals" &&
          row.permission.includes("same job domain"),
      ),
  );
  assert.equal(rows[5].source, "runtime.bootstrap.operations");
  assert.match(rows[5].resource, /9{64}/);
  assert.match(rows[5].permission, /one control read; hold at most 7s/);
  delete doc.runtime.ipc;
  delete doc.runtime.signals;
  delete doc.runtime.bootstrap;
  assert.deepEqual(requestedAllowances(doc), []);
});

test("event descriptor origins preserve omitted and empty deny permissions", () => {
  const doc = fixture();
  doc.runtime.ipc = { default: "deny", pipes: [] };
  assert.deepEqual(requestedAllowances(doc), []);
  assert.equal(Object.hasOwn(doc.runtime.ipc, "eventfds"), false);
  doc.runtime.ipc.eventfds = [];
  assert.deepEqual(requestedAllowances(doc), []);
  assert.ok(withRequirements(doc, schema).required_capabilities.includes("runtime.explicit-eventfds.v1"));
  doc.runtime.ipc.eventfds = ["create", "read", "write"];
  const normalized = withRequirements(doc, schema);
  assert.deepEqual(fieldIssues(normalized, schema), []);
  assert.deepEqual(requestedAllowances(normalized), ["create", "read", "write"].map(permission => ({
    resource: "Job event descriptors", permission, source: "runtime.ipc.eventfds",
  })));
  assert.deepEqual(doc.runtime.seccomp.allow_syscalls, []);
});

test("each explicit bootstrap operation displays its own measured scope", () => {
  const doc = fixture();
  const operations = ["barrier_read", "listener_send", "filter_finalize", "working_directory", "credential_namespace"];
  doc.runtime.bootstrap = {
    profile: "measured-held-exec.v1", helper_digest: "8".repeat(64),
    operations, max_hold_seconds: 9,
  };
  const normalized = withRequirements(doc, schema);
  assert.deepEqual(fieldIssues(normalized, schema), []);
  assert.ok(normalized.required_capabilities.includes("runtime.credential-namespace.v1"));
  const rows = requestedAllowances(normalized);
  assert.equal(rows.length, operations.length);
  assert.ok(rows.every(row => row.source === "runtime.bootstrap.operations"));
  assert.match(rows[0].permission, /one control read/);
  assert.match(rows[1].permission, /measured exec listener/);
  assert.match(rows[2].permission, /measured syscall filter/);
  assert.match(rows[3].permission, /immutable working directory/);
  assert.match(rows[4].permission, /measured credential namespace/);
  assert.ok(rows.slice(1).every(row => !row.permission.includes("one control read")));
  assert.deepEqual(doc.runtime.seccomp.allow_syscalls, []);
});
