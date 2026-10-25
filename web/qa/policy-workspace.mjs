// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
import { chromium } from "playwright";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { extname, join } from "node:path";
import ts from "typescript";
const output = process.env.QA_OUTPUT;
if (!output) throw new Error("Set QA_OUTPUT to an owned artifact directory.");
await mkdir(output, { recursive: true });
const schema = JSON.parse(
  await readFile(
    new URL("../../internal/policy/schema.v2.json", import.meta.url),
  ),
);
const helpers = ts.transpileModule(
  await readFile(new URL("../src/policy-schema.ts", import.meta.url), "utf8"),
  {
    compilerOptions: {
      module: ts.ModuleKind.ES2022,
      target: ts.ScriptTarget.ES2022,
    },
  },
).outputText;
const { emptyKernelDocument, withRequirements } = await import(
  `data:text/javascript;base64,${Buffer.from(helpers).toString("base64")}`
);
const contract = {
  schema,
  schema_digest: "a".repeat(64),
  compiler_version: "fixture-compiler",
  selected_profile: "selected-inspection.v2",
  kernel_profile: "kernel-policy.v2",
  default: "deny",
  admission_available: false,
  inventory_pending: true,
  capability_ids: [],
  runtime_templates: [],
};
const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, "http://fixture").pathname;
    const file = join(
      new URL("../dist/", import.meta.url).pathname,
      path === "/" ? "index.html" : path,
    );
    response.setHeader(
      "Content-Type",
      {
        ".html": "text/html",
        ".js": "application/javascript",
        ".css": "text/css",
      }[extname(file)] || "application/octet-stream",
    );
    response.end(await readFile(file));
  } catch {
    response.writeHead(404);
    response.end();
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const base = `http://127.0.0.1:${server.address().port}`;
// QA_CHROMIUM points at a preinstalled browser when the pinned Playwright
// build is not downloaded (for example /opt/pw-browsers in the build sandbox).
const browser = await chromium.launch({ headless: true, executablePath: process.env.QA_CHROMIUM || undefined });
const errors = [];
const requests = [];
let roles = ["admin"];
let saved;
let version = {
  id: "full-version-one",
  policy_id: "full-policy-one",
  number: 1,
  parent_id: "",
  state: "draft",
  rights: { workspace_write: false, tcp_address: "", tcp_port: 0 },
  digest: "c".repeat(64),
  revision: 1,
  actor: "fixture-admin",
  reason: "Create a complete contract draft.",
  created_at: "2026-10-15T00:00:00Z",
};
const ctx = await browser.newContext({
  viewport: { width: 1440, height: 1000 },
});
await ctx.route("**/api/v1/**", async (route) => {
  const req = route.request();
  const path = new URL(req.url()).pathname.slice("/api/v1/".length);
  const input = req.method() === "GET" ? undefined : req.postDataJSON();
  requests.push({ path, method: req.method(), input });
  const json = (body, status = 200) =>
    route.fulfill({
      status,
      contentType: "application/json",
      body: JSON.stringify(body),
    });
  if (path === "session")
    return json({
      actor: { subject: "fixture-admin", kind: "human", roles, scopes: [] },
      csrf_token: "fixture-csrf",
      expires: 9999999999,
      customer_policy: true,
      local_identity: true,
    });
  if (path === "events")
    return route.fulfill({
      contentType: "text/event-stream",
      body: ": fixture\n\n",
    });
  if (path === "policy-schema") return json(contract);
  if (path === "overview") return json({});
  if (path === "policy-validate") {
    let doc;
    try {
      doc = input.format === "yaml" ? saved.document : JSON.parse(input.source);
    } catch {
      return json(
        {
          error: {
            code: "invalid_policy_document",
            message: "The source has invalid JSON.",
          },
        },
        422,
      );
    }
    if (doc.unknown)
      return json(
        {
          error: {
            code: "invalid_policy_document",
            message: "policy.unknown: additional properties are not allowed",
          },
        },
        422,
      );
    if (input.format === "yaml")
      assert.ok(input.source.includes('"read": "deny"'));
    return json({
      purpose: "contract-validation",
      document: doc,
      schema_digest: contract.schema_digest,
      admission_available: false,
    });
  }
  if (path === "policy-documents" && req.method() === "POST") {
    saved = {
      purpose: "contract-draft",
      version,
      document: JSON.parse(input.source),
      document_digest: "b".repeat(64),
      schema_digest: contract.schema_digest,
      compiler_version: contract.compiler_version,
    };
    return json(saved);
  }
  if (path === "policy-documents/full-version-one")
    return json({ ...saved, version });
  if (path === "policies/full-policy-one")
    return json({
      id: "full-policy-one",
      name: "Explicit build policy",
      description: "Full deny contract.",
      created_at: version.created_at,
    });
  if (path === "policies/full-policy-one/versions")
    return json({ items: [version] });
  if (path === "policies") return json({ items: [] });
  if (path === "versions/full-version-one/transition") {
    version = {
      ...version,
      state: input.state,
      revision: version.revision + 1,
    };
    return json(version);
  }
  if (path === "policy-preview")
    return json(
      {
        error: {
          code: "target_unqualified",
          message:
            "Required capability fs.rules.v1 is unqualified on this node and boot.",
        },
      },
      422,
    );
  return json({ items: [] });
});
const page = await ctx.newPage();
page.on("pageerror", (error) => errors.push(error.message));
try {
  await page.goto(`${base}/#/policy-builder`);
  await page
    .getByRole("heading", { name: "Full policy builder", exact: true })
    .waitFor();
  await page
    .getByText("No rule. No allowance.", { exact: true })
    .first()
    .waitFor();
  assert.equal(
    await page
      .getByRole("button", { name: "Save full contract draft" })
      .isDisabled(),
    true,
  );
  await page
    .getByLabel("Policy name", { exact: true })
    .fill("Explicit build policy");
  await page
    .getByLabel("Description", { exact: true })
    .fill("Full deny contract.");
  await page
    .getByLabel("Draft reason", { exact: true })
    .fill("Create a complete contract draft.");
  await page.getByRole("button", { name: "Save full contract draft" }).click();
  await page.getByText("Complete the policy fields", { exact: true }).waitFor();
  await page
    .locator('details.policy-section[data-section="lifecycle"] > summary')
    .click();
  await page
    .getByLabel("policy.lifecycle.baseline_version", { exact: true })
    .fill("reviewed-baseline");
  const files = page.locator('details.policy-section[data-section="files"]');
  await files
    .getByRole("button", { name: "Add rules item", exact: true })
    .click();
  assert.equal(
    await page
      .getByLabel("policy.files.rules.0.effect", { exact: true })
      .inputValue(),
    "deny",
  );
  await page
    .getByLabel("policy.files.rules.0.id", { exact: true })
    .fill("input-read");
  await page
    .getByLabel("policy.files.rules.0.selector.path", { exact: true })
    .fill("/work/input");
  await page
    .getByLabel("policy.files.rules.0.operations: read", { exact: true })
    .check();
  await page
    .getByLabel("policy.files.rules.0.effect", { exact: true })
    .selectOption("allow");
  await page
    .getByRole("cell", { name: "files.rules.input-read", exact: true })
    .waitFor();
  const source = JSON.parse(
    await page.getByLabel("Full policy source", { exact: true }).inputValue(),
  );
  assert.deepEqual(source.runtime.seccomp.allow_syscalls, []);
  assert.deepEqual(source.runtime_templates, []);
  assert.ok(source.required_capabilities.includes("fs.read.v1"));
  for (const section of [
    "programs",
    "network",
    "identity",
    "runtime",
    "evidence",
    "extensions",
    "runtime_templates",
    "defaults",
  ]) {
    await page
      .locator(`details.policy-section[data-section="${section}"] > summary`)
      .click();
  }
  await page.getByRole("button", { name: "Save full contract draft" }).click();
  await page
    .getByRole("heading", { name: "Explicit build policy", exact: true })
    .waitFor();
  assert.equal(saved.document.files.rules[0].selector.path, "/work/input");
  assert.equal(
    await page
      .getByText("Selected existing-file write opens denied", { exact: true })
      .count(),
    0,
  );
  await page
    .getByRole("button", { name: "Submit for approval", exact: true })
    .click();
  await page
    .locator("dialog")
    .getByRole("cell", { name: "exact: /work/input", exact: true })
    .waitFor();
  await page
    .getByLabel("Decision reason", { exact: true })
    .fill("Inspect the exact full policy document.");
  await page
    .getByLabel("I reviewed the exact version and rights.", { exact: true })
    .check();
  await page
    .getByRole("button", { name: "Confirm decision", exact: true })
    .click();
  await page.locator("dialog").waitFor({ state: "hidden" });
  assert.equal(
    await page
      .getByRole("button", { name: "Approve this version", exact: true })
      .isDisabled(),
    true,
  );
  await page
    .getByText("Verify an effective preview against a signed target report", {
      exact: true,
    })
    .click();
  for (const [label, value] of [
    ["Stored target report digest", "d".repeat(64)],
    ["Enrolled node", "fixture-node"],
    ["Current boot", "fixture-boot"],
    ["Preview reason", "Check this exact target."],
  ])
    await page.getByLabel(label, { exact: true }).fill(value);
  await page
    .getByRole("button", { name: "Check target compatibility", exact: true })
    .click();
  await page
    .getByText(
      "Required capability fs.rules.v1 is unqualified on this node and boot.",
      { exact: true },
    )
    .waitFor();
  await page.getByRole("button", { name: "New version", exact: true }).click();
  await page
    .getByRole("heading", { name: "Full policy builder", exact: true })
    .waitFor();
  await page
    .getByRole("cell", { name: "exact: /work/input", exact: true })
    .waitFor();
  const advanced = page.getByLabel("Full policy source", { exact: true });
  const modified = JSON.parse(await advanced.inputValue());
  modified.unknown = true;
  await advanced.fill(JSON.stringify(modified));
  assert.equal(
    await page
      .getByRole("button", { name: "Save full contract draft" })
      .isDisabled(),
    true,
  );
  await page
    .getByRole("button", {
      name: "Validate and apply full source",
      exact: true,
    })
    .click();
  await page
    .getByText("policy.unknown: additional properties are not allowed", {
      exact: true,
    })
    .waitFor();
  await page
    .getByRole("button", { name: "Discard source edits", exact: true })
    .click();
  await page
    .getByLabel("Full policy source format", { exact: true })
    .selectOption("yaml");
  await page
    .getByRole("button", {
      name: "Validate and apply full source",
      exact: true,
    })
    .click();
  await page
    .getByText(
      "The API validated this contract. Enforcement remains unqualified.",
      { exact: true },
    )
    .waitFor();
  await page.evaluate(() => scrollTo(0, 0));
  await page.screenshot({
    path: `${output}/full-policy-desktop.png`,
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  assert.ok(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  );
  await page.screenshot({
    path: `${output}/full-policy-mobile.png`,
    fullPage: true,
  });
  roles = ["viewer"];
  await page.reload();
  await page
    .getByRole("heading", { name: "Full policy builder", exact: true })
    .waitFor();
  assert.equal(
    await page
      .getByRole("button", { name: "Save full contract draft" })
      .isDisabled(),
    true,
  );
  assert.deepEqual(errors, []);
  const report = {
    status: "PASS",
    fixture: "isolated browser API fixture",
    schema_sections: true,
    deny_defaults: true,
    explicit_sources: true,
    full_document_save_and_reload: true,
    full_document_submit: true,
    unsupported_approval_disabled: true,
    target_rejection: true,
    advanced_unknown_field_rejection: true,
    yaml_validation: true,
    mobile: true,
    viewer_read_only: true,
    page_errors: errors,
  };
  await writeFile(
    `${output}/policy-workspace-report.json`,
    JSON.stringify(report, null, 2),
  );
  console.log(JSON.stringify(report));
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}
