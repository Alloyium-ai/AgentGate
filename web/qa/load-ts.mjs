// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// loadTS transpiles first-party TypeScript modules from web/src into a fresh
// private temporary directory and imports them, so node tests run the exact
// source the browser bundle uses. Relative imports between the listed
// modules are rewritten to the transpiled files; nothing else is resolved.
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import ts from "typescript";

export async function loadTS(...names) {
  const dir = await mkdtemp(join(tmpdir(), "agentgate-web-qa-"));
  try {
    for (const name of names) {
      const source = await readFile(new URL(`../src/${name}.ts`, import.meta.url), "utf8");
      let out = ts.transpileModule(source, {
        compilerOptions: { module: ts.ModuleKind.ES2022, target: ts.ScriptTarget.ES2022 },
      }).outputText;
      out = out.replace(/from\s+"\.\/([a-z0-9-]+)"/g, (whole, dep) => {
        if (!names.includes(dep)) throw new Error(`${name}.ts imports ./${dep}, which the test did not load`);
        return `from "./${dep}.mjs"`;
      });
      await writeFile(join(dir, `${name}.mjs`), out, { mode: 0o600 });
    }
    const modules = {};
    for (const name of names) Object.assign(modules, await import(pathToFileURL(join(dir, `${name}.mjs`)).href));
    return modules;
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
