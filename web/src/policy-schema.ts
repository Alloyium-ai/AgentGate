// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
export type Schema = {
  $ref?: string;
  type?: string;
  title?: string;
  description?: string;
  const?: unknown;
  enum?: (string | number | boolean)[];
  properties?: Record<string, Schema>;
  required?: string[];
  items?: Schema;
  minItems?: number;
  maxItems?: number;
  uniqueItems?: boolean;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  additionalProperties?: boolean;
  $defs?: Record<string, Schema>;
  oneOf?: Schema[];
  "x-section"?: string;
  "x-capability"?: string;
  "x-value-capabilities"?: Record<string, string>;
};
export type PolicyDocument = Record<string, any>;
export type PolicyContract = {
  schema: Schema;
  schema_digest: string;
  compiler_version: string;
  selected_profile: string;
  kernel_profile: string;
  default: string;
  admission_available: boolean;
  inventory_pending: boolean;
  capability_ids: string[];
  runtime_templates: unknown[];
};
export type FieldIssue = { path: string; message: string };

export function resolveSchema(schema: Schema, root: Schema): Schema {
  if (!schema.$ref) return schema;
  const name = schema.$ref.startsWith("#/$defs/") ? schema.$ref.slice(8) : "";
  const target = root.$defs?.[name];
  if (!target)
    throw new Error("The policy schema contains an unsupported reference.");
  return { ...target, ...schema, $ref: undefined };
}

export function initialValue(input: Schema, root: Schema): any {
  const schema = resolveSchema(input, root);
  if ("const" in schema) return schema.const;
  if (schema.enum)
    return schema.enum.includes("deny") ? "deny" : schema.enum[0];
  if (schema.type === "object")
    return Object.fromEntries(
      (schema.required || []).map((name) => [
        name,
        initialValue(schema.properties![name], root),
      ]),
    );
  if (schema.type === "array") return [];
  if (schema.type === "boolean") return false;
  if (schema.type === "integer") return schema.minimum ?? 0;
  return "";
}

export function requiredCapabilities(
  document: PolicyDocument,
  root: Schema,
): string[] {
  const result = new Set<string>();
  function visit(input: Schema, value: any) {
    const schema = resolveSchema(input, root);
    if (schema["x-capability"]) result.add(schema["x-capability"]!);
    const selected = schema["x-value-capabilities"]?.[String(value)];
    if (selected) result.add(selected);
    if (Array.isArray(value) && schema.items)
      value.forEach((item) => visit(schema.items!, item));
    else if (value && typeof value === "object")
      Object.entries(value).forEach(([name, item]) => {
        if (schema.properties?.[name]) visit(schema.properties[name], item);
      });
  }
  visit(root, document);
  return [...result].sort();
}

export function withRequirements(
  document: PolicyDocument,
  root: Schema,
): PolicyDocument {
  return {
    ...document,
    required_capabilities: requiredCapabilities(document, root),
  };
}

export function emptyKernelDocument(contract: PolicyContract): PolicyDocument {
  const branch = contract.schema.oneOf?.find(
    (branch) => branch.properties?.profile?.const === contract.kernel_profile,
  );
  if (!branch)
    throw new Error("The current schema has no full policy profile.");
  const names = new Set([
    ...(contract.schema.required || []),
    ...(branch.required || []),
  ]);
  const document = Object.fromEntries(
    [...names].map((name) => [
      name,
      initialValue(contract.schema.properties![name], contract.schema),
    ]),
  );
  document.profile = contract.kernel_profile;
  return withRequirements(document, contract.schema);
}

// This supplies field feedback. The API remains the authority for all policy validation.
export function fieldIssues(
  document: PolicyDocument,
  root: Schema,
): FieldIssue[] {
  const issues: FieldIssue[] = [];
  function visit(input: Schema, value: any, path: string) {
    const schema = resolveSchema(input, root);
    const add = (message: string) => issues.push({ path, message });
    if ("const" in schema && value !== schema.const)
      add(`Use ${String(schema.const)}.`);
    if (schema.enum && !schema.enum.includes(value))
      add("Select a registered value.");
    if (schema.type === "object") {
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        add("Supply an object.");
        return;
      }
      for (const name of schema.required || [])
        if (!(name in value))
          issues.push({
            path: `${path}.${name}`,
            message: "Supply this field.",
          });
      for (const [name, item] of Object.entries(value)) {
        if (schema.properties?.[name])
          visit(schema.properties[name], item, `${path}.${name}`);
        else if (schema.additionalProperties === false)
          issues.push({
            path: `${path}.${name}`,
            message: "This field is not registered.",
          });
      }
    }
    if (schema.type === "array") {
      if (!Array.isArray(value)) {
        add("Supply an array.");
        return;
      }
      if (value.length < (schema.minItems || 0))
        add(`Select at least ${schema.minItems} item(s).`);
      if (schema.maxItems !== undefined && value.length > schema.maxItems)
        add(`Use at most ${schema.maxItems} item(s).`);
      if (
        schema.uniqueItems &&
        new Set(value.map((item) => JSON.stringify(item))).size !== value.length
      )
        add("Remove duplicate items.");
      if (schema.items)
        value.forEach((item, i) => visit(schema.items!, item, `${path}.${i}`));
    }
    if (schema.type === "string") {
      if (typeof value !== "string") {
        add("Supply text.");
        return;
      }
      if (value.length < (schema.minLength || 0)) add("Supply this field.");
      if (schema.maxLength !== undefined && value.length > schema.maxLength)
        add(`Use at most ${schema.maxLength} characters.`);
      if (schema.pattern && !new RegExp(schema.pattern).test(value))
        add("Use the format in the policy schema.");
    }
    if (
      schema.type === "integer" &&
      (!Number.isInteger(value) ||
        (schema.minimum !== undefined && value < schema.minimum) ||
        (schema.maximum !== undefined && value > schema.maximum))
    )
      add(
        `Use an integer from ${schema.minimum ?? "the minimum"} to ${schema.maximum ?? "the maximum"}.`,
      );
    if (schema.type === "boolean" && typeof value !== "boolean")
      add("Supply true or false.");
  }
  visit(root, document, "policy");
  const branch = root.oneOf?.find(
    (branch) => branch.properties?.profile?.const === document.profile,
  );
  for (const name of branch?.required || [])
    if (!(name in document))
      issues.push({ path: `policy.${name}`, message: "Supply this section." });
  if (
    document.profile ===
      root.oneOf?.find((branch) => branch.required?.includes("files"))
        ?.properties?.profile?.const &&
    document.selected !== undefined
  )
    issues.push({
      path: "policy.selected",
      message: "Remove compatibility fields from the full profile.",
    });
  if (document.network?.rules)
    document.network.rules.forEach((rule: any, i: number) => {
      if (rule.port_to < rule.port_from)
        issues.push({
          path: `policy.network.rules.${i}.port_to`,
          message: "The last port must equal or exceed the first port.",
        });
    });
  (document.sockets?.rules || []).forEach((rule: any, i: number) => {
    if (rule.local && rule.local.port_to < rule.local.port_from)
      issues.push({
        path: `policy.sockets.rules.${i}.local.port_to`,
        message: "The last port must equal or exceed the first port.",
      });
    if (rule.effect !== "allow") return;
    if (
      (rule.operations || []).some((op: string) =>
        ["bind", "listen", "accept"].includes(op),
      ) &&
      !rule.local
    )
      issues.push({
        path: `policy.sockets.rules.${i}.local`,
        message: "Supply the explicit local selector.",
      });
    if (
      (rule.operations || []).some((op: string) =>
        ["get_option", "set_option"].includes(op),
      ) &&
      !rule.options?.length
    )
      issues.push({
        path: `policy.sockets.rules.${i}.options`,
        message: "Supply the explicit option level and name pairs.",
      });
  });
  return issues;
}

export function requestedAllowances(
  document: PolicyDocument,
): { resource: string; permission: string; source: string }[] {
  const rows: { resource: string; permission: string; source: string }[] = [];
  for (const [family, rules] of [
    ["files", document.files?.rules],
    ["programs", document.programs?.rules],
    ["network", document.network?.rules],
    ["sockets", document.sockets?.rules],
  ] as const) {
    (rules || []).forEach((rule: any) => {
      if (rule.effect !== "allow") return;
      rows.push({
        resource: rule.selector
          ? `${rule.selector.kind}: ${rule.selector.path}`
          : rule.destination
            ? `${rule.destination.kind}: ${rule.destination.value}`
            : family === "sockets"
              ? rule.local
                ? `${rule.local.address}:${rule.local.port_from}–${rule.local.port_to}`
                : `Owned ${rule.family} ${rule.protocol} sockets`
              : "Unspecified",
        permission:
          family === "files"
            ? rule.operations.join(", ")
            : family === "programs"
              ? rule.approval
                ? `Execute with observed argv[1] approval: ${rule.approval.argv1.join(", ")}; timeout ${rule.approval.timeout_seconds}s`
                : "Execute"
              : family === "sockets"
                ? `${rule.family} ${rule.protocol}: ${rule.operations.join(", ")}${rule.options?.length ? `; options ${rule.options.map((option: any) => `${option.level}/${option.name}`).join(", ")}` : ""}`
                : `${rule.family} ${rule.protocol} ${rule.port_from}–${rule.port_to}`,
        source: `${family}.rules.${rule.id || "unnamed"}`,
      });
    });
  }
  (document.runtime?.seccomp?.allow_syscalls || []).forEach((name: string) =>
    rows.push({
      resource: name,
      permission: "System call; resource checks also apply",
      source: "runtime.seccomp.allow_syscalls",
    }),
  );
  (document.runtime?.memory?.anonymous || []).forEach((operation: string) =>
    rows.push({
      resource: "Anonymous memory",
      permission: operation,
      source: "runtime.memory.anonymous",
    }),
  );
  if (document.runtime?.memory?.heap === "allow")
    rows.push({
      resource: "Process heap",
      permission: "Adjust heap break",
      source: "runtime.memory.heap",
    });
  (document.runtime?.ipc?.pipes || []).forEach((operation: string) =>
    rows.push({
      resource: "Job pipes",
      permission: operation,
      source: "runtime.ipc.pipes",
    }),
  );
  (document.runtime?.ipc?.eventfds || []).forEach((operation: string) =>
    rows.push({
      resource: "Job event descriptors",
      permission: operation,
      source: "runtime.ipc.eventfds",
    }),
  );
  (document.runtime?.signals || []).forEach((signal: number) =>
    rows.push({
      resource: `Linux signal ${signal}`,
      permission: "Signal targets within the same job domain",
      source: "runtime.signals",
    }),
  );
  const bootstrap = document.runtime?.bootstrap;
  const bootstrapScopes: Record<string, string> = {
    barrier_read: "one control read",
    listener_send: "transfer the measured exec listener",
    filter_finalize: "finalize the measured syscall filter",
    working_directory: "select the immutable working directory",
    credential_namespace: "enter the measured credential namespace",
  };
  (bootstrap?.operations || []).forEach((operation: string) =>
    rows.push({
      resource: `Measured held helper ${bootstrap.helper_digest}`,
      permission: `${operation}; ${bootstrapScopes[operation] || "unregistered helper operation"}; hold at most ${bootstrap.max_hold_seconds}s`,
      source: "runtime.bootstrap.operations",
    }),
  );
  return rows;
}

export function toPolicyYAML(value: any, depth = 0): string {
  const pad = "  ".repeat(depth);
  if (!value || typeof value !== "object" || !Object.keys(value).length)
    return JSON.stringify(value);
  const entries = Array.isArray(value)
    ? value.map((item) => ["-", item] as const)
    : Object.entries(value).map(
        ([key, item]) => [`${JSON.stringify(key)}:`, item] as const,
      );
  return entries
    .map(([key, item]) => {
      const nested =
        item && typeof item === "object" && Object.keys(item).length;
      return `${pad}${key}${nested ? `\n${toPolicyYAML(item, depth + 1)}` : ` ${JSON.stringify(item)}`}`;
    })
    .join("\n");
}
