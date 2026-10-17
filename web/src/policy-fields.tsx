// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
import React from "react";
import {
  FieldIssue,
  Schema,
  initialValue,
  resolveSchema,
} from "./policy-schema";
export const fieldLabel = (name: string) =>
  name.replaceAll("_", " ").replace(/^./, (char) => char.toUpperCase());

export function PolicyFields({
  schema: input,
  root,
  value,
  onChange,
  path,
  issues,
}: {
  schema: Schema;
  root: Schema;
  value: any;
  onChange: (value: any) => void;
  path: string;
  issues: FieldIssue[];
}) {
  const schema = resolveSchema(input, root);
  const title = schema.title || fieldLabel(path.split(".").at(-1)!);
  const id = path;
  const ownIssues = issues.filter((issue) => issue.path === path);
  const note = (
    <>
      {schema.description && <small>{schema.description}</small>}
      {ownIssues.map((issue) => (
        <small className="field-error" key={issue.message}>
          {issue.message}
        </small>
      ))}
    </>
  );
  if ("const" in schema)
    return (
      <div className="policy-constant" id={id}>
        <span>{title}</span>
        <strong>{String(schema.const)}</strong>
        {note}
      </div>
    );
  if (schema.type === "object")
    return (
      <fieldset id={id}>
        <legend>{title}</legend>
        {note}
        {Object.entries(schema.properties || {}).map(([name, child]) => {
          const childPath = `${path}.${name}`;
          const optional = !(schema.required || []).includes(name);
          const present = value && name in value;
          return (
            <div className="policy-field" key={name}>
              {optional && (
                <label className="check-row">
                  <input
                    aria-label={`Include ${childPath}`}
                    type="checkbox"
                    checked={Boolean(present)}
                    onChange={(event) => {
                      const next = { ...value };
                      if (event.target.checked)
                        next[name] = initialValue(child, root);
                      else delete next[name];
                      onChange(next);
                    }}
                  />
                  <span>Include {fieldLabel(name)}</span>
                </label>
              )}
              {(!optional || present) && (
                <PolicyFields
                  schema={child}
                  root={root}
                  value={value?.[name]}
                  onChange={(item) => onChange({ ...value, [name]: item })}
                  path={childPath}
                  issues={issues}
                />
              )}
            </div>
          );
        })}
      </fieldset>
    );
  if (schema.type === "array") {
    const items = Array.isArray(value) ? value : [];
    const itemSchema = schema.items
      ? resolveSchema(schema.items, root)
      : undefined;
    if (schema.maxItems === 0)
      return (
        <div id={id} className="policy-constant">
          <span>{title}</span>
          <strong>None permitted by this schema</strong>
          {note}
        </div>
      );
    if (itemSchema?.enum)
      return (
        <fieldset id={id}>
          <legend>
            {title} · {items.length} selected
          </legend>
          {note}
          <div className="policy-choices">
            {itemSchema.enum.map((option) => (
              <label className="check-row" key={String(option)}>
                <input
                  aria-label={`${path}: ${option}`}
                  type="checkbox"
                  checked={items.includes(option)}
                  onChange={(event) =>
                    onChange(
                      event.target.checked
                        ? [...items, option]
                        : items.filter((item) => item !== option),
                    )
                  }
                />
                <span>{String(option)}</span>
              </label>
            ))}
          </div>
          <p className="form-note">
            An empty selection permits no operation. Each choice is an explicit
            draft permission.
          </p>
        </fieldset>
      );
    return (
      <fieldset id={id}>
        <legend>
          {title} · {items.length} item(s)
        </legend>
        {note}
        {!items.length && <p className="form-note">No rule. No allowance.</p>}
        {items.map((item, index) => (
          <div className="policy-rule" key={index}>
            <div className="panel-title">
              <strong>
                {title} {index + 1}
              </strong>
              <button
                type="button"
                className="secondary"
                onClick={() => onChange(items.filter((_, i) => i !== index))}
              >
                Remove {title.toLowerCase()} {index + 1}
              </button>
            </div>
            {schema.items && (
              <PolicyFields
                schema={schema.items}
                root={root}
                value={item}
                onChange={(next) =>
                  onChange(
                    items.map((current, i) => (i === index ? next : current)),
                  )
                }
                path={`${path}.${index}`}
                issues={issues}
              />
            )}
          </div>
        ))}
        <button
          type="button"
          className="secondary"
          disabled={
            schema.maxItems !== undefined && items.length >= schema.maxItems
          }
          onClick={() =>
            onChange([...items, initialValue(schema.items!, root)])
          }
        >
          Add {title.toLowerCase()} item
        </button>
      </fieldset>
    );
  }
  if (schema.enum)
    return (
      <label htmlFor={id}>
        {title}
        <select
          id={id}
          aria-label={path}
          value={String(value)}
          aria-invalid={!!ownIssues.length}
          onChange={(event) =>
            onChange(
              schema.enum!.find((item) => String(item) === event.target.value),
            )
          }
        >
          {schema.enum.map((item) => (
            <option key={String(item)} value={String(item)}>
              {String(item)}
            </option>
          ))}
        </select>
        {note}
      </label>
    );
  if (schema.type === "boolean")
    return (
      <label className="check-row" htmlFor={id}>
        <input
          id={id}
          aria-label={path}
          type="checkbox"
          checked={Boolean(value)}
          onChange={(event) => onChange(event.target.checked)}
        />
        <span>
          {title}
          {note}
        </span>
      </label>
    );
  return (
    <label htmlFor={id}>
      {title}
      <input
        id={id}
        aria-label={path}
        type={schema.type === "integer" ? "number" : "text"}
        value={value ?? ""}
        aria-invalid={!!ownIssues.length}
        min={schema.minimum}
        max={schema.maximum}
        minLength={schema.minLength}
        maxLength={schema.maxLength}
        onChange={(event) =>
          onChange(
            schema.type === "integer"
              ? event.target.value === ""
                ? ""
                : Number(event.target.value)
              : event.target.value,
          )
        }
      />
      {note}
    </label>
  );
}
