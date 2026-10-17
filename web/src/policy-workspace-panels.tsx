// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
import React from "react";
import { ErrorBox } from "./components";
import { PolicyFields } from "./policy-fields";
import {
  FieldIssue,
  PolicyContract,
  PolicyDocument,
  emptyKernelDocument,
} from "./policy-schema";

export function DraftMetadata({
  parentID,
  name,
  setName,
  description,
  setDescription,
  hasParent,
  document,
  contract,
}: {
  parentID?: string;
  name: string;
  setName: (value: string) => void;
  description: string;
  setDescription: (value: string) => void;
  hasParent: boolean;
  document: PolicyDocument;
  contract: PolicyContract;
}) {
  return (
    <section className="panel">
      <h2>
        {parentID ? "Propose a new full document" : "Create a full document"}
      </h2>
      <label>
        Policy name
        <input
          value={name}
          onChange={(event) => setName(event.target.value)}
          required
          minLength={2}
          maxLength={100}
          readOnly={hasParent}
        />
      </label>
      <label>
        Description
        <textarea
          value={description}
          onChange={(event) => setDescription(event.target.value)}
          maxLength={1000}
          readOnly={hasParent}
        />
      </label>
      <p className="form-note">
        Schema {document.schema_version} · compiler {contract.compiler_version}
      </p>
      <details>
        <summary>Schema digest</summary>
        <code className="policy-digest">{contract.schema_digest}</code>
      </details>
    </section>
  );
}

export function GuidedPolicy({
  contract,
  document,
  dirty,
  issues,
  update,
}: {
  contract: PolicyContract;
  document: PolicyDocument;
  dirty: boolean;
  issues: FieldIssue[];
  update: (value: PolicyDocument) => void;
}) {
  const sections = Object.entries(contract.schema.properties || {}).filter(
    ([name]) =>
      name in document &&
      !["schema_version", "profile", "required_capabilities"].includes(name),
  );
  return (
    <section className="panel">
      <div className="panel-title">
        <h2>Guided draft fields</h2>
        <button
          className="secondary"
          type="button"
          disabled={dirty}
          onClick={() => {
            update(emptyKernelDocument(contract));
          }}
        >
          Reset document to deny
        </button>
      </div>
      <p className="form-note">
        A new rule starts with deny. Select allow only for an explicit request.
        Every field comes from the API schema.
      </p>
      <fieldset disabled={dirty} className="policy-form-shell">
        {sections.map(([name, schema]) => (
          <details
            className="policy-section"
            data-section={name}
            key={name}
            open={name === "files" || undefined}
          >
            <summary>
              {schema["x-section"] || name.replaceAll("_", " ")}
              <span>Draft fields · unqualified</span>
            </summary>
            <PolicyFields
              schema={{ ...schema, title: schema["x-section"] || name }}
              root={contract.schema}
              value={document[name]}
              onChange={(value) => update({ ...document, [name]: value })}
              path={`policy.${name}`}
              issues={issues}
            />
          </details>
        ))}
      </fieldset>
    </section>
  );
}

export function AdvancedPolicy({
  format,
  source,
  dirty,
  validated,
  onFormat,
  onSource,
  onApply,
  onDiscard,
}: {
  format: string;
  source: string;
  dirty: boolean;
  validated: boolean;
  onFormat: (value: string) => void;
  onSource: (value: string) => void;
  onApply: () => void;
  onDiscard: () => void;
}) {
  return (
    <section className="panel">
      <h2>Advanced JSON / YAML</h2>
      <p>
        Validate the source to apply it to the guided draft. The API rejects
        unknown fields, invalid defaults, and incorrect capability declarations.
      </p>
      <label>
        Full policy source format
        <select
          aria-label="Full policy source format"
          value={format}
          onChange={(event) => {
            onFormat(event.target.value);
          }}
        >
          <option value="json">JSON</option>
          <option value="yaml">YAML</option>
        </select>
      </label>
      <label>
        Full policy source
        <textarea
          aria-label="Full policy source"
          rows={18}
          spellCheck={false}
          value={source}
          onChange={(event) => {
            onSource(event.target.value);
          }}
        />
      </label>
      <div className="version-actions">
        <button
          type="button"
          className="secondary"
          onClick={onApply}
          disabled={!source.trim()}
        >
          Validate and apply full source
        </button>
        {dirty && (
          <button type="button" className="secondary" onClick={onDiscard}>
            Discard source edits
          </button>
        )}
      </div>
      {dirty && (
        <p role="status">
          The source differs from the guided draft. Validate and apply it before
          saving.
        </p>
      )}
      {validated && (
        <p role="status">
          The API validated this contract. Enforcement remains unqualified.
        </p>
      )}
    </section>
  );
}

export function SavePolicyDraft({
  reason,
  setReason,
  showIssues,
  issues,
  error,
  busy,
  disabled,
}: {
  reason: string;
  setReason: (value: string) => void;
  showIssues: boolean;
  issues: FieldIssue[];
  error: unknown;
  busy: boolean;
  disabled: boolean;
}) {
  return (
    <section className="panel">
      <label>
        Draft reason
        <textarea
          value={reason}
          onChange={(event) => setReason(event.target.value)}
          required
          minLength={3}
          maxLength={512}
        />
      </label>
      {showIssues && issues.length > 0 && (
        <div className="error-box" role="alert">
          <div>
            <strong>Complete the policy fields</strong>
            <ul>
              {issues.map((issue, i) => (
                <li key={i}>
                  <a
                    href={`#${issue.path}`}
                    onClick={(event) => {
                      event.preventDefault();
                      const element = window.document.getElementById(
                        issue.path,
                      );
                      let section = element?.parentElement;
                      while (section) {
                        if (section.tagName === "DETAILS")
                          section.setAttribute("open", "");
                        section = section.parentElement;
                      }
                      element?.scrollIntoView({ block: "center" });
                      element?.focus();
                    }}
                  >
                    {issue.path}
                  </a>
                  : {issue.message}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
      {Boolean(error) && <ErrorBox error={error} />}
      <button type="submit" disabled={disabled}>
        {busy ? "Saving validated draft…" : "Save full contract draft"}
      </button>
      <p className="form-note">
        The API validates every field and capability declaration before it
        stores this immutable version. Saving supplies no workload authority.
      </p>
    </section>
  );
}
