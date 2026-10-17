// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

import React, { useEffect, useState } from "react";
import { api, Rights } from "./api";
import { ErrorBox, Loading } from "./components";

type Field = { type?: string; title?: string; description?: string; minLength?: number; maxLength?: number; minimum?: number; maximum?: number; pattern?: string; "x-capability"?: string };
type Contract = { schema: { properties: { schema_version: { const: string } }; $defs: { selected: { properties: Record<string, Field> } } }; schema_digest: string; selected_profile: string };
type Validated = { purpose: string; schema_digest: string; document: { selected: Rights } };

export function CustomerPolicyEditor({ rights, onChange, onReady }: { rights: Rights; onChange: (value: Rights) => void; onReady: (ready: boolean) => void }) {
  const [contract, setContract] = useState<Contract>();
  const [error, setError] = useState<unknown>();
  const [source, setSource] = useState("");
  const [format, setFormat] = useState("json");
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let live = true;
    onReady(false);
    api<Contract>("policy-schema").then(value => { if (live) setContract(value); }).catch(error => { if (live) setError(error); });
    return () => { live = false; };
  }, []);
  useEffect(() => {
    if (!contract || dirty) return;
    if (Object.values(contract.schema.$defs.selected.properties).some(field => !["boolean", "string", "integer"].includes(field.type || ""))) { onReady(false); return; }
    const capabilities = [...new Set(Object.values(contract.schema.$defs.selected.properties).map(field => field["x-capability"]).filter(Boolean))].sort();
    setSource(JSON.stringify({ schema_version: contract.schema.properties.schema_version.const, profile: contract.selected_profile, required_capabilities: capabilities, selected: rights }, null, 2));
    onReady(true);
  }, [contract, rights, dirty]);
  async function apply() {
    if (!contract) return;
    setBusy(true); setError(undefined);
    try {
      const result = await api<Validated>("policy-validate", "POST", { format, source, schema_digest: contract.schema_digest, reason: "Validate and apply the advanced policy source" });
      if (result.schema_digest !== contract.schema_digest || result.purpose !== "document-validation" || !result.document.selected) throw new Error("The policy contract changed. Reopen the editor.");
      onChange(result.document.selected); setDirty(false); onReady(true);
    } catch (error) { setError(error); onReady(false); }
    finally { setBusy(false); }
  }
  if (!contract) return error ? <ErrorBox error={error} /> : <Loading />;
  const fields = contract.schema.$defs.selected.properties;
  if (Object.values(fields).some(field => !["boolean", "string", "integer"].includes(field.type || ""))) return <ErrorBox error={new Error("This schema requires a newer guided editor.")} />;
  return <>
    <fieldset aria-label="Guided policy fields">
      <legend>Compatibility declarations · inspection-only</legend>
      {Object.entries(fields).map(([name, field]) => {
        const value = rights[name as keyof Rights];
        return <label className={field.type === "boolean" ? "check-row" : ""} key={name}>
          {field.type === "boolean" ? <>
            <input type="checkbox" checked={Boolean(value)} onChange={event => onChange({ ...rights, [name]: event.target.checked })} />
            <span>{field.title}<small>{field.description}</small></span>
          </> : <>
            {field.title}
            <input aria-label={field.title} type={field.type === "integer" ? "number" : "text"} value={String(value)} required min={field.minimum} max={field.maximum} minLength={field.minLength} maxLength={field.maxLength} pattern={field.pattern} onChange={event => onChange({ ...rights, [name]: field.type === "integer" ? Number(event.target.value) : event.target.value })} />
            <small>{field.description}</small>
          </>}
        </label>;
      })}
      <p className="form-note">These compatibility declarations do not authorize a workload. Full policy defaults deny every controllable operation.</p>
    </fieldset>
    <details className="advanced-policy">
      <summary>Advanced JSON / YAML policy editor</summary>
      <p className="form-note">This editor exposes the same inspection fields as the guided form. It grants no read or runtime permission. Unsupported fields and unqualified profiles are rejected.</p>
      <label>Policy source format<select aria-label="Policy source format" value={format} onChange={event => { setFormat(event.target.value); setDirty(true); onReady(false); }}><option value="json">JSON</option><option value="yaml">YAML</option></select></label>
      <label>Policy source<textarea aria-label="Policy source" value={source} rows={12} spellCheck={false} onChange={event => { setSource(event.target.value); setDirty(true); onReady(false); }} /></label>
      <button type="button" className="secondary" disabled={busy || !source.trim()} onClick={apply}>{busy ? "Validating…" : "Validate and apply source"}</button>
      {dirty && <p className="form-note">Apply the validated source before saving this draft.</p>}
      {Boolean(error) && <ErrorBox error={error} />}
    </details>
  </>;
}
