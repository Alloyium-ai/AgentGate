// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
import React, { useEffect, useState } from "react";
import { Actor, ApiError, Policy, Version, api, can } from "./api";
import { ErrorBox, Loading } from "./components";
import {
  AdvancedPolicy,
  DraftMetadata,
  GuidedPolicy,
  SavePolicyDraft,
} from "./policy-workspace-panels";
import { PolicyWorkflow } from "./policy-profile";
import {
  PolicyContract,
  PolicyDocument,
  emptyKernelDocument,
  fieldIssues,
  requestedAllowances,
  toPolicyYAML,
  withRequirements,
} from "./policy-schema";
import "./policy-workspace.css";

export type DocumentVersion = {
  purpose: string;
  document: PolicyDocument;
  version: Version;
  document_digest: string;
  schema_digest: string;
  compiler_version: string;
};
type ValidatedDocument = {
  purpose: string;
  document: PolicyDocument;
  schema_digest: string;
  admission_available: boolean;
};

export function usePolicyDocument(versionID?: string) {
  const [state, setState] = useState<{
    id?: string;
    document?: DocumentVersion;
    error?: unknown;
    loading: boolean;
  }>({ loading: false });
  useEffect(() => {
    let live = true;
    setState({ id: versionID, loading: Boolean(versionID) });
    if (versionID)
      api<DocumentVersion>(`policy-documents/${versionID}`)
        .then((document) => {
          if (live) setState({ id: versionID, document, loading: false });
        })
        .catch((error) => {
          if (live)
            setState({
              id: versionID,
              error:
                error instanceof ApiError && error.status === 404
                  ? undefined
                  : error,
              loading: false,
            });
        });
    return () => {
      live = false;
    };
  }, [versionID]);
  return state.id === versionID ? state : { loading: true };
}

export function RequestedPolicy({ document }: { document: PolicyDocument }) {
  const rows = requestedAllowances(document);
  return (
    <section
      aria-label="Requested permission preview"
      className="requested-policy"
    >
      <div className="panel-title">
        <h2>Requested permissions</h2>
        <span className="pill">Draft · unqualified</span>
      </div>
      <p>
        All registered operations, unmatched resources, and missing managed
        policy state default to deny.
      </p>
      <p className="form-note">
        This preview lists explicit draft allowances. A qualified target must
        verify each required capability before any effective policy can exist.
      </p>
      {rows.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Resource</th>
                <th>Requested permission</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={index}>
                  <td>{row.resource}</td>
                  <td>{row.permission}</td>
                  <td>
                    <code>{row.source}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="form-note">
          No file, program, network, or system call allowance is requested.
        </p>
      )}
      <p className="form-note">
        Deny rules and path specificity can further restrict these requests. No
        loader, library, read, DNS, or runtime permission is inherited.
      </p>
      <details>
        <summary>
          Required capabilities · {document.required_capabilities?.length || 0}
        </summary>
        <ul>
          {(document.required_capabilities || []).map((capability: string) => (
            <li key={capability}>
              <code>{capability}</code> · target qualification required
            </li>
          ))}
        </ul>
      </details>
    </section>
  );
}

export function TargetPreview({ versionID }: { versionID: string }) {
  const [target, setTarget] = useState({
    target_digest: "",
    node: "",
    boot: "",
    reason: "",
  });
  const [result, setResult] = useState<any>();
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  async function preview(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    setResult(undefined);
    try {
      setResult(
        await api("policy-preview", "POST", {
          ...target,
          version_id: versionID,
        }),
      );
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    setResult(undefined);
    setError(undefined);
  }, [versionID]);
  return (
    <details className="target-preview">
      <summary>
        Verify an effective preview against a signed target report
      </summary>
      <p>
        The API checks the stored document, enrolled node, boot, report
        freshness, and required capability qualification.
      </p>
      <form onSubmit={preview}>
        <fieldset disabled={busy}>
          {(
            [
              ["target_digest", "Stored target report digest"],
              ["node", "Enrolled node"],
              ["boot", "Current boot"],
              ["reason", "Preview reason"],
            ] as const
          ).map(([name, title]) => (
            <label key={name}>
              {title}
              <input
                aria-label={title}
                value={target[name]}
                onChange={(event) => {
                  setTarget({ ...target, [name]: event.target.value });
                  setResult(undefined);
                  setError(undefined);
                }}
                required
                minLength={name === "reason" ? 3 : 1}
              />
            </label>
          ))}
          <button type="submit">
            {busy ? "Checking target…" : "Check target compatibility"}
          </button>
        </fieldset>
      </form>
      {Boolean(error) && <ErrorBox error={error} />}
      {result && (
        <div role="status">
          <p>
            Validation preview only. Workload admission remains unavailable.
          </p>
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}
    </details>
  );
}

export function PolicyWorkspace({
  actor,
  parentID,
  navigate,
  refresh,
}: {
  actor: Actor;
  parentID?: string;
  navigate: (path: string) => void;
  refresh: () => void;
}) {
  const [contract, setContract] = useState<PolicyContract>();
  const [document, setDocument] = useState<PolicyDocument>();
  const [family, setFamily] = useState<Policy>();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const [format, setFormat] = useState("json");
  const [source, setSource] = useState("");
  const [dirty, setDirty] = useState(false);
  const [validated, setValidated] = useState(false);
  const [showIssues, setShowIssues] = useState(false);
  const writable = can(actor, "editor");
  useEffect(() => {
    let live = true;
    setContract(undefined);
    setDocument(undefined);
    setError(undefined);
    setFamily(undefined);
    setName("");
    setDescription("");
    setReason("");
    setValidated(false);
    setDirty(false);
    (async () => {
      const current = await api<PolicyContract>("policy-schema");
      let draft = emptyKernelDocument(current);
      if (parentID) {
        const parent = await api<DocumentVersion>(
          `policy-documents/${parentID}`,
        );
        if (
          parent.schema_digest !== current.schema_digest ||
          parent.document.profile !== current.kernel_profile
        )
          throw new Error(
            "This parent requires its original full policy schema.",
          );
        const policy = await api<Policy>(
          `policies/${parent.version.policy_id}`,
        );
        if (!live) return;
        setFamily(policy);
        setName(policy.name);
        setDescription(policy.description);
        draft = parent.document;
      }
      if (live) {
        setContract(current);
        setDocument(draft);
      }
    })().catch((error) => {
      if (live) setError(error);
    });
    return () => {
      live = false;
    };
  }, [parentID]);
  useEffect(() => {
    if (document && !dirty)
      setSource(
        format === "yaml"
          ? toPolicyYAML(document)
          : JSON.stringify(document, null, 2),
      );
  }, [document, format, dirty]);
  function update(next: PolicyDocument) {
    setDocument(withRequirements(next, contract!.schema));
    setValidated(false);
    setError(undefined);
  }
  async function validateSource() {
    setBusy(true);
    setError(undefined);
    setValidated(false);
    try {
      const result = await api<ValidatedDocument>("policy-validate", "POST", {
        format,
        source,
        schema_digest: contract!.schema_digest,
        reason: "Validate the full policy draft without authorizing a workload",
      });
      if (
        result.purpose !== "contract-validation" ||
        result.schema_digest !== contract!.schema_digest ||
        result.document.profile !== contract!.kernel_profile ||
        result.admission_available !== false
      )
        throw new Error(
          "The validation response does not match this draft contract.",
        );
      setDocument(result.document);
      setDirty(false);
      setValidated(true);
      setShowIssues(false);
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  async function save(event: React.FormEvent) {
    event.preventDefault();
    setShowIssues(true);
    setError(undefined);
    if (dirty || fieldIssues(document!, contract!.schema).length) return;
    setBusy(true);
    try {
      const result = await api<DocumentVersion>("policy-documents", "POST", {
        name,
        description,
        parent_id: parentID,
        format: "json",
        source: JSON.stringify(document),
        schema_digest: contract!.schema_digest,
        reason,
      });
      if (
        result.purpose !== "contract-draft" ||
        result.schema_digest !== contract!.schema_digest
      )
        throw new Error("The API did not retain this draft contract.");
      refresh();
      navigate(`policies/${result.version.policy_id}`);
    } catch (error) {
      setError(error);
    } finally {
      setBusy(false);
    }
  }
  if (!contract || !document)
    return error ? <ErrorBox error={error} /> : <Loading />;
  const issues = fieldIssues(document, contract.schema);
  return (
    <div className="policy-workspace">
      <button className="back-link" onClick={() => navigate("policies")}>
        ← Policy library
      </button>
      <div className="section-title">
        <div>
          <span className="eyebrow">DENY BY DEFAULT</span>
          <h1>Full policy builder</h1>
          <p>
            Describe every explicit permission in one versioned policy document.
          </p>
        </div>
        <span className="pill">Draft authoring · admission blocked</span>
      </div>
      <div className="fixture-banner">
        This engine remains unqualified. You can validate, save, and submit a
        contract draft. Approval, publication, grants, and runs remain blocked.
      </div>
      <PolicyWorkflow />
      <div className="panel">
        <div className="panel-title">
          <h2>Runtime templates</h2>
          <span className="pill">None qualified</span>
        </div>
        <p>
          No reviewed runtime template is available. No permission is inherited.
          Add each required file, executable, and system call explicitly.
        </p>
        <p className="form-note">
          The schema registers draft fields. It does not prove that a target
          enforces them. Kernel inventory:{" "}
          {contract.inventory_pending
            ? "pending"
            : "available through signed reports"}
          .
        </p>
      </div>
      <form onSubmit={save} noValidate={false}>
        <fieldset disabled={busy || !writable} className="policy-form-shell">
          <DraftMetadata
            parentID={parentID}
            name={name}
            setName={setName}
            description={description}
            setDescription={setDescription}
            hasParent={Boolean(family)}
            document={document}
            contract={contract}
          />
          <GuidedPolicy
            contract={contract}
            document={document}
            dirty={dirty}
            issues={showIssues ? issues : []}
            update={update}
          />
          <AdvancedPolicy
            format={format}
            source={source}
            dirty={dirty}
            validated={validated}
            onFormat={(value) => {
              setFormat(value);
              if (dirty) setValidated(false);
            }}
            onSource={(value) => {
              setSource(value);
              setDirty(true);
              setValidated(false);
              setError(undefined);
            }}
            onApply={validateSource}
            onDiscard={() => {
              setDirty(false);
              setError(undefined);
            }}
          />
          <section className="panel">
            <RequestedPolicy document={document} />
          </section>
          <SavePolicyDraft
            reason={reason}
            setReason={setReason}
            showIssues={showIssues}
            issues={issues}
            error={error}
            busy={busy}
            disabled={dirty || !name.trim() || !reason.trim()}
          />
        </fieldset>
      </form>
      {!writable && (
        <p className="form-note">
          Your role permits inspection. An editor can save a policy draft.
        </p>
      )}
    </div>
  );
}
