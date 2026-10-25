// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Shared pieces of the provisioning pages: honest enforcement notices, state
// badges, one-time secrets, copy buttons, confirmation dialogs and the
// "What can this agent do?" panel.

import React, { useEffect, useId, useRef, useState } from "react";
import { AlertTriangle, Check, Copy, ShieldAlert, ShieldOff } from "lucide-react";
import { Badge, ErrorBox, Modal } from "./components";
import { KERNEL_UNVERIFIED, PolicyDocument } from "./prov-api";
import { DiffRow, Risk, rows, sentences } from "./access-model";

export function KernelNotice({ compact = false }: { compact?: boolean }) {
  if (compact)
    return (
      <span className="kernel-flag" title="kernel_verified: false">
        <ShieldOff size={14} aria-hidden="true" /> {KERNEL_UNVERIFIED}
      </span>
    );
  return (
    <div className="kernel-notice" role="note">
      <ShieldOff size={19} aria-hidden="true" />
      <div>
        <strong>{KERNEL_UNVERIFIED}</strong>
        <p>
          kernel verified: no. The host is asked to enforce this policy with its BPF LSM programs, but no verification
          report signed by an independent authority exists yet, so the API reports <code>kernel_verified: false</code>.
          Treat every permission shown here as what was requested, not as proven behavior.
        </p>
      </div>
    </div>
  );
}

const stateText: Record<string, string> = {
  approval_pending: "Waiting for approval",
  awaiting_key_approval: "Awaiting host key approval",
  rekey_required: "Re-enrollment required",
  retiring: "Retiring: removing secrets",
};
const stateTone: Record<string, string> = {
  active: "allowed",
  running: "allowed",
  stopped: "committed",
  approved: "approved",
  queued: "pending",
  provisioning: "pending",
  requested: "pending",
  approval_pending: "pending",
  awaiting_key_approval: "pending",
  pending: "pending",
  stopping: "pending",
  deleting: "pending",
  retiring: "pending",
  stored: "allowed",
  rekey_required: "denied",
  failed: "denied",
  rejected: "denied",
  expired: "incomplete",
  cancelled: "incomplete",
  retired: "",
  deleted: "",
};
export function StateBadge({ state }: { state: string }) {
  return <span className={`badge state ${stateTone[state] ?? ""}`}>{stateText[state] || state.replaceAll("_", " ")}</span>;
}

export function RiskBadge({ risk }: { risk: Risk }) {
  const label = { low: "Low risk", medium: "Medium risk", high: "High risk", protective: "Restricts access" }[risk];
  return <span className={`badge risk-${risk}`}>{label}</span>;
}

export function LiveRegion({ message }: { message: string }) {
  return (
    <div className="sr-only" role="status" aria-live="polite" aria-atomic="true">
      {message}
    </div>
  );
}

export function CopyButton({ text, label = "Copy", className = "secondary" }: { text: string; label?: string; className?: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  useEffect(() => {
    if (state === "idle") return;
    const t = setTimeout(() => setState("idle"), 2500);
    return () => clearTimeout(t);
  }, [state]);
  return (
    <>
      <button
        type="button"
        className={className}
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(text);
            setState("copied");
          } catch {
            setState("failed");
          }
        }}
      >
        {state === "copied" ? <Check size={15} aria-hidden="true" /> : <Copy size={15} aria-hidden="true" />}
        {state === "copied" ? "Copied" : label}
      </button>
      <span className="sr-only" role="status" aria-live="polite">
        {state === "copied" ? "Copied to the clipboard" : state === "failed" ? "Copy failed. Select the text and copy it." : ""}
      </span>
    </>
  );
}

export function Digest({ value, label }: { value?: string; label?: string }) {
  if (!value) return <span className="muted">—</span>;
  return (
    <span className="digest">
      <code title={value} aria-label={label ? `${label} ${value}` : value}>
        {value.length > 24 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value}
      </code>
      <CopyButton text={value} label="Copy" className="icon-copy" />
    </span>
  );
}

// OneTimeSecret shows a value the service returns once (an enrollment token,
// an API token). The parent drops it from state when the dialog closes.
export function OneTimeSecret({ label, value, note }: { label: string; value: string; note: string }) {
  const id = useId();
  return (
    <div className="one-time">
      <div className="one-time-head">
        <AlertTriangle size={17} aria-hidden="true" />
        <strong>Shown once.</strong> <span>{note}</span>
      </div>
      <label htmlFor={id}>{label}</label>
      <div className="one-time-row">
        <input id={id} readOnly value={value} spellCheck={false} autoComplete="off" onFocus={(e) => e.currentTarget.select()} />
        <CopyButton text={value} />
      </div>
    </div>
  );
}

export function CodeBlock({ text, label }: { text: string; label: string }) {
  return (
    <div className="code-block">
      <div className="code-block-head">
        <span>{label}</span>
        <CopyButton text={text} />
      </div>
      <pre tabIndex={0} aria-label={label}>
        {text}
      </pre>
    </div>
  );
}

// ConfirmDialog asks for a reason (3 to 512 characters, as every mutating
// endpoint requires) and, for destructive actions, for the exact name.
export function ConfirmDialog({
  title,
  children,
  confirmLabel,
  danger = false,
  typeToConfirm,
  defaultReason = "",
  onClose,
  onConfirm,
}: {
  title: string;
  children?: React.ReactNode;
  confirmLabel: string;
  danger?: boolean;
  typeToConfirm?: string;
  defaultReason?: string;
  onClose: () => void;
  onConfirm: (reason: string) => Promise<void>;
}) {
  const [reason, setReason] = useState(defaultReason);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const ready = reason.trim().length >= 3 && reason.length <= 512 && (!typeToConfirm || typed === typeToConfirm);
  return (
    <Modal title={title} onClose={onClose}>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          if (!ready) return;
          setBusy(true);
          setError(undefined);
          try {
            await onConfirm(reason.trim());
          } catch (cause) {
            setError(cause);
          } finally {
            setBusy(false);
          }
        }}
      >
        {children}
        <label>
          Reason
          <textarea autoFocus value={reason} onChange={(e) => setReason(e.target.value)} required minLength={3} maxLength={512} placeholder="Recorded in the audit log with your identity." />
        </label>
        {typeToConfirm && (
          <label>
            Type <code>{typeToConfirm}</code> to confirm
            <input value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />
          </label>
        )}
        {Boolean(error) && <ErrorBox error={error} />}
        <div className="modal-actions">
          <button type="button" className="secondary" onClick={onClose}>
            Cancel
          </button>
          <button className={danger ? "danger-solid" : ""} disabled={busy || !ready}>
            {busy ? "Working…" : confirmLabel}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// Gate renders an action button that is disabled with a visible reason when
// the actor may not use it. The service enforces the same rule.
export function Gate({ allowed, reason, children, onClick, className, type = "button" }: { allowed: boolean; reason?: string; children: React.ReactNode; onClick?: () => void; className?: string; type?: "button" | "submit" }) {
  const id = useId();
  return (
    <span className="gate">
      <button type={type} className={className} disabled={!allowed} aria-describedby={!allowed && reason ? id : undefined} onClick={onClick}>
        {children}
      </button>
      {!allowed && reason && (
        <small id={id} className="gate-reason">
          {reason}
        </small>
      )}
    </span>
  );
}

export function Issues({ issues, field }: { issues: { field: string; message: string }[]; field: string }) {
  const list = issues.filter((i) => i.field === field || i.field.startsWith(field + "."));
  if (!list.length) return null;
  return (
    <ul className="field-issues" role="alert">
      {list.map((i, n) => (
        <li key={n}>{i.message}</li>
      ))}
    </ul>
  );
}

// ServerMessages shows validator output exactly as the service returned it.
export function ServerMessages({ title, items, tone = "info" }: { title: string; items?: string[] | null; tone?: "info" | "warn" }) {
  if (!items?.length) return null;
  return (
    <div className={`server-messages ${tone}`}>
      <strong>{title}</strong>
      <ul>
        {items.map((m, i) => (
          <li key={i}>
            <code className="verbatim">{m}</code>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function AccessSummary({ doc, title = "What can this agent do?" }: { doc?: PolicyDocument; title?: string }) {
  const [json, setJSON] = useState(false);
  if (!doc) return null;
  const list = rows(doc);
  return (
    <section className="panel access-summary" aria-label={title}>
      <div className="panel-title">
        <h2>{title}</h2>
        <ShieldAlert size={19} aria-hidden="true" />
      </div>
      <ul className="plain-summary">
        {sentences(doc).map((s, i) => (
          <li key={i}>{s}</li>
        ))}
      </ul>
      <div className="table-wrap">
        <table>
          <caption className="sr-only">{title} — each permission, its value, what it means and its risk</caption>
          <thead>
            <tr>
              <th scope="col">Area</th>
              <th scope="col">Permission</th>
              <th scope="col">Value</th>
              <th scope="col">What it means</th>
              <th scope="col">Risk</th>
            </tr>
          </thead>
          <tbody>
            {list.map((r, i) => (
              <tr key={i}>
                <td>{r.area}</td>
                <td>
                  <strong>{r.permission}</strong>
                </td>
                <td>
                  <code className="verbatim">{r.value}</code>
                </td>
                <td className="reason-cell">{r.meaning}</td>
                <td>
                  <RiskBadge risk={r.risk} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <button type="button" className="text-button" aria-expanded={json} onClick={() => setJSON(!json)}>
        {json ? "Hide policy JSON" : "Show policy JSON"}
      </button>
      {json && (
        <pre className="policy-json" tabIndex={0} aria-label="Policy JSON (read-only)">
          {JSON.stringify(doc, null, 2)}
        </pre>
      )}
      <p className="form-note">This describes the requested policy. {KERNEL_UNVERIFIED.toLowerCase()}.</p>
    </section>
  );
}

export function DiffTable({ rows: list, empty = "No permission changed." }: { rows: DiffRow[]; empty?: string }) {
  if (!list.length) return <p className="form-note">{empty}</p>;
  return (
    <div className="table-wrap">
      <table className="diff-table">
        <caption className="sr-only">Permission changes</caption>
        <thead>
          <tr>
            <th scope="col">Area</th>
            <th scope="col">Field</th>
            <th scope="col">Change</th>
            <th scope="col">Before</th>
            <th scope="col">After</th>
          </tr>
        </thead>
        <tbody>
          {list.map((r, i) => (
            <tr key={i} className={`diff-${r.change}`}>
              <td>{r.area}</td>
              <td>{r.field}</td>
              <td>
                <span className={`badge change-${r.change}`}>{r.change === "added" ? "+ added" : r.change === "removed" ? "− removed" : "~ changed"}</span>
              </td>
              <td>
                <code className="verbatim">{r.before ?? ""}</code>
              </td>
              <td>
                <code className="verbatim">{r.after ?? ""}</code>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// useFocusOnMount moves keyboard focus to a heading when a view opens, so
// screen reader users hear where they are after navigation.
export function useFocusHeading<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  useEffect(() => {
    ref.current?.focus();
  }, []);
  return ref;
}

export function Capabilities({ caps }: { caps: string[] }) {
  const label: Record<string, string> = {
    docker: "Docker host",
    appliance: "Appliance VM",
    "bpf-lsm": "Kernel BPF LSM (advertised)",
    "live-mounts": "Live host folders",
    "snapshot-mounts": "Snapshot folders",
    broker: "Credential broker (old name)",
    "brokered-secrets": "Brokered secrets",
    "pocpolicy-v2": "Filesystem and process policy",
  };
  if (!caps?.length) return <span className="muted">none reported</span>;
  return (
    <span className="chips">
      {caps.map((c) => (
        <span className="chip" key={c} title={c}>
          {label[c] || c}
        </span>
      ))}
    </span>
  );
}

export { Badge };
