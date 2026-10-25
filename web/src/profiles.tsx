// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Access profiles: named, immutable, digest-addressed policy versions. Every
// change rolls forward to a new version through the typed grants endpoint;
// a stored version never changes.

import React, { useMemo, useState } from "react";
import { ArrowLeft, History, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { Actor, ApiError, api, when } from "./api";
import { Empty, ErrorBox, Loading, Modal, SectionTitle } from "./components";
import { GrantEdit, GrantResult, Items, Preset, Profile, ProfileVersion, permissions, roleText, useResource } from "./prov-api";
import { AccessSummary, ConfirmDialog, DiffTable, Digest, Gate, KernelNotice, LiveRegion, RiskBadge, ServerMessages } from "./prov-components";
import { DEVICES, EXPLAIN, MOUNT_ROOT, SIGNALS, WEB_PROTOCOLS, describeEdit, diffDocuments, editIssue, mountsOf, webLabel, webOf } from "./access-model";
import { ClientPager, useClientPages } from "./prov-paging";

const NAME = /^[a-z0-9][a-z0-9-]{0,39}$/;
type Presets = { items: Preset[]; actions: string[]; revoke_kinds: string[] };

function CreateProfile({ actor, onClose, onDone }: { actor: Actor; onClose: () => void; onDone: (name: string) => void }) {
  const p = permissions(actor);
  const presets = useResource<Presets>("access-presets");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [source, setSource] = useState("preset");
  const [preset, setPreset] = useState("");
  const [requireApproval, setRequireApproval] = useState(true);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const chosen = presets.data?.items.find((x) => x.name === preset);
  const ready = NAME.test(name) && reason.trim().length >= 3 && (source !== "preset" || Boolean(preset));
  return (
    <Modal title="Create an access profile" onClose={onClose}>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(undefined);
          try {
            const body: Record<string, unknown> = { name, description, reason };
            if (source === "preset") body.preset = preset;
            if (!requireApproval) body.require_approval = false;
            await api("profiles", "POST", body);
            onDone(name);
          } catch (cause) {
            setError(cause);
          } finally {
            setBusy(false);
          }
        }}
      >
        <label>
          Profile name
          <input autoFocus value={name} onChange={(e) => setName(e.target.value)} required pattern="[a-z0-9][a-z0-9\-]{0,39}" maxLength={40} placeholder="python-dev" />
        </label>
        <label>
          Description
          <textarea value={description} onChange={(e) => setDescription(e.target.value)} maxLength={1000} placeholder="When to use this profile" />
        </label>
        <fieldset>
          <legend>Start from</legend>
          <label className="check-row">
            <input type="radio" name="source" checked={source === "preset"} onChange={() => setSource("preset")} />
            <span>A preset (web, filesystem and process sections from a named starting point)</span>
          </label>
          <label className="check-row">
            <input type="radio" name="source" checked={source === "example"} onChange={() => setSource("example")} />
            <span>The shipped example policy (policy.full.example.json: HTTP, HTTPS and QUIC, workspace and /tmp writable)</span>
          </label>
          {source === "preset" &&
            (presets.error ? (
              <ErrorBox error={presets.error} />
            ) : (
              <label>
                Preset
                <select value={preset} onChange={(e) => setPreset(e.target.value)} required>
                  <option value="">Choose a preset</option>
                  {presets.data?.items.map((x) => (
                    <option key={x.name} value={x.name}>
                      {x.name}
                    </option>
                  ))}
                </select>
              </label>
            ))}
          {chosen && (
            <div className="preset-card">
              <p>{chosen.description}</p>
              <p className="form-note">
                Public web: {chosen.web.length ? chosen.web.join(", ") : "none"} · writable: {[chosen.filesystem.workspace, ...chosen.filesystem.scratch].join(", ")} · execute:{" "}
                {chosen.filesystem.execute.join(", ")}
              </p>
            </div>
          )}
        </fieldset>
        <label className="check-row">
          <input type="checkbox" checked={requireApproval} disabled={!p.profilesAdmin} onChange={(e) => setRequireApproval(e.target.checked)} aria-describedby="approval-help" />
          <span>
            Launches of this profile need a second person's approval
            <small id="approval-help">
              {p.profilesAdmin
                ? "Turning this off approves version 1 as you create it: a launcher may start that version alone, unless the launch needs approval for another reason. Later versions need a second person until an administrator approves one."
                : `New profiles always require approval. Only an administrator can create one that skips it (your roles: ${roleText(actor)}).`}
            </small>
          </span>
        </label>
        <label>
          Reason
          <textarea value={reason} onChange={(e) => setReason(e.target.value)} required minLength={3} maxLength={512} />
        </label>
        {Boolean(error) && <ErrorBox error={error} />}
        <div className="modal-actions">
          <button type="button" className="secondary" onClick={onClose}>
            Cancel
          </button>
          <button disabled={busy || !ready}>{busy ? "Creating…" : "Create version 1"}</button>
        </div>
      </form>
    </Modal>
  );
}

export function Profiles({ actor, epoch, navigate }: { actor: Actor; epoch: number; navigate: (p: string) => void }) {
  const p = permissions(actor);
  const { data, error, loading } = useResource<Items<Profile>>("profiles", epoch);
  const [creating, setCreating] = useState(false);
  const [search, setSearch] = useState("");
  const items = (data?.items || []).filter((x) => (x.name + " " + x.description).toLowerCase().includes(search.toLowerCase()));
  const pages = useClientPages(items, 25);
  return (
    <>
      <SectionTitle
        eyebrow="ACCESS"
        title="Access profiles"
        text="Each profile is a chain of immutable versions. A launch names one exact version; editing creates the next version and never changes a running launch."
        action={
          <Gate allowed={p.editProfiles} reason={`Creating profiles needs the editor role. Your roles: ${roleText(actor)}.`} onClick={() => setCreating(true)}>
            <Plus size={17} aria-hidden="true" /> New profile
          </Gate>
        }
      />
      <div className="table-toolbar">
        <label className="search">
          <input placeholder="Search profiles" aria-label="Search profiles" value={search} onChange={(e) => setSearch(e.target.value)} />
        </label>
        <span>{items.length} profiles</span>
      </div>
      {error ? (
        <ErrorBox error={error} />
      ) : loading ? (
        <Loading />
      ) : !items.length ? (
        <Empty title="No access profiles" text="Create a profile from a preset, then grant or revoke access with typed edits." />
      ) : (
        <div className="table-wrap">
          <table>
            <caption className="sr-only">Access profiles</caption>
            <thead>
              <tr>
                <th scope="col">Profile</th>
                <th scope="col">Latest version</th>
                <th scope="col">Launch approval</th>
                <th scope="col">Created</th>
              </tr>
            </thead>
            <tbody>
              {pages.items.map((x) => (
                <tr key={x.id}>
                  <td>
                    <button className="row-link" onClick={() => navigate(`profiles/${x.name}`)}>
                      {x.name}
                    </button>
                    <small>{x.description || "No description"}</small>
                  </td>
                  <td>v{x.latest_version}</td>
                  <td>
                    {!x.require_approval && x.approved_version ? (
                      <span className="badge">Launcher may start v{x.approved_version} alone</span>
                    ) : (
                      <span className="badge pending">Second person required</span>
                    )}
                  </td>
                  <td>
                    {when(x.created_at)}
                    <small>{x.created_by}</small>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <ClientPager {...pages} bound={500} />
      {creating && (
        <CreateProfile
          actor={actor}
          onClose={() => setCreating(false)}
          onDone={(name) => {
            setCreating(false);
            navigate(`profiles/${name}`);
          }}
        />
      )}
    </>
  );
}

// ---- typed editor --------------------------------------------------------------

// DeviceList stages device grants: only the six character devices the policy
// format allows can be added, one at a time.
function DeviceList({ devices, onAdd, onRemove }: { devices: string[]; onAdd: (d: string) => void; onRemove: (d: string) => void }) {
  const [value, setValue] = useState("");
  const left = DEVICES.filter((d) => !devices.includes(d));
  return (
    <div className="grant-list">
      <div className="grant-list-head">
        <h4>Devices</h4>
        <RiskBadge risk={EXPLAIN.devices.risk} />
      </div>
      <p className="form-note">{EXPLAIN.devices.plain} Only {DEVICES.join(", ")} can be allowed.</p>
      <ul>
        {devices.length ? (
          devices.map((d) => (
            <li key={d}>
              <code className="verbatim">{d}</code>
              <button type="button" className="icon-button" aria-label={`Remove device ${d}`} onClick={() => onRemove(d)}>
                <Trash2 size={15} />
              </button>
            </li>
          ))
        ) : (
          <li className="muted">none</li>
        )}
      </ul>
      <div className="inline-add">
        <label>
          Allow a device
          <select value={value} onChange={(e) => setValue(e.target.value)}>
            <option value="">Choose</option>
            {left.map((d) => (
              <option key={d}>{d}</option>
            ))}
          </select>
        </label>
        <button
          type="button"
          className="secondary"
          disabled={!value}
          onClick={() => {
            onAdd(value);
            setValue("");
          }}
        >
          Stage device
        </button>
      </div>
    </div>
  );
}

function PathList({ title, kind, explain, paths, readOnly, onAdd, onRemove }: { title: string; kind: string; explain: { plain: string; risk: any }; paths: string[]; readOnly?: string; onAdd?: (p: string) => void; onRemove?: (p: string) => void }) {
  const [value, setValue] = useState("");
  const issue = value ? editIssue({ action: kind, values: [value] }) : undefined;
  return (
    <div className="grant-list">
      <div className="grant-list-head">
        <h4>{title}</h4>
        <RiskBadge risk={explain.risk} />
      </div>
      <p className="form-note">{explain.plain}</p>
      <ul>
        {paths.length ? (
          paths.map((p) => (
            <li key={p}>
              <code className="verbatim">{p}</code>
              {onRemove && (
                <button type="button" className="icon-button" aria-label={`Remove ${title.toLowerCase()} ${p}`} onClick={() => onRemove(p)}>
                  <Trash2 size={15} />
                </button>
              )}
            </li>
          ))
        ) : (
          <li className="muted">none</li>
        )}
      </ul>
      {readOnly ? (
        <p className="form-note">{readOnly}</p>
      ) : (
        onAdd && (
          <div className="inline-add">
            <label>
              <span className="sr-only">Add a {title.toLowerCase()} path</span>
              <input value={value} onChange={(e) => setValue(e.target.value)} placeholder="/srv/data" spellCheck={false} aria-invalid={Boolean(issue)} />
            </label>
            <button
              type="button"
              className="secondary"
              disabled={!value || Boolean(issue)}
              onClick={() => {
                onAdd(value.replace(/\/+$/, ""));
                setValue("");
              }}
            >
              Stage {kind}
            </button>
            {issue && <small className="field-issue">{issue}</small>}
          </div>
        )
      )}
    </div>
  );
}

function ValidatorError({ error }: { error: unknown }) {
  if (error instanceof ApiError)
    return (
      <div className="error-box" role="alert">
        <div>
          <strong>The service refused the change</strong>
          <p>
            <code className="verbatim">{error.code}</code>: <span className="verbatim">{error.message}</span>
          </p>
          {error.requestID && <small>Request {error.requestID}</small>}
        </div>
      </div>
    );
  return <ErrorBox error={error} />;
}

export type Applied = { result: GrantResult; parent: ProfileVersion };

// AppliedResult shows the service's answer to an applied grant: the new
// version's digest, the diff from its parent, and the messages and notices
// verbatim. It lives on the profile page, so it survives the editor moving on
// to the new latest version.
function AppliedResult({ applied, onDismiss }: { applied: Applied; onDismiss: () => void }) {
  const { result, parent } = applied;
  return (
    <section className="panel preview" aria-live="polite" aria-label="Last applied change">
      <div className="panel-title">
        <h3 className="subheading">
          Applied: version {result.version?.number} (from v{parent.number})
        </h3>
        <button type="button" className="secondary small" onClick={onDismiss}>
          Dismiss
        </button>
      </div>
      {result.version && <Digest value={result.version.digest} label="Version digest" />}
      {result.version && <DiffTable rows={result.changes ?? diffDocuments(parent.document, result.version.document)} />}
      <ServerMessages title="Messages" items={result.messages} />
      <ServerMessages title="Notices" items={result.notices} tone="warn" />
    </section>
  );
}

function AccessEditor({ profile, latest, actor, onApplied }: { profile: Profile; latest: ProfileVersion; actor: Actor; onApplied: (applied: Applied) => void }) {
  const p = permissions(actor);
  const doc = latest.document;
  const fs = doc.filesystem;
  const presets = useResource<Presets>("access-presets");
  const [staged, setStaged] = useState<GrantEdit[]>([]);
  const [upgrade, setUpgrade] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState<"" | "preview" | "apply">("");
  const [preview, setPreview] = useState<GrantResult>();
  const [previewError, setPreviewError] = useState<unknown>();
  const [result, setResult] = useState<GrantResult>();
  const [error, setError] = useState<unknown>();
  const [dns, setDNS] = useState("");
  const [mountName, setMountName] = useState("");
  const [mountMode, setMountMode] = useState("read-only");
  const [signal, setSignal] = useState("");
  const [preset, setPreset] = useState("");
  const [announce, setAnnounce] = useState("");
  const stage = (edit: GrantEdit) => {
    setPreview(undefined);
    setPreviewError(undefined);
    setResult(undefined);
    setStaged((s) => (s.length >= 16 ? s : [...s, edit]));
    setAnnounce(`Staged: ${describeEdit(edit).text}`);
  };
  const edits = staged.map((e) => (upgrade ? { ...e, upgrade_to_v2: true } : e));
  const body = { edits, reason: reason.trim() };
  const issues = staged.map(editIssue).filter(Boolean) as string[];
  const canSend = staged.length > 0 && reason.trim().length >= 3 && !issues.length && !busy;
  const web = webOf(doc);
  const mounts = mountsOf(doc);
  const notMount = (x: string) => !x.startsWith(MOUNT_ROOT + "/");
  if (!p.editProfiles)
    return (
      <section className="panel">
        <h2>Change access</h2>
        <p className="form-note">Granting or revoking access needs the editor role. Your roles: {roleText(actor)}. You can read every version and its permissions.</p>
      </section>
    );
  return (
    <section className="panel access-editor" aria-labelledby="editor-title">
      <LiveRegion message={announce} />
      <div className="panel-title">
        <div>
          <h2 id="editor-title">Change access (rolls forward to version {latest.number + 1})</h2>
          <p>Edits apply to the latest version only, in the order listed. Nothing changes until you apply; the stored versions never change.</p>
        </div>
      </div>
      {doc.version !== "agentgate.poc.v2" && (
        <label className="check-row warn-row">
          <input type="checkbox" checked={upgrade} onChange={(e) => setUpgrade(e.target.checked)} />
          <span>
            Upgrade to version two (filesystem and process controls) with these edits
            <small>This version has network controls only and cannot launch. Upgrading keeps every network field and adds the example's host controls.</small>
          </span>
        </label>
      )}
      <details open>
        <summary>Network</summary>
        <div className="grant-list">
          <div className="grant-list-head">
            <h4>Public web</h4>
            <RiskBadge risk="high" />
          </div>
          <p className="form-note">{EXPLAIN.web.plain}</p>
          <ul>
            {WEB_PROTOCOLS.map((n) => (
              <li key={n}>
                <span>
                  {webLabel(n)}: <strong>{web.includes(n) ? "allowed" : "denied"}</strong>
                </span>
                <button type="button" className="secondary small" onClick={() => stage(web.includes(n) ? { action: "deny-web", values: [n] } : { action: "allow-web", values: [n] })}>
                  {web.includes(n) ? `Stage deny ${n}` : `Stage allow ${n}`}
                </button>
              </li>
            ))}
          </ul>
        </div>
        <div className="grant-list">
          <div className="grant-list-head">
            <h4>DNS resolvers</h4>
            <RiskBadge risk="medium" />
          </div>
          <p className="form-note">{EXPLAIN.dns.plain}</p>
          <ul>
            {doc.dns.resolvers.map((ip) => (
              <li key={ip}>
                <code>{ip}</code>
                <button type="button" className="icon-button" aria-label={`Remove resolver ${ip}`} onClick={() => stage({ action: "revoke", kind: "dns", values: [ip] })}>
                  <Trash2 size={15} />
                </button>
              </li>
            ))}
          </ul>
          <div className="inline-add">
            <label>
              <span className="sr-only">Replace the resolvers with (comma separated)</span>
              <input value={dns} onChange={(e) => setDNS(e.target.value)} placeholder="1.1.1.1, 9.9.9.9" />
            </label>
            <button
              type="button"
              className="secondary"
              disabled={!dns || Boolean(editIssue({ action: "dns", values: dns.split(/[\s,]+/).filter(Boolean) }))}
              onClick={() => {
                stage({ action: "dns", values: dns.split(/[\s,]+/).filter(Boolean) });
                setDNS("");
              }}
            >
              Stage replace resolvers
            </button>
            {dns && editIssue({ action: "dns", values: dns.split(/[\s,]+/).filter(Boolean) }) && <small className="field-issue">{editIssue({ action: "dns", values: dns.split(/[\s,]+/).filter(Boolean) })}</small>}
          </div>
        </div>
        <p className="form-note">
          Default {doc.default}, IPv6 {doc.ipv6}, task board {doc.taskboard.address}:{doc.taskboard.port}. These are fixed by the policy format.
        </p>
      </details>
      <details open>
        <summary>Files</summary>
        {fs ? (
          <>
            <PathList title="Workspace" kind="write" explain={EXPLAIN.workspace} paths={[fs.workspace]} readOnly="The workspace is always writable and never executable; it cannot be revoked. Use deny to hide a subtree of it." />
            <PathList title="Write" kind="write" explain={EXPLAIN.write} paths={fs.scratch.filter(notMount)} onAdd={(x) => stage({ action: "write", values: [x] })} onRemove={(x) => stage({ action: "revoke", kind: "write", values: [x] })} />
            <PathList title="Read" kind="read" explain={EXPLAIN.read} paths={fs.read_only.filter(notMount)} onAdd={(x) => stage({ action: "read", values: [x] })} onRemove={(x) => stage({ action: "revoke", kind: "read", values: [x] })} />
            <PathList title="Execute" kind="exec" explain={EXPLAIN.exec} paths={fs.execute} onAdd={(x) => stage({ action: "exec", values: [x] })} onRemove={(x) => stage({ action: "revoke", kind: "exec", values: [x] })} />
            <DeviceList devices={fs.devices} onAdd={(d) => stage({ action: "device", values: [d] })} onRemove={(d) => stage({ action: "revoke", kind: "device", values: [d] })} />
            <PathList title="Deny" kind="deny" explain={EXPLAIN.deny} paths={fs.deny} onAdd={(x) => stage({ action: "deny", values: [x] })} onRemove={(x) => stage({ action: "revoke", kind: "deny", values: [x] })} />
          </>
        ) : (
          <p className="form-note">This version has no filesystem section. Stage an edit with the upgrade option to add one.</p>
        )}
      </details>
      <details open>
        <summary>Mounts (host folders)</summary>
        <p className="form-note">
          A profile reserves a host folder name and its mode. The launch chooses which host folder is bound there (or a read-only snapshot copy), and the
          target must support it. {EXPLAIN.mountRW.plain}
        </p>
        <ul className="plain-list">
          {mounts.length ? (
            mounts.map((m) => (
              <li key={m.name}>
                <code>{m.path}</code> <strong>{m.mode}</strong> <RiskBadge risk={m.mode === "read-write" ? "high" : "medium"} />
                <button type="button" className="icon-button" aria-label={`Remove host folder ${m.name}`} onClick={() => stage({ action: "unmount", values: [m.name] })}>
                  <Trash2 size={15} />
                </button>
              </li>
            ))
          ) : (
            <li className="muted">none</li>
          )}
        </ul>
        <div className="inline-add">
          <label>
            Host folder name
            <input value={mountName} onChange={(e) => setMountName(e.target.value)} placeholder="repo" />
          </label>
          <label>
            Mode
            <select value={mountMode} onChange={(e) => setMountMode(e.target.value)}>
              <option value="read-only">read-only</option>
              <option value="read-write">read-write (never executable)</option>
            </select>
          </label>
          <button
            type="button"
            className="secondary"
            disabled={Boolean(editIssue({ action: "mount", values: [mountName] }))}
            onClick={() => {
              stage({ action: "mount", values: [mountName], mode: mountMode });
              setMountName("");
            }}
          >
            Stage host folder
          </button>
        </div>
      </details>
      <details open>
        <summary>Processes</summary>
        <p className="form-note">{EXPLAIN.signals.plain}</p>
        <ul className="plain-list">
          {(doc.process?.signals || []).map((s) => (
            <li key={s}>
              <code>{s}</code>
              <button type="button" className="icon-button" aria-label={`Remove signal ${s}`} onClick={() => stage({ action: "revoke", kind: "signal", values: [s] })}>
                <Trash2 size={15} />
              </button>
            </li>
          ))}
        </ul>
        <div className="inline-add">
          <label>
            Allow a signal
            <select value={signal} onChange={(e) => setSignal(e.target.value)}>
              <option value="">Choose</option>
              {SIGNALS.filter((s) => !doc.process?.signals.includes(s)).map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className="secondary"
            disabled={!signal}
            onClick={() => {
              stage({ action: "signal", values: [signal] });
              setSignal("");
            }}
          >
            Stage signal
          </button>
        </div>
      </details>
      <details open>
        <summary>Memory</summary>
        <p className="form-note">{fs?.memory.anonymous_execute ? EXPLAIN.anonOn.plain : EXPLAIN.anonOff.plain}</p>
        <button type="button" className="secondary" onClick={() => stage(fs?.memory.anonymous_execute ? { action: "revoke", kind: "anon-exec" } : { action: "anon-exec" })}>
          {fs?.memory.anonymous_execute ? "Stage turn off executable anonymous memory" : "Stage turn on executable anonymous memory"}
        </button>
      </details>
      <details>
        <summary>Replace with a preset</summary>
        <p className="form-note">A preset replaces the web, filesystem and process sections. DNS and the task board stay.</p>
        <div className="inline-add">
          <label>
            Preset
            <select value={preset} onChange={(e) => setPreset(e.target.value)}>
              <option value="">Choose</option>
              {presets.data?.items.map((x) => (
                <option key={x.name} value={x.name}>
                  {x.name}
                </option>
              ))}
            </select>
          </label>
          <button type="button" className="secondary" disabled={!preset} onClick={() => stage({ action: "preset", values: [preset] })}>
            Stage preset
          </button>
        </div>
      </details>
      <h3 className="subheading">Staged changes ({staged.length} of 16)</h3>
      {staged.length ? (
        <ol className="staged">
          {staged.map((e, i) => {
            const d = describeEdit(e);
            return (
              <li key={i}>
                <span>{d.text}</span>
                <RiskBadge risk={d.risk} />
                <code className="verbatim">{JSON.stringify(e)}</code>
                <button type="button" className="icon-button" aria-label={`Unstage change ${i + 1}`} onClick={() => setStaged(staged.filter((_, n) => n !== i))}>
                  <Trash2 size={15} />
                </button>
              </li>
            );
          })}
        </ol>
      ) : (
        <p className="form-note">No changes staged.</p>
      )}
      {issues.map((x, i) => (
        <p className="field-issue" key={i}>
          {x}
        </p>
      ))}
      <label>
        Reason
        <textarea value={reason} onChange={(e) => setReason(e.target.value)} minLength={3} maxLength={512} placeholder="Why this access is needed" />
      </label>
      <div className="version-actions">
        <button
          type="button"
          className="secondary"
          disabled={!canSend}
          onClick={async () => {
            setBusy("preview");
            setPreview(undefined);
            setPreviewError(undefined);
            try {
              const out = await api<GrantResult>(`profiles/${profile.id}/versions/${latest.number}/grants`, "POST", { ...body, dry_run: true });
              if (out.dry_run !== true) throw new Error("The service did not confirm a dry run. Nothing is shown as a preview.");
              setPreview(out);
            } catch (cause) {
              setPreviewError(cause);
            } finally {
              setBusy("");
            }
          }}
        >
          {busy === "preview" ? "Checking…" : "Preview (dry run)"}
        </button>
        <button
          type="button"
          disabled={!canSend}
          onClick={async () => {
            setBusy("apply");
            setError(undefined);
            try {
              const out = await api<GrantResult>(`profiles/${profile.id}/versions/${latest.number}/grants`, "POST", body);
              setStaged([]);
              setPreview(undefined);
              setAnnounce(out.changed ? `Version ${out.version?.number} created.` : "No change: the edits produced the same policy.");
              if (out.changed && out.version) onApplied({ result: out, parent: latest });
              else setResult(out);
            } catch (cause) {
              setError(cause);
            } finally {
              setBusy("");
            }
          }}
        >
          {busy === "apply" ? "Applying…" : `Apply as version ${latest.number + 1}`}
        </button>
      </div>
      {preview && (
        <div className="preview" aria-live="polite">
          <h3 className="subheading">Dry run: the service's result (nothing was stored)</h3>
          <p className="form-note">
            {preview.changed ? `Version ${preview.from_version} would become version ${preview.from_version + 1}.` : "No change: the edits produce the same policy, so no version would be created."}
          </p>
          <div className="metadata">
            <div>
              <span>From (v{preview.from_version})</span>
              <Digest value={preview.from_digest} label="Parent digest" />
            </div>
            <div>
              <span>Result</span>
              <Digest value={preview.digest} label="Result digest" />
            </div>
          </div>
          <DiffTable rows={preview.changes} />
          <ServerMessages title="Messages" items={preview.messages} />
          <ServerMessages title="Notices" items={preview.notices} tone="warn" />
        </div>
      )}
      {Boolean(previewError) && <ValidatorError error={previewError} />}
      {Boolean(error) && <ValidatorError error={error} />}
      {result && (
        <div className="preview" aria-live="polite">
          <h3 className="subheading">No change: the policy is identical, so no version was created</h3>
          <ServerMessages title="Messages" items={result.messages} />
          <ServerMessages title="Notices" items={result.notices} tone="warn" />
        </div>
      )}
    </section>
  );
}

function DocumentVersion({ profile, latest, onClose, onDone }: { profile: Profile; latest: ProfileVersion; onClose: () => void; onDone: (n: number) => void }) {
  const [text, setText] = useState(JSON.stringify(latest.document, null, 2));
  const [parseError, setParseError] = useState("");
  return (
    <ConfirmDialog
      title={`New version from a document (parent v${latest.number})`}
      confirmLabel={`Store as version ${latest.number + 1}`}
      onClose={onClose}
      onConfirm={async (reason) => {
        let document: unknown;
        try {
          document = JSON.parse(text);
        } catch (e) {
          setParseError((e as Error).message);
          throw new Error("The document is not valid JSON.");
        }
        const v = await api<ProfileVersion>(`profiles/${profile.id}/versions`, "POST", { parent_version: latest.number, document, reason });
        onDone(v.number);
      }}
    >
      <p className="form-note">
        For changes the typed editor cannot make or to import a document the CLI produced. The service validates the whole document
        with the policy validator; a version two profile cannot return to version one.
      </p>
      <label>
        Policy document (agentgate.poc.v2)
        <textarea className="mono" rows={14} value={text} spellCheck={false} onChange={(e) => setText(e.target.value)} />
      </label>
      {parseError && <p className="field-issue">{parseError}</p>}
    </ConfirmDialog>
  );
}

export function ProfileDetail({ id: profileRef, selected, actor, epoch, navigate }: { id: string; selected?: number; actor: Actor; epoch: number; navigate: (p: string) => void }) {
  const p = permissions(actor);
  const profile = useResource<Profile>(`profiles/${encodeURIComponent(profileRef)}`, epoch);
  const versions = useResource<Items<ProfileVersion>>(`profiles/${encodeURIComponent(profileRef)}/versions`, epoch);
  const [compare, setCompare] = useState<number>();
  const [dialog, setDialog] = useState<"approval" | "require" | "document">();
  const [applied, setApplied] = useState<Applied>();
  const list = versions.data?.items || [];
  const byID = useMemo(() => new Map(list.map((v) => [v.id, v])), [list]);
  if (profile.loading || versions.loading) return <Loading />;
  if (profile.error || versions.error || !profile.data) return <ErrorBox error={profile.error || versions.error} />;
  const prof = profile.data;
  const latest = list[0];
  const current = list.find((v) => v.number === selected) || latest;
  const parent = current?.parent_id ? byID.get(current.parent_id) : undefined;
  const other = compare ? list.find((v) => v.number === compare) : undefined;
  const chain: number[] = [];
  for (let v: ProfileVersion | undefined = current; v && chain.length < 200; v = v.parent_id ? byID.get(v.parent_id) : undefined) chain.push(v.number);
  const reload = (n?: number) => {
    profile.reload();
    versions.reload();
    if (n) navigate(`profiles/${prof.name}/${n}`);
  };
  return (
    <>
      <button className="back-link" onClick={() => navigate("profiles")}>
        <ArrowLeft size={15} /> All profiles
      </button>
      <SectionTitle eyebrow="ACCESS PROFILE" title={prof.name} text={prof.description || "An immutable chain of access versions."} action={<span className="badge">latest v{prof.latest_version}</span>} />
      <section className="panel approval-panel">
        <div className="panel-title">
          <h2>Launch approval</h2>
          <ShieldCheck size={19} aria-hidden="true" />
        </div>
        <p>
          {prof.require_approval
            ? "Every launch of this profile waits for a second person with the approver role. The requester can never approve their own launch."
            : prof.approved_version
              ? `A launcher may start version ${prof.approved_version} alone, the version an administrator reviewed, unless the launch needs approval for another reason (inline access, live host folders, brokered secrets, public web, or the spec asks for it). Every other version, including newer ones, needs a second person.`
              : "No version is approved for launches without a second person, so every launch needs approval."}
        </p>
        {!prof.require_approval && prof.approved_version && (
          <div className="metadata">
            <div>
              <span>Approved version</span>
              <strong>
                v{prof.approved_version} by {prof.approved_by} {prof.approved_at ? when(prof.approved_at) : ""}
              </strong>
            </div>
            <div>
              <span>Approved digest</span>
              <Digest value={prof.approved_digest} label="Approved version digest" />
            </div>
          </div>
        )}
        <Gate
          className="secondary"
          allowed={p.profilesAdmin && !!current && (prof.require_approval || current.digest !== prof.approved_digest)}
          reason={
            !p.profilesAdmin
              ? `Only an administrator changes whether launches need approval. Your roles: ${roleText(actor)}.`
              : `Version ${current?.number} is already the approved version.`
          }
          onClick={() => setDialog("approval")}
        >
          {`Let launchers start v${current?.number ?? "?"} alone…`}
        </Gate>
        {!prof.require_approval && (
          <Gate
            className="secondary"
            allowed={p.profilesAdmin}
            reason={`Only an administrator changes whether launches need approval. Your roles: ${roleText(actor)}.`}
            onClick={() => setDialog("require")}
          >
            Require a second person…
          </Gate>
        )}
      </section>
      <div className="detail-grid">
        <div>
          {current && (
            <>
              <section className="panel">
                <div className="panel-title">
                  <h2>Version {current.number}</h2>
                  {current.number === latest?.number && <span className="badge allowed">latest</span>}
                </div>
                <div className="metadata">
                  <div>
                    <span>Digest (SHA-256 of the canonical document)</span>
                    <Digest value={current.digest} label="Version digest" />
                  </div>
                  <div>
                    <span>Parent chain</span>
                    <strong>{chain.map((n) => `v${n}`).join(" ← ")}</strong>
                  </div>
                  <div>
                    <span>Created</span>
                    <strong>
                      {when(current.created_at)} by {current.actor}
                    </strong>
                  </div>
                  <div>
                    <span>Reason</span>
                    <strong>{current.reason}</strong>
                  </div>
                  <div>
                    <span>Edits that produced it</span>
                    <strong>{current.edits?.length ? current.edits.map((e) => describeEdit(e).text).join(" ") : "a whole document"}</strong>
                  </div>
                </div>
                <h3 className="subheading">Changes from {parent ? `v${parent.number}` : "nothing (first version)"}</h3>
                <DiffTable rows={diffDocuments(parent?.document, current.document)} />
              </section>
              <AccessSummary doc={current.document} title={`What can this agent do? (v${current.number})`} />
            </>
          )}
          {applied && <AppliedResult applied={applied} onDismiss={() => setApplied(undefined)} />}
          {latest && (
            <AccessEditor
              key={latest.id}
              profile={prof}
              latest={latest}
              actor={actor}
              onApplied={(a) => {
                setApplied(a);
                reload(a.result.version?.number);
              }}
            />
          )}
          {latest && p.editProfiles && (
            <details className="panel advanced">
              <summary>Advanced: new version from a document</summary>
              <button type="button" className="secondary" onClick={() => setDialog("document")}>
                Paste a document…
              </button>
            </details>
          )}
        </div>
        <section className="panel">
          <div className="panel-title">
            <h2>Version history</h2>
            <History size={19} aria-hidden="true" />
          </div>
          <div className="version-list">
            {list.map((v) => (
              <button key={v.id} className={current?.id === v.id ? "selected" : ""} aria-current={current?.id === v.id ? "true" : undefined} onClick={() => navigate(`profiles/${prof.name}/${v.number}`)}>
                <span className="version-number">{v.number}</span>
                <div>
                  <strong>Version {v.number}</strong>
                  <small>
                    {when(v.created_at)} · {v.digest.slice(0, 12)}… · parent {v.parent_id ? `v${byID.get(v.parent_id)?.number ?? "?"}` : "none"}
                  </small>
                </div>
              </button>
            ))}
          </div>
          <label>
            Compare v{current?.number} with
            <select value={compare ?? ""} onChange={(e) => setCompare(e.target.value ? Number(e.target.value) : undefined)}>
              <option value="">Choose a version</option>
              {list
                .filter((v) => v.number !== current?.number)
                .map((v) => (
                  <option key={v.id} value={v.number}>
                    v{v.number}
                  </option>
                ))}
            </select>
          </label>
          {other && current && (
            <>
              <h3 className="subheading">
                From v{Math.min(other.number, current.number)} to v{Math.max(other.number, current.number)}
              </h3>
              <DiffTable rows={other.number < current.number ? diffDocuments(other.document, current.document) : diffDocuments(current.document, other.document)} />
            </>
          )}
        </section>
      </div>
      <KernelNotice />
      {dialog === "approval" && current && (
        <ConfirmDialog
          title={`Let launchers start version ${current.number} alone`}
          confirmLabel={`Approve version ${current.number}`}
          danger
          onClose={() => setDialog(undefined)}
          onConfirm={async (reason) => {
            await api(`profiles/${prof.id}`, "PATCH", { require_approval: false, version: current.number, digest: current.digest, reason });
            setDialog(undefined);
            reload();
          }}
        >
          <p>
            After this, a launcher can start an agent with version {current.number} of this profile without anyone else reviewing it, when nothing else in the launch needs approval. Every
            launch is still audited. Every other version, including any version added later, needs a second person until an administrator approves it here.
          </p>
          <div className="metadata">
            <div>
              <span>Version you reviewed</span>
              <strong>v{current.number}</strong>
            </div>
            <div>
              <span>Its digest (sent with the approval; a different one is refused)</span>
              <Digest value={current.digest} label="Version digest" />
            </div>
          </div>
        </ConfirmDialog>
      )}
      {dialog === "require" && (
        <ConfirmDialog
          title="Require a second person for every launch"
          confirmLabel="Require approval"
          onClose={() => setDialog(undefined)}
          onConfirm={async (reason) => {
            await api(`profiles/${prof.id}`, "PATCH", { require_approval: true, reason });
            setDialog(undefined);
            reload();
          }}
        >
          <p>After this, every launch of this profile waits in approval_pending for a different person with the approver role, and no version stays approved.</p>
        </ConfirmDialog>
      )}
      {dialog === "document" && latest && (
        <DocumentVersion
          profile={prof}
          latest={latest}
          onClose={() => setDialog(undefined)}
          onDone={(n) => {
            setDialog(undefined);
            reload(n);
          }}
        />
      )}
    </>
  );
}
