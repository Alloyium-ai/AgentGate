// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Launch: a guided form that produces one agentgate.launch.v1 spec, a
// mandatory Review & plan step (POST /launch-plans, which creates nothing),
// and only then Launch with exactly the planned document. The same document
// works with `agentgate launch -f`.

import React, { useEffect, useMemo, useRef, useState } from "react";
import { FileUp, Plus, Rocket, Trash2 } from "lucide-react";
import { Actor, ApiError, api } from "./api";
import { ErrorBox, Loading, Modal, SectionTitle } from "./components";
import { Items, Launch, LaunchPlan, PolicyDocument, Profile, ProfileVersion, Target, TargetSecrets, permissions, roleText, useResource } from "./prov-api";
import { AccessSummary, Capabilities, CodeBlock, CopyButton, Digest, Gate, Issues, KernelNotice, LiveRegion, ServerMessages } from "./prov-components";
import { LIFETIME, LaunchForm, MountMode, buildSpec, cliCommands, emptyForm, envNameIssue, lifetimeText, parseSpec, predictApproval, specJSON } from "./launch-spec";
import { webOf } from "./access-model";

type PlanResponse = { dry_run: boolean; plan: LaunchPlan; spec: unknown; policy: PolicyDocument };

export function PlanView({ plan, policy }: { plan: LaunchPlan; policy?: PolicyDocument }) {
  const perm = plan.permissions;
  const list = (v?: string[] | null) => (v?.length ? v.join(", ") : "none");
  return (
    <div className="plan">
      <KernelNotice />
      <div className="metadata">
        <div>
          <span>Spec digest</span>
          <Digest value={plan.spec_digest} label="Spec digest" />
        </div>
        <div>
          <span>Policy digest</span>
          <Digest value={plan.policy_digest} label="Policy digest" />
        </div>
        <div>
          <span>Target</span>
          <strong>
            {plan.target?.name} <small>{plan.target?.id}</small>
          </strong>
        </div>
        <div>
          <span>Access</span>
          <strong>{plan.profile?.inline ? "Inline document (not a reviewed profile)" : `${String(plan.profile?.name)} v${String(plan.profile?.version)}`}</strong>
        </div>
        <div>
          <span>Mode and lifetime</span>
          <strong>
            {plan.mode === "oneshot" ? "One-shot" : "Session"} · {lifetimeText(plan.lifetime_seconds)}
          </strong>
        </div>
        <div>
          <span>Expires</span>
          <strong>
            {plan.expires_at ? new Date(plan.expires_at).toLocaleString() : "when queued"} <small>{plan.expiry_rule}</small>
          </strong>
        </div>
        <div>
          <span>Image</span>
          <code className="verbatim">{plan.image}</code>
        </div>
        <div>
          <span>Command</span>
          <code className="verbatim">{plan.command?.length ? JSON.stringify(plan.command) : "image default"}</code>
        </div>
        <div>
          <span>Working directory</span>
          <code>{plan.workdir}</code>
        </div>
        <div>
          <span>Approval</span>
          <strong>{plan.approval === "required" ? "Required: a different person with the approver role must approve" : "Automatic: nothing requires a second person"}</strong>
        </div>
        <div>
          <span>Kernel verified</span>
          <strong>{plan.kernel_verified ? "the plan claims true; protocol v1 cannot verify it" : "no"}</strong>
        </div>
      </div>
      <ServerMessages title="Why approval is needed" items={plan.approval_reasons} tone="warn" />
      <ServerMessages title="Notices from the service" items={plan.notices} tone="warn" />
      <h3 className="subheading">Effective permissions (the service's summary)</h3>
      <div className="table-wrap">
        <table>
          <caption className="sr-only">Effective permissions</caption>
          <tbody>
            <tr>
              <th scope="row">Network default</th>
              <td>
                {perm.network_default} · IPv6 {perm.ipv6}
              </td>
            </tr>
            <tr>
              <th scope="row">Public web (any public IPv4 address)</th>
              <td>{list(perm.web)}</td>
            </tr>
            <tr>
              <th scope="row">DNS resolvers</th>
              <td>{list(perm.dns_resolvers)}</td>
            </tr>
            <tr>
              <th scope="row">Read-only</th>
              <td>{list(perm.read_only)}</td>
            </tr>
            <tr>
              <th scope="row">Writable (never executable)</th>
              <td>{list(perm.writable)}</td>
            </tr>
            <tr>
              <th scope="row">Executable</th>
              <td>{list(perm.execute)}</td>
            </tr>
            <tr>
              <th scope="row">Denied</th>
              <td>{list(perm.deny)}</td>
            </tr>
            <tr>
              <th scope="row">Devices</th>
              <td>{list(perm.devices)}</td>
            </tr>
            <tr>
              <th scope="row">Signals</th>
              <td>{list(perm.signals)}</td>
            </tr>
            <tr>
              <th scope="row">Executable anonymous memory</th>
              <td>{perm.anonymous_execute ? "on (weakens write-xor-execute)" : "off"}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <h3 className="subheading">Host folders</h3>
      {plan.mounts?.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Host folder</th>
                <th scope="col">Mode</th>
                <th scope="col">Path inside the agent</th>
              </tr>
            </thead>
            <tbody>
              {plan.mounts.map((m) => (
                <tr key={m.name}>
                  <td>{m.name}</td>
                  <td>
                    <code>{m.source}</code>
                  </td>
                  <td>{m.mode === "snapshot" ? "snapshot (read-only copy)" : m.mode === "read-write" ? "read-write (live; changes persist)" : "read-only (live bind)"}</td>
                  <td>
                    <code>{m.path}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="form-note">No host folders are mounted.</p>
      )}
      <h3 className="subheading">Brokered secrets</h3>
      {plan.secrets?.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Secret</th>
                <th scope="col">Broker address variable</th>
                <th scope="col">Upstreams</th>
                <th scope="col">Header</th>
              </tr>
            </thead>
            <tbody>
              {plan.secrets.map((s) => (
                <tr key={s.ref}>
                  <td>
                    {s.ref}
                    <small>{s.secret_id}</small>
                  </td>
                  <td>
                    <code>{s.env}</code>
                  </td>
                  <td>{s.upstreams?.join(", ")}</td>
                  <td>
                    <code>{s.header}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="form-note">The agent never receives a secret value. It gets only the broker address; the host's broker adds the credential to requests for these upstreams.</p>
        </div>
      ) : (
        <p className="form-note">No secrets are brokered.</p>
      )}
      {policy && <AccessSummary doc={policy} title="What can this agent do? (effective launch policy)" />}
    </div>
  );
}

function ImportSpec({ onClose, onImport }: { onClose: () => void; onImport: (form: LaunchForm) => void }) {
  const [text, setText] = useState("");
  const [error, setError] = useState("");
  return (
    <Modal title="Import a launch spec" onClose={onClose}>
      <p className="form-note">Paste or choose an agentgate.launch.v1 JSON document, for example one written for `agentgate launch -f`. Unknown fields and duplicate keys are refused.</p>
      <label>
        Spec file
        <input
          type="file"
          accept="application/json,.json"
          onChange={async (e) => {
            const f = e.target.files?.[0];
            if (!f) return;
            if (f.size > 64 << 10) {
              setError("A launch spec is at most 64 KiB.");
              return;
            }
            setText(await f.text());
          }}
        />
      </label>
      <label>
        Spec JSON
        <textarea className="mono" rows={12} value={text} spellCheck={false} onChange={(e) => setText(e.target.value)} />
      </label>
      {error && (
        <p className="field-issue" role="alert">
          {error}
        </p>
      )}
      <div className="modal-actions">
        <button type="button" className="secondary" onClick={onClose}>
          Cancel
        </button>
        <button
          disabled={!text.trim()}
          onClick={() => {
            const out = parseSpec(text);
            if (out.error || !out.form) setError(out.error || "The spec could not be read.");
            else onImport(out.form);
          }}
        >
          Load into the form
        </button>
      </div>
    </Modal>
  );
}

const UNITS = [
  { label: "seconds", factor: 1 },
  { label: "minutes", factor: 60 },
  { label: "hours", factor: 3600 },
];

export function LaunchPage({ actor, from, navigate }: { actor: Actor; from?: string; navigate: (p: string) => void }) {
  const p = permissions(actor);
  const targets = useResource<Items<Target>>("targets");
  const profiles = useResource<Items<Profile>>("profiles");
  const source = useResource<{ launch: Launch }>(from ? `launches/${encodeURIComponent(from)}` : null);
  const [form, setForm] = useState<LaunchForm>(emptyForm);
  const [unit, setUnit] = useState(60);
  const [touched, setTouched] = useState(false);
  const [importing, setImporting] = useState(false);
  const [planning, setPlanning] = useState(false);
  const [plan, setPlan] = useState<PlanResponse>();
  const [plannedJSON, setPlannedJSON] = useState("");
  const [planError, setPlanError] = useState<unknown>();
  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState<unknown>();
  const [announce, setAnnounce] = useState("");
  const [commandText, setCommandText] = useState("");
  const reviewRef = useRef<HTMLHeadingElement>(null);
  const profileName = form.access.kind === "profile" ? form.access.profile : "";
  const versions = useResource<Items<ProfileVersion>>(profileName ? `profiles/${encodeURIComponent(profileName)}/versions` : null);
  const load = (next: LaunchForm) => {
    setForm(next);
    setCommandText(next.command.join("\n"));
    setPlan(undefined);
    setTouched(true);
  };
  useEffect(() => {
    if (source.data?.launch.spec) {
      const out = parseSpec(JSON.stringify(source.data.launch.spec));
      if (out.form) load(out.form);
    }
  }, [source.data]);
  const target = targets.data?.items.find((t) => t.name === form.target);
  const secrets = useResource<TargetSecrets>(target && target.state === "active" ? `targets/${encodeURIComponent(target.id)}/secrets${profileName ? `?profile=${encodeURIComponent(profileName)}` : ""}` : null);
  const activeTargets = (targets.data?.items || []).filter((t) => t.state === "active");
  const profile = profiles.data?.items.find((x) => x.name === profileName);
  const version = versions.data?.items.find((v) => form.access.kind === "profile" && v.number === form.access.version);
  useEffect(() => {
    if (form.access.kind === "profile" && profile && !form.access.version) setForm((f) => ({ ...f, access: { kind: "profile", profile: profile.name, version: profile.latest_version } }));
  }, [profile?.id]);
  const built = useMemo(() => buildSpec(form), [form]);
  const json = specJSON(built.spec);
  const stale = Boolean(plan) && plannedJSON !== json;
  const set = <K extends keyof LaunchForm>(key: K, value: LaunchForm[K]) => {
    setTouched(true);
    setForm((f) => ({ ...f, [key]: value }));
  };
  const caps = target?.capabilities || [];
  const live = caps.includes("live-mounts");
  const snap = caps.includes("snapshot-mounts");
  const targetSecrets = secrets.data?.target_id === target?.id ? secrets.data?.items || [] : [];
  const reasons = predictApproval(form, profile?.require_approval, version ? webOf(version.document).length > 0 : undefined);
  const commands = cliCommands(built.spec);
  const issues = touched ? built.issues : [];
  if (!p.launch && !from)
    return (
      <>
        <SectionTitle eyebrow="LAUNCH" title="Launch an agent" text="Launching needs the launcher role." />
        <ErrorBox error={new ApiError(403, "forbidden", `Launching needs the launcher role. Your roles: ${roleText(actor)}. The service refuses launch and plan requests without it.`, "")} />
      </>
    );
  return (
    <>
      <SectionTitle
        eyebrow="LAUNCH"
        title="Launch an agent"
        text="Describe what runs, where, for how long and with which access. Review the service's plan, then launch exactly that spec."
        action={
          <button className="secondary" onClick={() => setImporting(true)}>
            <FileUp size={16} aria-hidden="true" /> Import spec JSON
          </button>
        }
      />
      <LiveRegion message={announce} />
      {(targets.loading || profiles.loading || source.loading) && <Loading />}
      {Boolean(targets.error) && <ErrorBox error={targets.error} />}
      {Boolean(source.error) && <ErrorBox error={source.error} />}
      <form
        className="launch-form"
        noValidate
        onSubmit={async (e) => {
          e.preventDefault();
          setTouched(true);
          if (built.issues.length) {
            setAnnounce(`${built.issues.length} problems need attention before planning.`);
            return;
          }
          setPlanning(true);
          setPlanError(undefined);
          setPlan(undefined);
          try {
            const out = await api<PlanResponse>("launch-plans", "POST", built.spec);
            setPlan(out);
            setPlannedJSON(json);
            setAnnounce(`Plan ready. Approval ${out.plan.approval}.`);
            setTimeout(() => reviewRef.current?.focus(), 0);
          } catch (cause) {
            setPlanError(cause);
            setAnnounce("The service refused the plan.");
          } finally {
            setPlanning(false);
          }
        }}
      >
        <section className="panel">
          <h2>1. What and where</h2>
          <div className="form-grid">
            <label>
              Launch name
              <input value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="repo-fixer" maxLength={40} aria-invalid={issues.some((i) => i.field === "name")} />
            </label>
            <label>
              Target
              <select value={form.target} onChange={(e) => set("target", e.target.value)}>
                <option value="">Choose an active target</option>
                {activeTargets.map((t) => (
                  <option key={t.id} value={t.name}>
                    {t.name} ({t.online ? "online" : "offline"})
                  </option>
                ))}
              </select>
            </label>
          </div>
          <Issues issues={issues} field="name" />
          <Issues issues={issues} field="target" />
          {target && (
            <p className="form-note">
              <Capabilities caps={target.capabilities} /> <KernelNotice compact />
            </p>
          )}
          {!activeTargets.length && !targets.loading && <p className="form-note">No target is enrolled and active. An administrator adds one on the Targets page.</p>}
          <fieldset>
            <legend>Mode</legend>
            <label className="check-row">
              <input type="radio" name="mode" checked={form.mode === "oneshot"} onChange={() => set("mode", "oneshot")} />
              <span>
                One-shot: run the command once and end <small>Lifetime 1 second to 1 hour; a command is required.</small>
              </span>
            </label>
            <label className="check-row">
              <input type="radio" name="mode" checked={form.mode === "session"} onChange={() => set("mode", "session")} />
              <span>
                Session: a long-running agent <small>Lifetime 1 minute to 24 hours.</small>
              </span>
            </label>
            <div className="form-grid">
              <label>
                Lifetime (hard cap)
                <input
                  type="number"
                  min={Math.ceil(LIFETIME[form.mode].min / unit)}
                  max={Math.floor(LIFETIME[form.mode].max / unit)}
                  value={Number.isFinite(form.lifetime_seconds) ? form.lifetime_seconds / unit : ""}
                  onChange={(e) => set("lifetime_seconds", Math.round(Number(e.target.value) * unit))}
                />
              </label>
              <label>
                Unit
                <select value={unit} onChange={(e) => setUnit(Number(e.target.value))}>
                  {UNITS.map((u) => (
                    <option key={u.factor} value={u.factor}>
                      {u.label}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <p className="form-note">
              {lifetimeText(form.lifetime_seconds)}. The clock starts when the launch is queued (after approval). The kernel policy and the host end the launch
              then; the agent cannot extend it.
            </p>
            <Issues issues={issues} field="lifetime_seconds" />
          </fieldset>
        </section>
        <section className="panel">
          <h2>2. The agent</h2>
          <label>
            Image (immutable digest)
            <input value={form.image} onChange={(e) => set("image", e.target.value.trim())} placeholder="agentgate-coding@sha256:…" spellCheck={false} />
          </label>
          <Issues issues={issues} field="image" />
          <label>
            Command, one argument per line (no shell)
            <textarea
              className="mono"
              rows={4}
              value={commandText}
              spellCheck={false}
              onChange={(e) => {
                setCommandText(e.target.value);
                set(
                  "command",
                  e.target.value
                    .split("\n")
                    .map((line) => line.replace(/\r$/, ""))
                    .filter((line) => line !== ""),
                );
              }}
              placeholder={"claude\n--print\nfix the failing tests"}
            />
          </label>
          <p className="form-note">Each line is one argument, passed as-is; blank lines are ignored. Leave empty for a session that uses the image's default.</p>
          <Issues issues={issues} field="command" />
          <label>
            Working directory (optional)
            <input value={form.workdir} onChange={(e) => set("workdir", e.target.value)} placeholder="/var/lib/agentgate/workspace" spellCheck={false} />
          </label>
          <Issues issues={issues} field="workdir" />
          <fieldset>
            <legend>Environment (not secret)</legend>
            <p className="form-note">Names that look like credentials (KEY, TOKEN, *_KEY, PASSWORD, …) are refused, as the service refuses them. Secrets arrive only through the broker below.</p>
            {form.env.map((row, i) => {
              const issue = row.name ? envNameIssue(row.name) : undefined;
              return (
                <div className="row-edit" key={i}>
                  <label>
                    Name
                    <input
                      value={row.name}
                      spellCheck={false}
                      aria-invalid={Boolean(issue)}
                      onChange={(e) =>
                        set(
                          "env",
                          form.env.map((x, n) => (n === i ? { ...x, name: e.target.value } : x)),
                        )
                      }
                    />
                  </label>
                  <label>
                    Value
                    <input
                      value={row.value}
                      spellCheck={false}
                      autoComplete="off"
                      onChange={(e) =>
                        set(
                          "env",
                          form.env.map((x, n) => (n === i ? { ...x, value: e.target.value } : x)),
                        )
                      }
                    />
                  </label>
                  <button type="button" className="icon-button" aria-label={`Remove variable ${row.name || i + 1}`} onClick={() => set("env", form.env.filter((_, n) => n !== i))}>
                    <Trash2 size={15} />
                  </button>
                  {issue && <small className="field-issue">{issue}</small>}
                </div>
              );
            })}
            <button type="button" className="secondary" disabled={form.env.length >= 64} onClick={() => set("env", [...form.env, { name: "", value: "" }])}>
              <Plus size={15} aria-hidden="true" /> Add variable
            </button>
            <Issues issues={issues} field="env" />
          </fieldset>
        </section>
        <section className="panel">
          <h2>3. Access</h2>
          <fieldset>
            <legend>Access source</legend>
            <label className="check-row">
              <input type="radio" name="access" checked={form.access.kind === "profile"} onChange={() => set("access", { kind: "profile", profile: "", version: 0 })} />
              <span>A stored profile version (reviewed, versioned)</span>
            </label>
            <label className="check-row">
              <input type="radio" name="access" checked={form.access.kind === "inline"} onChange={() => set("access", { kind: "inline", document: version ? JSON.stringify(version.document, null, 2) : "" })} />
              <span>
                An inline document <span className="badge pending">always needs approval</span>
                <small>Not a reviewed profile; cannot use brokered secrets.</small>
              </span>
            </label>
          </fieldset>
          {form.access.kind === "profile" ? (
            <div className="form-grid">
              <label>
                Profile
                <select value={form.access.profile} onChange={(e) => set("access", { kind: "profile", profile: e.target.value, version: 0 })}>
                  <option value="">Choose a profile</option>
                  {profiles.data?.items.map((x) => (
                    <option key={x.id} value={x.name}>
                      {x.name} (latest v{x.latest_version}){x.require_approval ? " · needs approval" : ""}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Version
                <select value={form.access.version || ""} onChange={(e) => set("access", { kind: "profile", profile: profileName, version: Number(e.target.value) })}>
                  <option value="">Choose</option>
                  {versions.data?.items.map((v) => (
                    <option key={v.id} value={v.number}>
                      v{v.number} · {v.digest.slice(0, 12)}…{v.document.version !== "agentgate.poc.v2" ? " (version one: cannot launch)" : ""}
                    </option>
                  ))}
                </select>
              </label>
            </div>
          ) : (
            <label>
              Inline agentgate.poc.v2 document
              <textarea className="mono" rows={10} spellCheck={false} value={form.access.document} onChange={(e) => set("access", { kind: "inline", document: e.target.value })} />
            </label>
          )}
          <Issues issues={issues} field="access" />
          {version && <AccessSummary doc={version.document} title={`What can this agent do? (${profileName} v${version.number}, before host folders)`} />}
        </section>
        <section className="panel">
          <h2>4. Host folders</h2>
          <p className="form-note">
            A live folder (read-only or read-write) needs a target with live-mounts; a snapshot needs snapshot-mounts. Live folders always need approval. Protected
            host trees, credential stores and home directories are refused; the host checks again.
          </p>
          {form.mounts.map((m, i) => (
            <div className="row-edit" key={i}>
              <label>
                Name in the agent
                <input value={m.name} onChange={(e) => set("mounts", form.mounts.map((x, n) => (n === i ? { ...x, name: e.target.value } : x)))} placeholder="repo" />
              </label>
              <label>
                Host folder
                <input value={m.source} spellCheck={false} onChange={(e) => set("mounts", form.mounts.map((x, n) => (n === i ? { ...x, source: e.target.value.trim() } : x)))} placeholder="/srv/repos/app" />
              </label>
              <label>
                Mode
                <select value={m.mode} onChange={(e) => set("mounts", form.mounts.map((x, n) => (n === i ? { ...x, mode: e.target.value as MountMode } : x)))}>
                  <option value="snapshot" disabled={Boolean(target) && !snap}>
                    snapshot: read-only copy{target && !snap ? " (target lacks snapshot-mounts)" : ""}
                  </option>
                  <option value="read-only" disabled={Boolean(target) && !live}>
                    read-only: live bind{target && !live ? " (target lacks live-mounts)" : ""}
                  </option>
                  <option value="read-write" disabled={Boolean(target) && !live}>
                    read-write: live, changes persist{target && !live ? " (target lacks live-mounts)" : ""}
                  </option>
                </select>
              </label>
              <button type="button" className="icon-button" aria-label={`Remove host folder ${m.name || i + 1}`} onClick={() => set("mounts", form.mounts.filter((_, n) => n !== i))}>
                <Trash2 size={15} />
              </button>
              <small className="form-note">
                Appears at /var/lib/agentgate/mounts/{m.name || "NAME"}
                {m.mode === "read-write" ? "; the agent can change real host files (never executable)" : ""}.
              </small>
            </div>
          ))}
          <button type="button" className="secondary" disabled={form.mounts.length >= 8} onClick={() => set("mounts", [...form.mounts, { name: "", source: "", mode: snap || !live ? "snapshot" : "read-only" }])}>
            <Plus size={15} aria-hidden="true" /> Add host folder
          </button>
          <Issues issues={issues} field="mounts" />
        </section>
        <section className="panel">
          <h2>5. Brokered secrets</h2>
          <p className="form-note">
            The agent never sees a secret value. It receives only the broker's address in the variable you name; the broker on the host adds the credential to
            requests for the secret's upstreams. Each secret is scoped to profiles and people.
          </p>
          {secrets.error ? (
            <p className="form-note">
              The service did not list this target's secrets ({secrets.error instanceof ApiError ? `${secrets.error.code}: ${secrets.error.message}` : "unavailable"}). Type the secret name you were given;
              the plan checks that it exists on the target and is scoped to you and this profile.
            </p>
          ) : (
            target && (
              <ul className="plain-list">
                {targetSecrets.length ? (
                  targetSecrets.map((s) => {
                    const chosen = form.secrets.findIndex((x) => x.ref === s.name);
                    return (
                      <li key={s.name}>
                        <label className="check-row">
                          <input
                            type="checkbox"
                            checked={chosen >= 0}
                            disabled={s.state !== "stored" && chosen < 0}
                            onChange={(e) =>
                              set(
                                "secrets",
                                e.target.checked ? [...form.secrets, { ref: s.name, env: (s.name.replace(/-/g, "_").toUpperCase() + "_BASE_URL").replace(/^[^A-Z_]/, "S_") }] : form.secrets.filter((x) => x.ref !== s.name),
                              )
                            }
                          />
                          <span>
                            <strong>{s.name}</strong> → {s.upstreams.join(", ")} {s.state !== "stored" && <span className="badge pending">{s.state}</span>}
                            <small>
                              {s.wildcard_rules ? "Wildcard broker rules: every method and path of the upstreams." : `${s.rule_count} broker rule${s.rule_count === 1 ? "" : "s"}.`}{" "}
                              {s.usable ? `Usable by you${profileName ? ` with ${profileName}` : ""}.` : ""}
                            </small>
                            {!s.usable && <small className="field-issue">Not usable: {s.reason}. The plan will refuse it.</small>}
                          </span>
                        </label>
                      </li>
                    );
                  })
                ) : (
                  <li className="muted">{secrets.loading ? "Loading the target's secrets…" : `No secrets are stored on ${target.name}.`}</li>
                )}
              </ul>
            )
          )}
          {form.secrets.map((s, i) => (
            <div className="row-edit" key={i}>
              <label>
                Secret name
                <input value={s.ref} onChange={(e) => set("secrets", form.secrets.map((x, n) => (n === i ? { ...x, ref: e.target.value } : x)))} />
              </label>
              <label>
                Broker address variable
                <input value={s.env} spellCheck={false} onChange={(e) => set("secrets", form.secrets.map((x, n) => (n === i ? { ...x, env: e.target.value } : x)))} placeholder="ANTHROPIC_BASE_URL" />
              </label>
              <button type="button" className="icon-button" aria-label={`Remove secret ${s.ref || i + 1}`} onClick={() => set("secrets", form.secrets.filter((_, n) => n !== i))}>
                <Trash2 size={15} />
              </button>
            </div>
          ))}
          {Boolean(secrets.error) && (
            <button type="button" className="secondary" disabled={form.secrets.length >= 8} onClick={() => set("secrets", [...form.secrets, { ref: "", env: "" }])}>
              <Plus size={15} aria-hidden="true" /> Add a secret by name
            </button>
          )}
          <Issues issues={issues} field="secrets" />
        </section>
        <section className="panel">
          <h2>6. Approval</h2>
          <label className="check-row">
            <input type="radio" name="approval" checked={form.approval === "auto"} onChange={() => set("approval", "auto")} />
            <span>
              Automatic when allowed <small>Honoured only when nothing else requires a second person.</small>
            </span>
          </label>
          <label className="check-row">
            <input type="radio" name="approval" checked={form.approval === "required"} onChange={() => set("approval", "required")} />
            <span>Always require a different person to approve</span>
          </label>
          {reasons.length > 0 && (
            <div className="server-messages warn">
              <strong>This launch will probably need approval because:</strong>
              <ul>
                {reasons.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
              <small>The plan below is the authority; you cannot approve your own launch.</small>
            </div>
          )}
        </section>
        <section className="panel">
          <h2>Spec and CLI</h2>
          <p className="form-note">The UI and the CLI send the same document. Copy it to run the same launch from a terminal.</p>
          <div className="version-actions">
            <CopyButton text={json} label="Copy spec JSON" />
            <CopyButton text={`${commands.write}\n${commands.plan}\n${commands.launch}`} label="Copy as CLI commands" />
          </div>
          <details>
            <summary>Show spec JSON and CLI commands</summary>
            <CodeBlock label="agentgate.launch.v1" text={json} />
            <CodeBlock label="CLI" text={`${commands.write}\n${commands.plan}\n${commands.launch}`} />
          </details>
          {touched && built.issues.length > 0 && (
            <div className="server-messages warn" role="alert">
              <strong>Fix these before planning ({built.issues.length}):</strong>
              <ul>
                {built.issues.map((i, n) => (
                  <li key={n}>{i.message}</li>
                ))}
              </ul>
            </div>
          )}
          <Gate type="submit" allowed={p.launch && !planning} reason={!p.launch ? `Planning needs the launcher role. Your roles: ${roleText(actor)}.` : undefined}>
            {planning ? "Planning…" : "Review & plan"}
          </Gate>
        </section>
      </form>
      <section className="panel review" aria-labelledby="review-title">
        <h2 id="review-title" tabIndex={-1} ref={reviewRef}>
          Review & plan
        </h2>
        {!plan && !planError && <p className="form-note">Plan the launch to see the resolved spec digest, policy digest, effective permissions, folders, secrets, expiry and approval. Planning creates nothing.</p>}
        {Boolean(planError) && (
          <div className="error-box" role="alert">
            <div>
              <strong>The service refused the plan</strong>
              <p>
                {planError instanceof ApiError ? (
                  <>
                    <code className="verbatim">{planError.code}</code>: <span className="verbatim">{planError.message}</span>
                  </>
                ) : (
                  String((planError as Error)?.message || planError)
                )}
              </p>
            </div>
          </div>
        )}
        {plan && (
          <>
            {stale && (
              <p className="field-issue" role="alert">
                The form changed after this plan. Plan again before launching.
              </p>
            )}
            <PlanView plan={plan.plan} policy={plan.policy} />
            {Boolean(launchError) && <ErrorBox error={launchError} />}
            <div className="version-actions">
              <Gate
                allowed={!stale && !launching && p.launch}
                reason={stale ? "The form changed after the plan; plan again." : !p.launch ? "Launching needs the launcher role." : undefined}
                onClick={async () => {
                  setLaunching(true);
                  setLaunchError(undefined);
                  try {
                    const out = await api<{ launch: Launch }>("launches", "POST", JSON.parse(plannedJSON));
                    navigate(`launches/${out.launch.id}`);
                  } catch (cause) {
                    setLaunchError(cause);
                  } finally {
                    setLaunching(false);
                  }
                }}
              >
                <Rocket size={16} aria-hidden="true" /> {launching ? "Launching…" : plan.plan.approval === "required" ? "Launch (waits for approval)" : "Launch"}
              </Gate>
            </div>
          </>
        )}
      </section>
      {importing && (
        <ImportSpec
          onClose={() => setImporting(false)}
          onImport={(f) => {
            load(f);
            setImporting(false);
            setAnnounce("Spec loaded into the form. Review it and plan again.");
          }}
        />
      )}
    </>
  );
}
