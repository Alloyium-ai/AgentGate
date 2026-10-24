// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Targets: hosts that run agentgate-hostd. An administrator adds a target
// (one-time enrollment token), compares and approves the host key the host
// presented, re-enrolls, renames and retires it.

import React, { useMemo, useState } from "react";
import { ArrowLeft, KeyRound, Plus, RefreshCw, Server } from "lucide-react";
import { Actor, api } from "./api";
import { Empty, ErrorBox, Loading, Modal, SectionTitle } from "./components";
import { Enrollment, Items, Target, ago, permissions, roleText, useResource } from "./prov-api";
import { Capabilities, CodeBlock, ConfirmDialog, CopyButton, Gate, KernelNotice, LiveRegion, OneTimeSecret, StateBadge } from "./prov-components";
import { ClientPager, useClientPages } from "./prov-paging";
import { writePin } from "./secretseal";

const NAME = /^[a-z0-9][a-z0-9-]{0,39}$/;

export function targetKind(t: Target) {
  if (t.capabilities?.includes("appliance")) return "Appliance VM";
  if (t.capabilities?.includes("docker")) return "Docker host";
  return "Not reported";
}

export function health(t: Target) {
  switch (t.state) {
    case "pending":
      return "Waiting for the host to enroll";
    case "awaiting_key_approval":
      return "Enrolled; host key waits for approval";
    case "rekey_required":
      return "The job key rotated; enroll the host again";
    case "retired":
      return "Retired";
  }
  if (t.state !== "active") return t.state;
  return t.online ? `Online · heartbeat ${ago(t.last_seen_at)}` : `Offline · last heartbeat ${ago(t.last_seen_at)}`;
}

export function enrollCommand(token: string, runtime: string, origin = location.origin) {
  const loopback = /^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/.test(origin);
  const flags = [`--service-url ${origin}`, "--token-file agentgate-enroll.token", `--runtime ${runtime}`];
  if (loopback) flags.push("--allow-loopback-http");
  if (runtime === "appliance") flags.push("--appliance-state /var/lib/agentgate-appliance", "--source /opt/agentgate");
  return ["umask 077", `printf '%s\\n' '${token}' > agentgate-enroll.token`, `sudo agentgate-hostd install \\\n  ${flags.join(" \\\n  ")}`, "rm -f agentgate-enroll.token"].join("\n");
}

function EnrollmentPanel({ enrollment, runtime }: { enrollment: Enrollment; runtime: string }) {
  return (
    <>
      <OneTimeSecret label="One-time enrollment token" value={enrollment.token} note={`It works once and expires ${new Date(enrollment.expires_at).toLocaleTimeString()} (15 minutes). The service stores only its hash.`} />
      <CodeBlock label="Run on the host (as root)" text={enrollCommand(enrollment.token, runtime)} />
      <p className="form-note">
        The token goes in a file because command-line arguments are visible to other users of the host. After it enrolls, the target waits in
        "Awaiting host key approval": compare the host key fingerprint before you approve it.
      </p>
    </>
  );
}

function AddTarget({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState("");
  const [reason, setReason] = useState("");
  const [runtime, setRuntime] = useState("docker-host");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [result, setResult] = useState<{ target: Target; enrollment: Enrollment }>();
  const close = () => {
    setResult(undefined);
    if (result) onDone();
    onClose();
  };
  return (
    <Modal title={result ? `Enroll ${result.target.name}` : "Add a target"} onClose={close}>
      {result ? (
        <>
          <EnrollmentPanel enrollment={result.enrollment} runtime={runtime} />
          <div className="modal-actions">
            <button onClick={close}>I copied the token</button>
          </div>
        </>
      ) : (
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError(undefined);
            try {
              setResult(await api<{ target: Target; enrollment: Enrollment }>("targets", "POST", { name, reason }));
            } catch (cause) {
              setError(cause);
            } finally {
              setBusy(false);
            }
          }}
        >
          <label>
            Target name
            <input autoFocus value={name} onChange={(e) => setName(e.target.value)} required pattern="[a-z0-9][a-z0-9\-]{0,39}" maxLength={40} placeholder="build-host" aria-describedby="target-name-help" />
          </label>
          <small id="target-name-help" className="help">
            Lowercase letters, digits and -; launch specs name the target this way.
          </small>
          <label>
            Host runtime
            <select value={runtime} onChange={(e) => setRuntime(e.target.value)}>
              <option value="docker-host">Docker host (agents run as containers on this host)</option>
              <option value="appliance">Appliance VM (agents run in the AgentGate appliance)</option>
            </select>
          </label>
          <label>
            Reason
            <textarea value={reason} onChange={(e) => setReason(e.target.value)} required minLength={3} maxLength={512} placeholder="Why this host joins the control plane" />
          </label>
          {Boolean(error) && <ErrorBox error={error} />}
          <div className="modal-actions">
            <button type="button" className="secondary" onClick={onClose}>
              Cancel
            </button>
            <button disabled={busy || !NAME.test(name) || reason.trim().length < 3}>{busy ? "Creating…" : "Create target and token"}</button>
          </div>
        </form>
      )}
    </Modal>
  );
}

function ApproveKey({ target, onClose, onDone }: { target: Target; onClose: () => void; onDone: () => void }) {
  const [typed, setTyped] = useState("");
  const [compared, setCompared] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const entered = typed.trim();
  const matches = entered === target.host_key_id;
  return (
    <Modal title={`Approve the host key of ${target.name}`} onClose={onClose}>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(undefined);
          try {
            await api(`targets/${target.id}/approve-key`, "POST", { host_key_id: entered, reason });
            // The administrator compared this fingerprint on the host console:
            // pin it in this browser for sealing secrets later.
            writePin(target.id, entered);
            onDone();
          } catch (cause) {
            setError(cause);
          } finally {
            setBusy(false);
          }
        }}
      >
        <div className="fingerprint-compare">
          <span>The service received this host key</span>
          <code className="fingerprint">{target.host_key_id || "—"}</code>
          <small>
            from {target.hostname || "an unnamed host"} · agent {target.agent_version || "unknown"}
          </small>
        </div>
        <ol className="steps">
          <li>
            On the host console, read the fingerprint <code>agentgate-hostd install</code> reported when it enrolled. If your build does not print it, run{" "}
            <code>sudo grep host_key_id /var/lib/agentgate-hostd/identity.json</code>.
          </li>
          <li>Paste or type that fingerprint below. Do not copy it from this page.</li>
          <li>Approve only if they match. A token intercepted in transit cannot activate another key without this step.</li>
        </ol>
        <label>
          Fingerprint shown on the host
          <input value={typed} onChange={(e) => setTyped(e.target.value)} placeholder="ed25519:…" spellCheck={false} autoComplete="off" aria-describedby="fingerprint-result" />
        </label>
        <p id="fingerprint-result" role="status" aria-live="polite" className={entered ? (matches ? "match ok" : "match bad") : "match"}>
          {!entered ? "Waiting for the fingerprint from the host." : matches ? "Match: the fingerprints are identical." : "No match. Do not approve. Issue a new enrollment token and enroll the host again."}
        </p>
        {matches && (
          <>
            <label className="check-row">
              <input type="checkbox" checked={compared} onChange={(e) => setCompared(e.target.checked)} />
              <span>I read this fingerprint on the host itself, not from a message or this page.</span>
            </label>
            <label>
              Reason
              <textarea value={reason} onChange={(e) => setReason(e.target.value)} required minLength={3} maxLength={512} placeholder="Matches the host console" />
            </label>
          </>
        )}
        {Boolean(error) && <ErrorBox error={error} />}
        <div className="modal-actions">
          <button type="button" className="secondary" onClick={onClose}>
            Cancel
          </button>
          <button disabled={busy || !matches || !compared || reason.trim().length < 3}>{busy ? "Approving…" : "Approve host key"}</button>
        </div>
      </form>
    </Modal>
  );
}

function Reenroll({ target, onClose, onDone }: { target: Target; onClose: () => void; onDone: () => void }) {
  const [result, setResult] = useState<Enrollment>();
  const [runtime, setRuntime] = useState(target.capabilities?.includes("appliance") ? "appliance" : "docker-host");
  if (result)
    return (
      <Modal
        title={`Enroll ${target.name} again`}
        onClose={() => {
          setResult(undefined);
          onDone();
        }}
      >
        <EnrollmentPanel enrollment={result} runtime={runtime} />
        <div className="modal-actions">
          <button
            onClick={() => {
              setResult(undefined);
              onDone();
            }}
          >
            I copied the token
          </button>
        </div>
      </Modal>
    );
  return (
    <ConfirmDialog
      title={`New enrollment token for ${target.name}`}
      confirmLabel="Issue a one-time token"
      onClose={onClose}
      onConfirm={async (reason) => {
        const out = await api<{ enrollment: Enrollment }>(`targets/${target.id}/enrollment`, "POST", { reason });
        setResult(out.enrollment);
      }}
    >
      <p>
        Use this after a host reinstall or a job key rotation. When the host enrolls with the new token, its old key is retired and the target's queued
        jobs are cancelled. The service refuses while the target has a launch that has not ended.
      </p>
      <label>
        Host runtime
        <select value={runtime} onChange={(e) => setRuntime(e.target.value)}>
          <option value="docker-host">Docker host</option>
          <option value="appliance">Appliance VM</option>
        </select>
      </label>
    </ConfirmDialog>
  );
}

function Rename({ target, onClose, onDone }: { target: Target; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState(target.name);
  return (
    <ConfirmDialog
      title={`Rename ${target.name}`}
      confirmLabel="Rename"
      onClose={onClose}
      onConfirm={async (reason) => {
        if (!NAME.test(name)) throw new Error("A target name matches ^[a-z0-9][a-z0-9-]{0,39}$.");
        await api(`targets/${target.id}`, "PATCH", { name, reason });
        onDone();
      }}
    >
      <label>
        New name
        <input value={name} onChange={(e) => setName(e.target.value)} pattern="[a-z0-9][a-z0-9\-]{0,39}" maxLength={40} />
      </label>
      <p className="form-note">Launch specs that name the old target name stop resolving. Stored launches keep the target id.</p>
    </ConfirmDialog>
  );
}

function TargetActions({ target, actor, onChanged }: { target: Target; actor: Actor; onChanged: () => void }) {
  const p = permissions(actor);
  const [dialog, setDialog] = useState<"approve" | "enroll" | "rename" | "retire">();
  const notAdmin = `Only an administrator manages targets. Your roles: ${roleText(actor)}.`;
  const retired = target.state === "retired";
  const done = () => {
    setDialog(undefined);
    onChanged();
  };
  return (
    <div className="version-actions">
      {target.state === "awaiting_key_approval" && (
        <Gate allowed={p.targetsAdmin} reason={notAdmin} onClick={() => setDialog("approve")}>
          <KeyRound size={15} aria-hidden="true" /> Approve host key
        </Gate>
      )}
      <Gate className="secondary" allowed={p.targetsAdmin && !retired} reason={retired ? "A retired target cannot enroll." : notAdmin} onClick={() => setDialog("enroll")}>
        <RefreshCw size={15} aria-hidden="true" /> New enrollment token
      </Gate>
      <Gate className="secondary" allowed={p.targetsAdmin && !retired} reason={retired ? "A retired target cannot change." : notAdmin} onClick={() => setDialog("rename")}>
        Rename
      </Gate>
      <Gate className="secondary danger" allowed={p.targetsAdmin && !retired} reason={retired ? "Already retired." : notAdmin} onClick={() => setDialog("retire")}>
        Retire
      </Gate>
      {dialog === "approve" && <ApproveKey target={target} onClose={() => setDialog(undefined)} onDone={done} />}
      {dialog === "enroll" && <Reenroll target={target} onClose={() => setDialog(undefined)} onDone={done} />}
      {dialog === "rename" && <Rename target={target} onClose={() => setDialog(undefined)} onDone={done} />}
      {dialog === "retire" && (
        <ConfirmDialog
          title={`Retire ${target.name}`}
          confirmLabel="Retire target"
          danger
          typeToConfirm={target.name}
          onClose={() => setDialog(undefined)}
          onConfirm={async (reason) => {
            await api(`targets/${target.id}`, "DELETE", { reason });
            done();
          }}
        >
          <p>
            Retiring revokes the host key (later polls are refused), cancels queued jobs, voids unused enrollment tokens and marks this target's secrets
            deleted. The service refuses while any launch on the target has not ended. It does not send a removal job to a retired host, so remove the host
            agent's state on the host yourself.
          </p>
        </ConfirmDialog>
      )}
    </div>
  );
}

export function TargetDetail({ id, actor, epoch, navigate }: { id: string; actor: Actor; epoch: number; navigate: (p: string) => void }) {
  const t = useResource<Target>(`targets/${encodeURIComponent(id)}`, epoch);
  const [announce, setAnnounce] = useState("");
  if (t.loading) return <Loading />;
  if (t.error || !t.data) return <ErrorBox error={t.error} />;
  const target = t.data;
  return (
    <>
      <button className="back-link" onClick={() => navigate("targets")}>
        <ArrowLeft size={15} /> All targets
      </button>
      <SectionTitle eyebrow="TARGET" title={target.name} text={health(target)} action={<StateBadge state={target.state} />} />
      <LiveRegion message={announce} />
      <KernelNotice />
      <section className="panel">
        <div className="panel-title">
          <h2>Host</h2>
          <Server size={19} aria-hidden="true" />
        </div>
        <div className="metadata">
          <div>
            <span>Kind</span>
            <strong>{targetKind(target)}</strong>
          </div>
          <div>
            <span>Capabilities</span>
            <Capabilities caps={target.capabilities} />
          </div>
          <div>
            <span>Hostname</span>
            <strong>{target.hostname || "—"}</strong>
          </div>
          <div>
            <span>Agent version</span>
            <strong>{target.agent_version || "—"}</strong>
          </div>
          <div>
            <span>Last heartbeat</span>
            <strong>{target.last_seen_at ? `${new Date(target.last_seen_at).toLocaleString()} (${ago(target.last_seen_at)})` : "never"}</strong>
          </div>
          <div>
            <span>Heartbeat interval</span>
            <strong>{target.heartbeat_seconds} s (lost after 3 missed)</strong>
          </div>
          <div>
            <span>Host key fingerprint</span>
            <code className="fingerprint">{target.host_key_id || "not enrolled"}</code>
          </div>
          <div>
            <span>Service job key</span>
            <code>{target.job_key_id || "—"}</code>
          </div>
          <div>
            <span>Kernel verified</span>
            <strong>no — {target.kernel_verified ? "the API reported true, which protocol v1 never allows; treat as unverified" : "not yet verified on this host"}</strong>
          </div>
          <div>
            <span>Target id</span>
            <code>{target.id}</code> <CopyButton text={target.id} label="Copy id" className="icon-copy" />
          </div>
        </div>
        <TargetActions
          target={target}
          actor={actor}
          onChanged={() => {
            setAnnounce(`Target ${target.name} updated.`);
            t.reload();
          }}
        />
      </section>
    </>
  );
}

export function Targets({ actor, epoch, navigate }: { actor: Actor; epoch: number; navigate: (p: string) => void }) {
  const p = permissions(actor);
  const { data, error, loading, reload } = useResource<Items<Target>>("targets", epoch);
  const [adding, setAdding] = useState(false);
  const [showRetired, setShowRetired] = useState(false);
  const items = useMemo(() => (data?.items || []).filter((t) => showRetired || t.state !== "retired"), [data, showRetired]);
  const pages = useClientPages(items, 25);
  return (
    <>
      <SectionTitle
        eyebrow="ENFORCEMENT HOSTS"
        title="Targets"
        text="Hosts that run agentgate-hostd. A host joins with a one-time token, and its key becomes active only after an administrator compares and approves it."
        action={
          <Gate allowed={p.targetsAdmin} reason={`Only an administrator adds targets. Your roles: ${roleText(actor)}.`} onClick={() => setAdding(true)}>
            <Plus size={17} aria-hidden="true" /> Add target
          </Gate>
        }
      />
      <KernelNotice />
      <div className="table-toolbar">
        <label className="check-row inline">
          <input type="checkbox" checked={showRetired} onChange={(e) => setShowRetired(e.target.checked)} />
          <span>Show retired targets</span>
        </label>
        <span>{items.length} targets</span>
      </div>
      {error ? (
        <ErrorBox error={error} />
      ) : loading ? (
        <Loading />
      ) : !items.length ? (
        <Empty title="No targets yet" text="Add a target, run the enrollment command on the host, then approve its key." />
      ) : (
        <div className="table-wrap">
          <table>
            <caption className="sr-only">Targets</caption>
            <thead>
              <tr>
                <th scope="col">Target</th>
                <th scope="col">State</th>
                <th scope="col">Health</th>
                <th scope="col">Kind and capabilities</th>
                <th scope="col">Kernel</th>
              </tr>
            </thead>
            <tbody>
              {pages.items.map((t) => (
                <tr key={t.id}>
                  <td>
                    <button className="row-link" onClick={() => navigate(`targets/${t.id}`)}>
                      {t.name}
                    </button>
                    <small>{t.hostname || "no host yet"}</small>
                  </td>
                  <td>
                    <StateBadge state={t.state} />
                  </td>
                  <td>
                    <span className={`health ${t.state === "active" ? (t.online ? "online" : "offline") : ""}`}>{health(t)}</span>
                  </td>
                  <td>
                    <strong>{targetKind(t)}</strong>
                    <Capabilities caps={t.capabilities} />
                  </td>
                  <td>
                    <KernelNotice compact />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <ClientPager {...pages} />
      {adding && <AddTarget onClose={() => setAdding(false)} onDone={reload} />}
    </>
  );
}
