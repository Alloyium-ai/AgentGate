// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Launches: the list with filters, and one launch's state timeline (live over
// Server-Sent Events with resume and a polling fallback), bounded output,
// spec and plan, evidence receipt, approval and stop.

import React, { useEffect, useMemo, useRef, useState } from "react";
import { ArrowLeft, Download, Pause, Play, RotateCcw, Square } from "lucide-react";
import { Actor, SESSION_ENDED, api, when } from "./api";
import { Empty, ErrorBox, Loading, SectionTitle } from "./components";
import { Items, Job, LAUNCH_STATES, Launch, LaunchEvent, LaunchPage, LogPage, Target, isTerminal, permissions, roleText, targetName, useResource } from "./prov-api";
import { CodeBlock, ConfirmDialog, CopyButton, Digest, Gate, KernelNotice, LiveRegion, ServerMessages, StateBadge } from "./prov-components";
import { CursorPager, useCursorPages } from "./prov-paging";
import { PlanView, usePlanPolicyCheck } from "./launch-form";
import { LogStatus, StreamStatus, followLaunch, followLog } from "./launch-stream";
import { LogBuffer, TRUNCATION_MARKER, filterLines, toText, visible } from "./log-view";
import { missingText, readEvidence } from "./evidence";
import { lifetimeText } from "./launch-spec";

function remaining(expires?: string, now = Date.now()) {
  if (!expires) return "";
  const s = Math.round((new Date(expires).getTime() - now) / 1000);
  if (!Number.isFinite(s)) return "";
  return s <= 0 ? "lifetime reached" : `ends in ${lifetimeText(s > 3600 ? s - (s % 60) : s)}`;
}

const LAUNCH_PAGE = 25;
const NAME_FILTER = /^[a-z0-9-]{1,40}$/;

export function Launches({ actor, epoch, navigate }: { actor: Actor; epoch: number; navigate: (p: string) => void }) {
  const p = permissions(actor);
  const [state, setState] = useState("");
  const [target, setTarget] = useState("");
  const [name, setName] = useState("");
  const [mine, setMine] = useState(false);
  const typed = name.trim().toLowerCase();
  const nameIssue = typed && !NAME_FILTER.test(typed) ? "A name filter is 1 to 40 of a-z, 0-9 and -." : "";
  const filters = new URLSearchParams({ limit: String(LAUNCH_PAGE) });
  if (state) filters.set("state", state);
  if (target) filters.set("target", target);
  if (typed && !nameIssue) filters.set("name", typed);
  if (mine) filters.set("mine", "true");
  const key = filters.toString();
  const pages = useCursorPages(key);
  if (pages.cursor) filters.set("cursor", pages.cursor);
  const { data, error, loading } = useResource<LaunchPage>(`launches?${filters.toString()}`, epoch);
  const targets = useResource<Items<Target>>("targets", epoch);
  const items = data?.items || [];
  return (
    <>
      <SectionTitle
        eyebrow="AGENTS"
        title="Launches"
        text="Every launch is bound to one spec digest and one policy digest. Each state change is an audit record."
        action={
          p.launch && (
            <button onClick={() => navigate("launch")}>
              <Play size={16} aria-hidden="true" /> New launch
            </button>
          )
        }
      />
      <form className="filters" onSubmit={(e) => e.preventDefault()} aria-label="Filter launches">
        <label>
          State
          <select value={state} onChange={(e) => setState(e.target.value)}>
            <option value="">All states</option>
            <option value="active">Not ended</option>
            <option value="ended">Ended</option>
            {LAUNCH_STATES.map((s) => (
              <option key={s} value={s}>
                {s.replaceAll("_", " ")}
              </option>
            ))}
          </select>
        </label>
        <label>
          Target
          <select value={target} onChange={(e) => setTarget(e.target.value)}>
            <option value="">All targets</option>
            {targets.data?.items.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Name contains
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="repo-fixer" aria-describedby="name-filter-issue" />
        </label>
        <label className="check-row inline">
          <input type="checkbox" checked={mine} onChange={(e) => setMine(e.target.checked)} />
          <span>Only mine</span>
        </label>
      </form>
      {nameIssue && (
        <p className="field-issue" id="name-filter-issue">
          {nameIssue}
        </p>
      )}
      <p className="form-note">The service applies every filter and pages the newest launches first, {LAUNCH_PAGE} at a time.</p>
      {error ? (
        <ErrorBox error={error} />
      ) : loading ? (
        <Loading />
      ) : !items.length ? (
        <Empty title="No launches match" text={p.launch ? "Start one from the Launch page." : "Launches appear here when a launcher starts one."} />
      ) : (
        <div className="table-wrap">
          <table>
            <caption className="sr-only">Launches</caption>
            <thead>
              <tr>
                <th scope="col">Launch</th>
                <th scope="col">State</th>
                <th scope="col">Target</th>
                <th scope="col">Requested by</th>
                <th scope="col">Lifetime</th>
                <th scope="col">Kernel</th>
              </tr>
            </thead>
            <tbody>
              {items.map((l) => (
                <tr key={l.id}>
                  <td>
                    <button className="row-link" onClick={() => navigate(`launches/${l.id}`)}>
                      {l.name}
                    </button>
                    <small>
                      {when(l.created_at)} · {l.mode}
                    </small>
                  </td>
                  <td>
                    <StateBadge state={l.state} />
                    {l.evidence_missing && <small>evidence missing: {l.evidence_missing}</small>}
                  </td>
                  <td>{targetName(targets.data?.items, l.target_id)}</td>
                  <td>
                    {l.requested_by}
                    {l.requested_by === actor.subject && <small>you</small>}
                  </td>
                  <td>
                    {lifetimeText(l.lifetime_seconds)}
                    <small>{!isTerminal(l.state) && remaining(l.expires_at)}</small>
                  </td>
                  <td>
                    <span className="kernel-flag">not verified</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <CursorPager page={pages.page} size={LAUNCH_PAGE} shown={items.length} next={data?.next_cursor} onNext={pages.next} onPrevious={pages.previous} />
    </>
  );
}

// ---- detail --------------------------------------------------------------------

function Timeline({ events }: { events: LaunchEvent[] }) {
  if (!events.length) return <p className="form-note">No events yet.</p>;
  return (
    <ol className="state-timeline">
      {events.map((e) => (
        <li key={e.seq} className={`event-${e.kind}`}>
          <div className="event-head">
            <span className="seq">#{e.seq}</span>
            {e.kind === "state" ? (
              <strong>
                {e.from_state ? <StateBadge state={e.from_state} /> : <span className="badge">new</span>} → <StateBadge state={e.to_state || ""} />
              </strong>
            ) : (
              <strong>{e.kind.replaceAll("_", " ")}</strong>
            )}
            <time dateTime={e.time}>{new Date(e.time).toLocaleString()}</time>
          </div>
          <p>
            <span className="muted">by</span> <code>{e.actor}</code> {e.reason && <span className="verbatim">· {e.reason}</span>}
          </p>
          {e.data && Object.keys(e.data).length > 0 && (
            <dl className="event-data">
              {Object.entries(e.data).map(([k, v]) => (
                <React.Fragment key={k}>
                  <dt>{k.replaceAll("_", " ")}</dt>
                  <dd>
                    <code className="verbatim">{typeof v === "string" ? v : JSON.stringify(v)}</code>
                  </dd>
                </React.Fragment>
              ))}
            </dl>
          )}
        </li>
      ))}
    </ol>
  );
}

function logStatusText(s?: LogStatus) {
  if (!s) return "Connecting…";
  switch (s.mode) {
    case "live":
      return "Live";
    case "connecting":
      return "Connecting…";
    case "reconnecting":
      return `Reconnecting (attempt ${s.attempt})…`;
    default:
      return s.detail || "Not following";
  }
}

function LogViewer({ id, terminal }: { id: string; terminal: boolean }) {
  const buffer = useRef(new LogBuffer(20000));
  const [, setVersion] = useState(0);
  const [paused, setPaused] = useState(false);
  const [query, setQuery] = useState("");
  const [truncated, setTruncated] = useState(false);
  const [status, setStatus] = useState<LogStatus>();
  const [done, setDone] = useState(false);
  const view = useRef<HTMLDivElement>(null);
  const ended = useRef(terminal);
  ended.current = terminal;
  useEffect(() => {
    if (paused || done) return;
    // The service streams the output (Server-Sent Events) and resumes after
    // the last line this page holds; polling is the fallback.
    const handle = followLog(id, {
      after: buffer.current.lastSeq,
      onLines: (lines) => {
        if (buffer.current.append(lines)) setVersion((v) => v + 1);
      },
      onStatus: setStatus,
      onEnd: (end) => {
        setTruncated((t) => t || end.truncated);
        setDone(true);
      },
      onTruncated: (t) => setTruncated((x) => x || t),
      ended: () => ended.current,
      onSessionEnded: () => dispatchEvent(new CustomEvent(SESSION_ENDED, { detail: "session_expired" })),
    });
    return () => handle.stop();
  }, [id, paused, done]);
  const all = buffer.current.lines;
  const shown = filterLines(all, query);
  const visibleLines = shown.slice(-2000);
  useEffect(() => {
    if (!paused && !query && view.current) view.current.scrollTop = view.current.scrollHeight;
  });
  const marker = truncated || buffer.current.hasMarker();
  return (
    <section className="panel" aria-labelledby="logs-title">
      <div className="panel-title">
        <h2 id="logs-title">Agent output</h2>
        <div className="version-actions">
          <button type="button" className="secondary" aria-pressed={paused} onClick={() => setPaused(!paused)}>
            {paused ? <Play size={15} aria-hidden="true" /> : <Pause size={15} aria-hidden="true" />} {paused ? "Follow" : "Pause"}
          </button>
          <button
            type="button"
            className="secondary"
            disabled={!all.length}
            onClick={() => {
              const url = URL.createObjectURL(new Blob([toText(all)], { type: "text/plain;charset=utf-8" }));
              const a = document.createElement("a");
              a.href = url;
              a.download = `launch-${id}-output.txt`;
              a.click();
              setTimeout(() => URL.revokeObjectURL(url), 1000);
            }}
          >
            <Download size={15} aria-hidden="true" /> Download
          </button>
        </div>
      </div>
      <label className="search">
        <span className="sr-only">Search the output</span>
        <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search the output (or type stderr)" />
      </label>
      {marker && (
        <div className="evidence-warning" role="note">
          <strong>Output truncated.</strong> The service keeps at most 1 MiB and 20,000 lines per launch; output after the limit was not stored. Lines marked{" "}
          <code>{TRUNCATION_MARKER}</code> show where.
        </div>
      )}
      {buffer.current.dropped > 0 && <p className="form-note">This page keeps the newest 20,000 lines; {buffer.current.dropped} older lines are only in the download from a fresh load.</p>}
      <div className="log-view" ref={view} tabIndex={0} role="log" aria-label="Agent output" aria-live="off">
        {visibleLines.length ? (
          visibleLines.map((l) => (
            <div key={l.seq} className={`log-line ${l.stream === "stderr" ? "stderr" : ""} ${l.text.includes(TRUNCATION_MARKER) ? "log-marker" : ""}`}>
              <span className="log-time">{l.time.slice(11, 23)}</span>
              <span className="log-stream">{l.stream}</span>
              <span className="log-text">{visible(l.text)}</span>
            </div>
          ))
        ) : (
          <p className="muted">{query ? "No line matches." : done ? "The agent produced no output." : "Waiting for output…"}</p>
        )}
      </div>
      <p className="form-note">
        {shown.length} of {all.length} lines{shown.length > 2000 ? " (showing the newest 2000 matches)" : ""}. {paused ? "Paused: new output is not fetched." : done ? "The launch ended; this is all of its output." : `Following: ${logStatusText(status)}.`} Output is shown as plain text; control
        characters appear as escapes.
      </p>
    </section>
  );
}

function Receipt({ launch }: { launch: Launch }) {
  const r = launch.receipt;
  if (!r) {
    if (isTerminal(launch.state))
      return (
        <section className="panel evidence-missing" role="alert">
          <h2>No evidence receipt</h2>
          <p>
            <strong>evidence_missing: {launch.evidence_missing || "not recorded"}</strong>
          </p>
          <p>{missingText(launch.evidence_missing || "receipt_missing")}</p>
          {launch.terminal_reason && (
            <p>
              Terminal reason: <code className="verbatim">{launch.terminal_reason}</code>
            </p>
          )}
        </section>
      );
    return (
      <section className="panel">
        <h2>Evidence receipt</h2>
        <p className="form-note">The host returns the receipt when the launch stops, expires or fails.</p>
      </section>
    );
  }
  const ev = readEvidence(r.network_evidence, r.host_control_evidence);
  const same = (a?: string, b?: string) => (a && b && a === b ? "matches the launch" : "DIFFERS from the launch");
  return (
    <section className="panel" aria-labelledby="receipt-title">
      <h2 id="receipt-title">Evidence receipt</h2>
      <KernelNotice />
      <p className="form-note">
        The host reports these facts. The service checks their shape and digests; it cannot prove what ran on a compromised host (see docs/PROVISIONING.md,
        Trusted computing base).
      </p>
      <div className="metadata">
        <div>
          <span>Spec digest</span>
          <strong>
            <Digest value={r.spec_digest} /> {same(r.spec_digest, launch.spec_digest)}
          </strong>
        </div>
        <div>
          <span>Policy digest</span>
          <strong>
            <Digest value={r.policy_digest} /> {same(r.policy_digest, launch.policy_digest)}
          </strong>
        </div>
        <div>
          <span>Guard binary</span>
          <Digest value={r.guard_digest} />
        </div>
        <div>
          <span>Domain empty at the end</span>
          <strong>{r.domain_empty ? "yes" : "NO"}</strong>
        </div>
        <div>
          <span>Enforcement released</span>
          <strong>{r.enforcement_released ? "yes" : "NO"}</strong>
        </div>
        <div>
          <span>Exit</span>
          <strong>
            {r.exit_code ?? "—"} · {r.reason}
          </strong>
        </div>
        <div>
          <span>Ran</span>
          <strong>
            {r.started_at_ms ? new Date(r.started_at_ms).toLocaleString() : "—"} to {r.ended_at_ms ? new Date(r.ended_at_ms).toLocaleString() : "—"}
          </strong>
        </div>
        <div>
          <span>Kernel verified</span>
          <strong>no — kernel enforcement not yet verified on this host</strong>
        </div>
      </div>
      <h3 className="subheading">Object digests</h3>
      <ul className="plain-list">
        {Object.entries(r.bpf_objects || {}).map(([k, v]) => (
          <li key={k}>
            <code>{k}</code> <Digest value={v} />
          </li>
        ))}
        {!Object.keys(r.bpf_objects || {}).length && <li className="muted">none reported</li>}
      </ul>
      <h3 className="subheading">Host folders</h3>
      <ul className="plain-list">
        {(r.mounts || []).map((m) => (
          <li key={m.name}>
            {m.name} ({m.mode}): <code>{m.identity}</code>
          </li>
        ))}
        {!r.mounts?.length && <li className="muted">none</li>}
      </ul>
      <h3 className="subheading">Broker requests per upstream</h3>
      <ul className="plain-list">
        {Object.entries(r.broker_counts || {}).map(([k, v]) => (
          <li key={k}>
            <code>{k}</code>: {v}
          </li>
        ))}
        {!Object.keys(r.broker_counts || {}).length && <li className="muted">none</li>}
      </ul>
      {[...ev.rings, ...(ev.network ? [ev.network] : [])].map((ring) => (
        <div key={ring.name}>
          <h3 className="subheading">
            {ring.name === "network" ? "Network" : ring.name === "filesystem" ? "Filesystem" : "Process"} decisions{" "}
            {ring.complete === false ? <span className="badge incomplete">incomplete</span> : ring.complete ? <span className="badge allowed">complete</span> : null}
          </h3>
          <p className="form-note">
            Decisions {ring.decisions ?? "not reported"} · observed {ring.observed ?? "not reported"} · lost {ring.lost ?? "not reported"}
            {ring.lost ? " (some decisions were not recorded)" : ""}
          </p>
          {ring.operations.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th scope="col">{ring.name === "network" ? "Hook" : "Operation"}</th>
                    <th scope="col">Allowed</th>
                    <th scope="col">Denied</th>
                  </tr>
                </thead>
                <tbody>
                  {ring.operations.map((o) => (
                    <tr key={o.operation}>
                      <td>{o.operation}</td>
                      <td>{o.allowed}</td>
                      <td>{o.denied}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {ring.denials.length > 0 && (
            <>
              <h4>First denials{ring.denialsTruncated ? " (more were not kept)" : ""}</h4>
              <ul className="plain-list">
                {ring.denials.slice(0, 25).map((d, i) => (
                  <li key={i}>
                    <code>{d.operation}</code> <code className="verbatim">{visible(d.path || (d.target ? `pid ${d.target}` : "—"))}</code> {d.pid !== undefined && <small>pid {d.pid}</small>}
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      ))}
      {!ev.rings.length && !ev.network && <p className="form-note">The receipt carries no decision counters.</p>}
      {ev.trimmed && <p className="form-note">The host trimmed lists to fit the 128 KiB receipt bound; counts and digests are kept.</p>}
      {ev.networkFacts.length > 0 && (
        <div className="metadata">
          {ev.networkFacts.map((f) => (
            <div key={f.label}>
              <span>{f.label}</span>
              <code className="verbatim">{visible(f.value)}</code>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function statusText(s?: StreamStatus) {
  if (!s) return "Connecting…";
  switch (s.mode) {
    case "live":
      return "Live";
    case "connecting":
      return "Connecting…";
    case "reconnecting":
      return `Reconnecting (attempt ${s.attempt})…`;
    case "polling":
      return s.detail || "Polling";
    default:
      return s.detail || "Not following";
  }
}

export function LaunchDetail({ id, actor, epoch, navigate }: { id: string; actor: Actor; epoch: number; navigate: (p: string) => void }) {
  const p = permissions(actor);
  const detail = useResource<{ launch: Launch; jobs: Job[] }>(`launches/${encodeURIComponent(id)}`, epoch);
  const targets = useResource<Items<Target>>("targets", epoch);
  const [events, setEvents] = useState<LaunchEvent[]>([]);
  const [stream, setStream] = useState<StreamStatus>();
  const [announce, setAnnounce] = useState("");
  const [dialog, setDialog] = useState<"approve" | "reject" | "stop">();
  const [stopRequested, setStopRequested] = useState<string>();
  const [, setNow] = useState(0);
  const reload = useRef(detail.reload);
  reload.current = detail.reload;
  const policyCheck = usePlanPolicyCheck(detail.data?.launch.plan);
  useEffect(() => {
    const t = setInterval(() => setNow((x) => x + 1), 30000);
    return () => clearInterval(t);
  }, []);
  useEffect(() => {
    setEvents([]);
    let refreshTimer: ReturnType<typeof setTimeout>;
    const handle = followLaunch(id, {
      after: 0,
      onEvent: (e) => {
        const ev = e as unknown as LaunchEvent;
        setEvents((list) => (list.some((x) => x.seq === ev.seq) ? list : [...list, ev].slice(-5000)));
        if (ev.kind === "state" && ev.to_state) setAnnounce(`Launch is now ${ev.to_state.replaceAll("_", " ")}.`);
        if (ev.kind === "state" || ev.kind === "receipt") {
          clearTimeout(refreshTimer);
          refreshTimer = setTimeout(() => reload.current(), 300);
        }
      },
      onStatus: setStream,
      onSessionEnded: () => dispatchEvent(new CustomEvent(SESSION_ENDED, { detail: "session_expired" })),
    });
    return () => {
      clearTimeout(refreshTimer);
      handle.stop();
    };
  }, [id]);
  if (detail.loading) return <Loading />;
  if (detail.error || !detail.data) return <ErrorBox error={detail.error} />;
  const l = detail.data.launch;
  const terminal = isTerminal(l.state);
  const mine = l.requested_by === actor.subject;
  const approveReason = !p.approve
    ? `Deciding launches needs the approver role. Your roles: ${roleText(actor)}.`
    : l.state !== "approval_pending"
      ? `The launch is ${l.state.replaceAll("_", " ")}; only a launch waiting for approval can be decided.`
      : mine
        ? "You requested this launch. A different person must decide it."
        : undefined;
  // A plan whose broker settings do not make the sealed policy digest it names
  // shows something other than what the host would run: never approve it.
  const policyRefusal = !policyCheck.checked
    ? "Checking the plan's sealed broker policies…"
    : policyCheck.bad.length
      ? `The plan's broker settings for ${policyCheck.bad.join(", ")} do not make the sealed policy digest it names. Reject the launch and report it.`
      : undefined;
  const approveBlocked = approveReason ?? policyRefusal;
  const stopReason = !p.launch
    ? `Stopping needs the launcher role. Your roles: ${roleText(actor)}.`
    : terminal
      ? "The launch has ended."
      : l.state === "stopping"
        ? "Stop requested; waiting for the host to confirm an empty domain and released enforcement."
        : undefined;
  const sortedEvents = [...events].sort((a, b) => a.seq - b.seq);
  return (
    <>
      <button className="back-link" onClick={() => navigate("launches")}>
        <ArrowLeft size={15} /> All launches
      </button>
      <SectionTitle
        eyebrow="LAUNCH"
        title={l.name}
        text={`${l.mode === "oneshot" ? "One-shot" : "Session"} on ${targetName(targets.data?.items, l.target_id)} · requested by ${l.requested_by}${mine ? " (you)" : ""} · ${when(l.created_at)}`}
        action={<StateBadge state={l.state} />}
      />
      <LiveRegion message={announce} />
      <div className="stream-status" role="status">
        <span className={`dot ${stream?.mode || "connecting"}`} aria-hidden="true" /> Updates: {statusText(stream)}
      </div>
      {l.state === "stopping" && (
        <div className="evidence-warning" role="status">
          Stop requested{stopRequested ? ` at ${stopRequested}` : ""}. The launch ends stopped or expired only after the host confirms an empty domain and released
          enforcement; otherwise it ends failed and another stop is queued.
        </div>
      )}
      {terminal && l.evidence_missing && (
        <div className="error-box" role="alert">
          <div>
            <strong>Evidence missing: {l.evidence_missing}</strong>
            <p>{missingText(l.evidence_missing)}</p>
          </div>
        </div>
      )}
      <KernelNotice />
      <section className="panel">
        <div className="metadata">
          <div>
            <span>Spec digest</span>
            <Digest value={l.spec_digest} label="Spec digest" />
          </div>
          <div>
            <span>Policy digest</span>
            <Digest value={l.policy_digest} label="Policy digest" />
          </div>
          <div>
            <span>Lifetime</span>
            <strong>
              {lifetimeText(l.lifetime_seconds)}
              {terminal
                ? l.ended_at
                  ? ` · ended ${new Date(l.ended_at).toLocaleString()}`
                  : " · ended"
                : l.expires_at
                  ? ` · expires ${new Date(l.expires_at).toLocaleString()} (${remaining(l.expires_at)})`
                  : " · the clock starts when the launch is queued"}
            </strong>
          </div>
          <div>
            <span>Approval</span>
            <strong>
              {l.approval_required ? "required" : "automatic"}
              {l.decided_by ? ` · decided by ${l.decided_by}: ${l.decision_reason}` : ""}
            </strong>
          </div>
          {l.stop_reason && (
            <div>
              <span>Stop reason</span>
              <strong className="verbatim">{l.stop_reason}</strong>
            </div>
          )}
          {l.terminal_reason && (
            <div>
              <span>Terminal reason</span>
              <strong className="verbatim">{l.terminal_reason}</strong>
            </div>
          )}
          <div>
            <span>Kernel verified</span>
            <strong>no — kernel enforcement not yet verified on this host</strong>
          </div>
        </div>
        <div className="version-actions">
          <Gate allowed={!approveBlocked} reason={approveBlocked} onClick={() => setDialog("approve")}>
            Approve
          </Gate>
          <Gate className="secondary danger" allowed={!approveReason} reason={approveReason} onClick={() => setDialog("reject")}>
            Reject
          </Gate>
          <Gate className="secondary danger" allowed={!stopReason} reason={stopReason} onClick={() => setDialog("stop")}>
            <Square size={14} aria-hidden="true" /> {l.state === "stopping" ? "Stopping…" : "Stop"}
          </Gate>
          {p.launch && (
            <button className="secondary" onClick={() => navigate(`launch/from/${l.id}`)}>
              <RotateCcw size={15} aria-hidden="true" /> Launch again from this spec
            </button>
          )}
          <CopyButton
            text={`agentgate show ${l.id}\nagentgate events ${l.id} -f\nagentgate logs ${l.id} -f\nagentgate approve ${l.id} --reason "Reviewed the plan"\nagentgate stop ${l.id} --reason "Done" --wait`}
            label="Copy CLI commands"
          />
        </div>
      </section>
      <section className="panel" aria-labelledby="timeline-title">
        <h2 id="timeline-title">State timeline</h2>
        <Timeline events={sortedEvents} />
      </section>
      <LogViewer id={l.id} terminal={terminal} />
      <Receipt launch={l} />
      {l.plan && (
        <section className="panel">
          <h2>Plan (stored with the launch; never changes)</h2>
          <PlanView plan={l.plan} policy={l.policy} />
        </section>
      )}
      <section className="panel">
        <h2>Spec</h2>
        {l.spec && <CodeBlock label="agentgate.launch.v1 (canonical)" text={JSON.stringify(l.spec, null, 2)} />}
        <h3 className="subheading">Host jobs</h3>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Job</th>
                <th scope="col">State</th>
                <th scope="col">Attempts</th>
                <th scope="col">Created</th>
                <th scope="col">Deadline</th>
              </tr>
            </thead>
            <tbody>
              {detail.data.jobs.map((j) => (
                <tr key={j.id}>
                  <td>
                    {j.type}
                    <small>{j.id}</small>
                  </td>
                  <td>
                    <StateBadge state={j.state} />
                  </td>
                  <td>{j.attempts}</td>
                  <td>{when(j.created_at)}</td>
                  <td>{when(j.deadline)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      {(dialog === "approve" || dialog === "reject") && (
        <ConfirmDialog
          title={`${dialog === "approve" ? "Approve" : "Reject"} ${l.name}`}
          confirmLabel={dialog === "approve" ? "Approve this exact plan" : "Reject launch"}
          danger={dialog === "reject"}
          onClose={() => setDialog(undefined)}
          onConfirm={async (reason) => {
            await api(`launches/${l.id}/${dialog}`, "POST", { reason });
            setDialog(undefined);
            setAnnounce(dialog === "approve" ? "Approved." : "Rejected.");
            detail.reload();
          }}
        >
          <p>
            {dialog === "approve"
              ? "Approving covers exactly this plan: the spec and policy digests below. The lifetime clock starts and the launch is queued for the host."
              : "Rejecting ends the launch; nothing runs."}
          </p>
          <div className="metadata">
            <div>
              <span>Spec digest</span>
              <code>{l.spec_digest}</code>
            </div>
            <div>
              <span>Policy digest</span>
              <code>{l.policy_digest}</code>
            </div>
            {dialog === "approve" &&
              (l.plan?.secrets ?? []).map((s) => (
                <div key={s.ref}>
                  <span>Secret {s.ref}: sealed broker policy (checked against the settings shown in the plan)</span>
                  <code>{s.policy_digest}</code>
                </div>
              ))}
          </div>
          <ServerMessages title="Why approval is needed" items={l.plan?.approval_reasons} tone="warn" />
        </ConfirmDialog>
      )}
      {dialog === "stop" && (
        <ConfirmDialog
          title={`Stop ${l.name}`}
          confirmLabel="Stop launch"
          danger
          onClose={() => setDialog(undefined)}
          onConfirm={async (reason) => {
            await api(`launches/${l.id}/stop`, "POST", { reason });
            setDialog(undefined);
            setStopRequested(new Date().toLocaleTimeString());
            setAnnounce("Stop requested.");
            detail.reload();
          }}
        >
          <p>
            Stopping is safe to repeat. A launch that never reached its host is cancelled. Otherwise it moves to stopping and one stop job tells the host to kill
            every process in the sandbox, release enforcement and return the receipt.
          </p>
        </ConfirmDialog>
      )}
    </>
  );
}
