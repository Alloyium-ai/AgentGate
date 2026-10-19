// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

import React, { useEffect, useState } from "react";
import {
  ArrowUpRight,
  Plus,
  ShieldCheck,
  Clock,
  FileCheck2,
  Activity,
  ChevronRight,
  ArrowLeft,
  Check,
  X,
  History,
  Search,
  Download,
  Copy,
} from "lucide-react";
import {
  Actor,
  Policy,
  Version,
  Request,
  Run,
  Audit,
  Page,
  Rights,
  api,
  can,
  short,
  when,
  isCustomerPolicy,
} from "./api";
import {
  Badge,
  Empty,
  Loading,
  ErrorBox,
  RightsView,
  Diff,
  Modal,
  Pager,
  SectionTitle,
} from "./components";
import { PolicyProfile, PolicyWorkflow } from "./policy-profile";
import { CustomerPolicyEditor } from "./policy-editor";
import { RequestedPolicy, TargetPreview, usePolicyDocument } from "./policy-workspace";
import { PolicyDocument } from "./policy-schema";
export function useData<T>(path: string, epoch: number) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<unknown>();
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let live = true;
    setLoading(!data);
    setError(undefined);
    api<T>(path)
      .then((v) => {
        if (live) setData(v);
      })
      .catch((e) => {
        if (live) setError(e);
      })
      .finally(() => {
        if (live) setLoading(false);
      });
    return () => {
      live = false;
    };
  }, [path, epoch]);
  return { data, error, loading };
}
function usePaging(scope = "") {
  const [page, setPage] = useState({ scope, stack: [""] });
  const stack = page.scope === scope ? page.stack : [""];
  useEffect(() => {
    setPage((current) => current.scope === scope ? current : { scope, stack: [""] });
  }, [scope]);
  return {
    cursor: stack.at(-1) || "",
    back: stack.length > 1,
    next: (c: string) => setPage({ scope, stack: [...stack, c] }),
    previous: () => setPage({ scope, stack: stack.slice(0, -1) }),
    reset: () => setPage({ scope, stack: [""] }),
  };
}
export function Overview({
  epoch,
  navigate,
}: {
  epoch: number;
  navigate: (path: string) => void;
}) {
  const { data, error, loading } = useData<Record<string, any>>(
    "overview",
    epoch,
  );
  if (loading) return <Loading />;
  return (
    <>
      <SectionTitle
        eyebrow="CONTROL CENTER"
        title="Keep intent and execution in view."
        text="Review policy decisions, follow worker runs, and inspect the evidence behind them."
      />
      {Boolean(error) && <ErrorBox error={error} />}
      <div className="stats">
        {[
          {
            name: "Policy families",
            field: "policies",
            icon: ShieldCheck,
            to: "policies",
          },
          {
            name: "Awaiting a decision",
            field: "pending_requests",
            icon: Clock,
            to: "requests",
          },
          { name: "Recorded runs", field: "runs", icon: Activity, to: "runs" },
          {
            name: "Evidence needs review",
            field: "incomplete_runs",
            icon: FileCheck2,
            to: "runs",
          },
        ].map(({ name, field, icon: Icon, to }) => (
          <button className="stat" onClick={() => navigate(to)} key={field}>
            <div>
              <Icon size={20} />
              <ArrowUpRight size={17} />
            </div>
            <strong>{data?.[field] ?? "—"}</strong>
            <span>{name}</span>
          </button>
        ))}
      </div>
      <div className="overview-grid">
        <section className="panel trust-panel">
          <span className="pill">The control path</span>
          <h2>
            One decision.
            <br />
            One exact policy version.
          </h2>
          <p>
            A worker requests a published policy. A human approves the request.
            The admitted run keeps that version and its evidence.
          </p>
          <div className="flow">
            <span>Requested</span>
            <ChevronRight size={14} />
            <span>Approved</span>
            <ChevronRight size={14} />
            <span>Admitted</span>
          </div>
          <button onClick={() => navigate("requests")}>
            Review requests <ArrowUpRight size={16} />
          </button>
        </section>
        <section className="panel">
          <div className="panel-title">
            <h2>Two kinds of evidence</h2>
            <History size={19} />
          </div>
          <div className="explain-row">
            <span className="step-number">01</span>
            <div>
              <h3>Policy and decision history</h3>
              <p>
                Human and machine edits retain the actor, reason, exact version,
                and transaction result.
              </p>
              <button className="text-button" onClick={() => navigate("audit")}>
                Open audit explorer <ArrowUpRight size={14} />
              </button>
            </div>
          </div>
          <div className="explain-row">
            <span className="step-number">02</span>
            <div>
              <h3>Kernel execution evidence</h3>
              <p>
                Signed records describe selected kernel decisions. Loss and
                missing seals remain visible.
              </p>
              <button className="text-button" onClick={() => navigate("runs")}>
                Inspect runs <ArrowUpRight size={14} />
              </button>
            </div>
          </div>
        </section>
      </div>
      <PolicyWorkflow />
      <PolicyProfile />
      {data?.fixture_label && (
        <div className="fixture-banner">
          {data.fixture_label}. These records come from disposable developer
          acceptance.
        </div>
      )}
    </>
  );
}

export function Policies({
  actor,
  epoch,
  navigate,
  refresh,
}: {
  actor: Actor;
  epoch: number;
  navigate: (path: string) => void;
  refresh: () => void;
}) {
  const pg = usePaging();
  const { data, error, loading } = useData<Page<Policy>>(
    `policies?cursor=${pg.cursor}`,
    epoch,
  );
  const [create, setCreate] = useState(false);
  const [search, setSearch] = useState("");
  const items =
    data?.items.filter((p) =>
      (p.name + " " + p.description)
        .toLowerCase()
        .includes(search.toLowerCase()),
    ) || [];
  return (
    <>
      <SectionTitle
        eyebrow="POLICY LIBRARY"
        title="Policies"
        text="Create a draft, review its rights, and publish an immutable version."
        action={
          can(actor, "editor") && (
            <button onClick={() => isCustomerPolicy() ? navigate("policy-builder") : setCreate(true)}>
              <Plus size={17} />
              New policy
            </button>
          )
        }
      />
      <PolicyWorkflow />
      <PolicyProfile />
      <div className="table-toolbar">
        <label className="search">
          <Search size={17} />
          <input
            placeholder="Search this page"
            aria-label="Search policies"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </label>
        <span>{data?.items.length || 0} policy families</span>
      </div>
      {error ? (
        <ErrorBox error={error} />
      ) : loading ? (
        <Loading />
      ) : !items.length ? (
        <Empty
          title="Your policy library starts here"
          text="Create the first policy draft. Its history will retain every later version."
          action={
            can(actor, "editor") && (
              <button onClick={() => isCustomerPolicy() ? navigate("policy-builder") : setCreate(true)}>Create a policy</button>
            )
          }
        />
      ) : (
        <div className="policy-grid">
          {items.map((p) => (
            <button
              className="policy-card"
              key={p.id}
              onClick={() => navigate(`policies/${p.id}`)}
            >
              <div>
                <span className="policy-icon">
                  <ShieldCheck size={22} />
                </span>
                <ArrowUpRight size={17} />
              </div>
              <h3>{p.name}</h3>
              <p>
                {p.description || "A versioned workspace and endpoint policy."}
              </p>
              <footer>
                <span>Created {when(p.created_at)}</span>
                <ChevronRight size={16} />
              </footer>
            </button>
          ))}
        </div>
      )}
      <Pager
        next={data?.next_cursor}
        onNext={pg.next}
        onBack={pg.previous}
        back={pg.back}
      />
      {create && (
        <PolicyForm
          onClose={() => setCreate(false)}
          onDone={(id) => {
            setCreate(false);
            refresh();
            navigate(`policies/${id}`);
          }}
        />
      )}
    </>
  );
}
export function PolicyForm({
  parent,
  policyID,
  onClose,
  onDone,
}: {
  parent?: Version;
  policyID?: string;
  onClose: () => void;
  onDone: (id: string) => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [rights, setRights] = useState<Rights>(
    parent?.rights || {
      workspace_write: !isCustomerPolicy(),
      tcp_address: "127.0.0.1",
      tcp_port: isCustomerPolicy() ? 443 : 18081,
    },
  );
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [schemaReady, setSchemaReady] = useState(!isCustomerPolicy());
  const [error, setError] = useState<unknown>();
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!schemaReady) { setError(new Error("Apply the validated policy source before saving this draft.")); return; }
    setBusy(true);
    setError(undefined);
    try {
      const result = await api<any>(
        parent ? `policies/${policyID}/versions` : "policies",
        "POST",
        parent
          ? { parent_id: parent.id, rights, reason }
          : { name, description, rights, reason },
      );
      onDone(policyID || result.policy.id);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      title={parent ? "Propose a new version" : "Create a policy draft"}
      onClose={onClose}
    >
      <form onSubmit={submit}>
        {!parent && (
          <>
            <label>
              Policy name
              <input
                autoFocus
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                minLength={2}
                maxLength={100}
                placeholder="Workspace development"
              />
            </label>
            <label>
              Description
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                maxLength={1000}
                placeholder="Explain when this policy is appropriate."
              />
            </label>
          </>
        )}
        {isCustomerPolicy() ? <CustomerPolicyEditor rights={rights} onChange={setRights} onReady={setSchemaReady} /> : <fieldset>
          <legend>Current limited rights</legend>
          <label className="check-row">
            <input
              type="checkbox"
              checked={rights.workspace_write}
              onChange={(e) =>
                setRights({ ...rights, workspace_write: e.target.checked })
              }
            />
            <span>
              Allow workspace write opens for existing files
              <small>
                The run binds the workspace at runtime. This setting covers selected existing-file write opens.
              </small>
            </span>
          </label>
          <label>
            Allowed IPv4 TCP target
            <select
              aria-label="Allowed endpoint"
              value={rights.tcp_port}
              onChange={(e) =>
                setRights({ ...rights, tcp_port: Number(e.target.value) })
              }
            >
              <option value={18081}>
                Controlled endpoint A · IPv4 TCP 18081
              </option>
              <option value={18082}>
                Controlled endpoint B · IPv4 TCP 18082
              </option>
            </select>
          </label>
          <p className="form-note">Fixture mode: one controlled IPv4 TCP target on port 18081 or 18082.</p>
        </fieldset>}
        <Diff before={parent?.rights} after={rights} />
        <p className="form-note">
          {isCustomerPolicy() ? "This compatibility draft is inspection-only. Workload admission is blocked until the full deny-all profile qualifies. Every read and runtime dependency requires explicit permission." : "The fixture covers selected existing-file write opens and new IPv4 TCP connections. Other controls remain unqualified."}
        </p>
        <label>
          Reason
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            required
            minLength={3}
            maxLength={512}
            placeholder="Why does this policy or edit meet the worker's needs?"
          />
        </label>
        {Boolean(error) && <ErrorBox error={error} />}
        <div className="modal-actions">
          <button type="button" className="secondary" onClick={onClose}>
            Cancel
          </button>
          <button disabled={busy || !schemaReady || reason.trim().length < 3}>
            {busy ? "Saving…" : parent ? "Create new draft" : "Create draft"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function PolicyDetail({
  id,
  actor,
  epoch,
  navigate,
  refresh,
}: {
  id: string;
  actor: Actor;
  epoch: number;
  navigate: (path: string) => void;
  refresh: () => void;
}) {
  const family = useData<Policy>(`policies/${id}`, epoch);
  const pg = usePaging(id);
  const history = useData<Page<Version>>(
    `policies/${id}/versions?cursor=${pg.cursor}`,
    epoch,
  );
  const [selected, setSelected] = useState<string>();
  const [edit, setEdit] = useState(false);
  const [decision, setDecision] = useState<string>();
  const versions = history.data?.items || [];
  const v = versions.find((v) => v.id === selected) || versions[0];
  const documentState = usePolicyDocument(isCustomerPolicy() ? v?.id : undefined);
  const fullDocument = documentState.document;
  if (family.loading || history.loading) return <Loading />;
  if (family.error || history.error)
    return <ErrorBox error={family.error || history.error} />;
  return (
    <>
      <button className="back-link" onClick={() => navigate("policies")}>
        <ArrowLeft size={15} />
        Policy library
      </button>
      <SectionTitle
        eyebrow="VERSIONED POLICY"
        title={family.data?.name || "Policy"}
        text={family.data?.description || "An immutable policy history."}
        action={
          v &&
          can(actor, "editor") && (
            <button disabled={documentState.loading || Boolean(documentState.error)} onClick={() => fullDocument ? navigate(`policy-builder/${v.id}`) : setEdit(true)}>
              <Plus size={17} />
              New version
            </button>
          )
        }
      />
      <PolicyWorkflow />
      <PolicyProfile />
      {!v ? (
        <Empty
          title="No versions"
          text="This policy has no retained versions."
        />
      ) : (
        <div className="detail-grid">
          <section className="panel">
            <div className="panel-title">
              <h2>Version {v.number}</h2>
              <Badge value={v.state} />
            </div>
            {documentState.loading ? <Loading /> : documentState.error ? <ErrorBox error={documentState.error} /> : fullDocument ? <><RequestedPolicy document={fullDocument.document} /><TargetPreview key={v.id} versionID={v.id} /><details><summary>Stored full policy document</summary><pre>{JSON.stringify(fullDocument.document, null, 2)}</pre></details></> : <RightsView rights={v.rights} />}
            <div className="metadata">
              <div>
                <span>Proposed by</span>
                <strong>{v.actor}</strong>
              </div>
              <div>
                <span>Created</span>
                <strong>{when(v.created_at)}</strong>
              </div>
              <div>
                <span>Reason</span>
                <strong>{v.reason}</strong>
              </div>
              <div>
                <span>Version digest</span>
                <button
                  className="copy-value"
                  title={v.digest}
                  onClick={() => navigator.clipboard.writeText(v.digest)}
                >
                  {v.digest.slice(0, 16)}…<Copy size={13} />
                </button>
              </div>
            </div>
            {v.parent_id && !fullDocument && !documentState.loading && (
              <>
                <h3 className="subheading">Rights change</h3>
                <VersionDiff
                  parentID={v.parent_id}
                  after={v.rights}
                  epoch={epoch}
                />
              </>
            )}
            <div className="version-actions">
              <button className="secondary" onClick={() => navigate(`requests/${v.id}`)}>
                Requests for this version
              </button>
              <button className="secondary" onClick={() => navigate(`audit/${v.id}`)}>
                Audit history for this version
              </button>
              {v.state === "draft" && can(actor, "editor") && (
                <button disabled={documentState.loading || Boolean(documentState.error)} onClick={() => setDecision("proposed")}>
                  Submit for approval
                </button>
              )}
              {v.state === "proposed" && can(actor, "approver") && (
                <button disabled={isCustomerPolicy() || documentState.loading || Boolean(documentState.error)} onClick={() => setDecision("approved")}>
                  Approve this version
                </button>
              )}
              {v.state === "approved" && can(actor, "approver") && (
                <button disabled={isCustomerPolicy() || documentState.loading || Boolean(documentState.error)} onClick={() => setDecision("published")}>
                  Publish this version
                </button>
              )}
              {v.state === "published" && can(actor, "approver") && (
                <button
                  className="secondary danger"
                  onClick={() => setDecision("retired")}
                >
                  Retire this version
                </button>
              )}
            </div>
            <p className="form-note">
              {isCustomerPolicy() ? "Approval and publication remain unavailable until the deny-all engine qualifies. A draft retains all explicit fields." : "A new draft preserves all previous versions and run bindings."}
            </p>
          </section>
          <section className="panel">
            <div className="panel-title">
              <h2>Version history</h2>
              <History size={19} />
            </div>
            <div className="version-list">
              {versions.map((x) => (
                <button
                  key={x.id}
                  className={v.id === x.id ? "selected" : ""}
                  onClick={() => setSelected(x.id)}
                >
                  <span className="version-number">{x.number}</span>
                  <div>
                    <strong>Version {x.number}</strong>
                    <small>{when(x.created_at)}</small>
                  </div>
                  <Badge value={x.state} />
                </button>
              ))}
            </div>
            <Pager
              next={history.data?.next_cursor}
              onNext={(c) => {
                setSelected(undefined);
                pg.next(c);
              }}
              onBack={() => {
                setSelected(undefined);
                pg.previous();
              }}
              back={pg.back}
            />
          </section>
        </div>
      )}
      {edit && v && (
        <PolicyForm
          parent={v}
          policyID={id}
          onClose={() => setEdit(false)}
          onDone={() => {
            setEdit(false);
            setSelected(undefined);
            pg.reset();
            refresh();
          }}
        />
      )}
      {decision && v && (
        <DecisionForm
          title={`${decision[0].toUpperCase() + decision.slice(1)} version ${v.number}`}
          document={fullDocument?.document}
          rights={v.rights}
          onClose={() => setDecision(undefined)}
          onCommit={async (reason) => {
            await api(
              `versions/${v.id}/transition`,
              "POST",
              { state: decision, reason },
              v.revision,
              `${v.id}:${decision}:${v.revision}`,
            );
            setDecision(undefined);
            refresh();
          }}
        />
      )}
    </>
  );
}
function VersionDiff({
  parentID,
  after,
  epoch,
}: {
  parentID: string;
  after: Rights;
  epoch: number;
}) {
  const parent = useData<Version>(`versions/${parentID}`, epoch);
  if (parent.loading) return <Loading />;
  if (parent.error) return <ErrorBox error={parent.error} />;
  return <Diff before={parent.data?.rights} after={after} />;
}
export function DecisionForm({
  title,
  rights,
  document,
  onClose,
  onCommit,
}: {
  title: string;
  rights?: Rights;
  document?: PolicyDocument;
  onClose: () => void;
  onCommit: (reason: string) => Promise<void>;
}) {
  const [reason, setReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  return (
    <Modal title={title} onClose={onClose}>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(undefined);
          try {
            await onCommit(reason);
          } catch (e) {
            setError(e);
          } finally {
            setBusy(false);
          }
        }}
      >
        {document ? <RequestedPolicy document={document} /> : rights && <RightsView rights={rights} />}
        <p className="form-note">
          This decision enters the permanent change log with your identity and
          reason.
        </p>
        <label>
          Decision reason
          <textarea
            autoFocus
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            required
            minLength={3}
            maxLength={512}
            placeholder="Explain the decision for the next reviewer."
          />
        </label>
        <label className="check-row">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
          />
          <span>I reviewed the exact version and rights.</span>
        </label>
        {Boolean(error) && <ErrorBox error={error} />}
        <div className="modal-actions">
          <button type="button" className="secondary" onClick={onClose}>
            Cancel
          </button>
          <button disabled={busy || !confirmed || reason.trim().length < 3}>
            {busy ? "Committing…" : "Confirm decision"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function Requests({
  actor,
  epoch,
  refresh,
  versionID,
}: {
  actor: Actor;
  epoch: number;
  refresh: () => void;
  versionID?: string;
}) {
  const [filter, setFilter] = useState(versionID ? "" : "pending");
  const pg = usePaging(`${versionID || ""}:${filter}`);
  const params = new URLSearchParams({ cursor: pg.cursor, state: filter });
  if (versionID) params.set("version", versionID);
  const { data, error, loading } = useData<Page<Request>>(
    `requests?${params}`,
    epoch,
  );
  const [selected, setSelected] = useState<Request>();
  const [decision, setDecision] = useState<string>();
  return (
    <>
      <SectionTitle
        eyebrow="HUMAN DECISIONS"
        title="Requests"
        text={versionID ? `Requests for policy version ${short(versionID)}. Compare each request with that exact version.` : "Compare the requested rights and approve one exact published version."}
      />
      <div className="table-toolbar">
        <div className="segmented" aria-label="Request state">
          {["pending", "approved", "rejected", ""].map((x) => (
            <button
              key={x}
              className={filter === x ? "active" : ""}
              onClick={() => setFilter(x)}
            >
              {x || "All requests"}
            </button>
          ))}
        </div>
        <span>{data?.items.length || 0} on this page</span>
      </div>
      {error ? (
        <ErrorBox error={error} />
      ) : loading ? (
        <Loading />
      ) : !data?.items.length ? (
        <Empty
          title={
            filter === "pending"
              ? "The decision queue is clear"
              : "No matching requests"
          }
          text="Enrolled agents submit requests through the scoped API. New requests appear here."
        />
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Agent</th>
                <th>Requested version</th>
                <th>State</th>
                <th>Reason</th>
                <th>
                  <span className="sr-only">Review</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((q) => (
                <tr key={q.id}>
                  <td>
                    <strong>{q.agent_id}</strong>
                    <small>{when(q.created_at)}</small>
                  </td>
                  <td>
                    <code>{short(q.requested_version)}</code>
                  </td>
                  <td>
                    <Badge value={q.state} />
                  </td>
                  <td className="reason-cell">{q.reason}</td>
                  <td>
                    <button
                      className="secondary"
                      onClick={() => setSelected(q)}
                    >
                      Review <ChevronRight size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Pager
        next={data?.next_cursor}
        onNext={pg.next}
        onBack={pg.previous}
        back={pg.back}
      />
      {selected && !decision && (
        <RequestReview
          request={selected}
          epoch={epoch}
          actor={actor}
          onClose={() => setSelected(undefined)}
          onDecision={(state) => setDecision(state)}
        />
      )}{" "}
      {selected && decision && (
        <RequestDecision
          request={selected}
          state={decision}
          epoch={epoch}
          onClose={() => setDecision(undefined)}
          onDone={() => {
            setDecision(undefined);
            setSelected(undefined);
            refresh();
          }}
        />
      )}
    </>
  );
}
function RequestReview({
  request: q,
  epoch,
  actor,
  onClose,
  onDecision,
}: {
  request: Request;
  epoch: number;
  actor: Actor;
  onClose: () => void;
  onDecision: (s: string) => void;
}) {
  const { data, error, loading } = useData<Version>(
    `versions/${q.requested_version}`,
    epoch,
  );
  return (
    <Modal title="Review the policy request" onClose={onClose}>
      <div className="request-summary">
        <Badge value={q.state} />
        <h3>{q.agent_id}</h3>
        <p>{q.reason}</p>
      </div>
      {error ? (
        <ErrorBox error={error} />
      ) : loading ? (
        <Loading />
      ) : (
        data && (
          <>
            <h3 className="subheading">Requested · version {data.number}</h3>
            <RightsView rights={data.rights} />
            <p className="form-note">
              Version digest {data.digest.slice(0, 16)}…
            </p>
          </>
        )
      )}
      {q.approved_version && (
        <div className="decision-record">
          <strong>Approved version {short(q.approved_version)}</strong>
          <p>{q.decision_reason}</p>
          <small>Decision by {q.decided_by}</small>
        </div>
      )}
      <div className="modal-actions">
        <button className="secondary" onClick={onClose}>
          Close
        </button>
        {q.state === "pending" && can(actor, "approver") && (
          <>
            <button
              className="secondary danger"
              onClick={() => onDecision("rejected")}
            >
              <X size={15} />
              Reject
            </button>
            <button onClick={() => onDecision("approved")}>
              <Check size={15} />
              Approve exact version
            </button>
          </>
        )}
      </div>
    </Modal>
  );
}
function RequestDecision({
  request: q,
  state,
  epoch,
  onClose,
  onDone,
}: {
  request: Request;
  state: string;
  epoch: number;
  onClose: () => void;
  onDone: () => void;
}) {
  const { data } = useData<Version>(`versions/${q.requested_version}`, epoch);
  return (
    <DecisionForm
      title={`${state === "approved" ? "Approve" : "Reject"} request`}
      rights={data?.rights}
      onClose={onClose}
      onCommit={async (reason) => {
        await api(
          `requests/${q.id}/decision`,
          "POST",
          { state, version_id: q.requested_version, reason },
          q.revision,
          `${q.id}:${state}:${q.revision}`,
        );
        onDone();
      }}
    />
  );
}

export function Runs({
  epoch,
  navigate,
}: {
  epoch: number;
  navigate: (path: string) => void;
}) {
  const pg = usePaging();
  const { data, error, loading } = useData<Page<Run>>(
    `runs?cursor=${pg.cursor}`,
    epoch,
  );
  return (
    <>
      <SectionTitle
        eyebrow="EXECUTION EVIDENCE"
        title="Runs"
        text="Follow the identity, admitted policy version, and retained verification result."
      />
      {error ? (
        <ErrorBox error={error} />
      ) : loading ? (
        <Loading />
      ) : !data?.items.length ? (
        <Empty
          title="No execution evidence yet"
          text="An admitted worker run appears after its enrolled node submits signed evidence."
        />
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Run</th>
                <th>Agent</th>
                <th>Used policy</th>
                <th>Evidence</th>
                <th>Recorded</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((r) => (
                <tr key={r.id}>
                  <td>
                    <button
                      className="row-link"
                      onClick={() => navigate(`runs/${r.id}`)}
                    >
                      {r.id}
                      <ArrowUpRight size={14} />
                    </button>
                  </td>
                  <td>{r.agent_id}</td>
                  <td>
                    <code>{short(r.version_id)}</code>
                    <small>{r.policy_digest.slice(0, 12)}…</small>
                  </td>
                  <td>
                    <Badge value={r.verifier} />
                  </td>
                  <td>{when(r.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Pager
        next={data?.next_cursor}
        onNext={pg.next}
        onBack={pg.previous}
        back={pg.back}
      />
    </>
  );
}
type RunDetailData = {
  run: Run;
  request: Request;
  requested_policy: Version;
  approved_policy: Version;
  admitted_policy: Version;
  events: {
    decision: {
      seq: string;
      hook: number;
      allowed: boolean;
      pid: number;
      path: string;
      port: number;
      mono_ns: string;
    };
  }[];
  event_limit: number;
  seal: {
    present: boolean;
    node_signature: boolean;
    authority_receipt: boolean;
    retained: string;
    decisions: string;
    reported_loss: string;
  };
};
export function RunDetail({
  id,
  epoch,
  navigate,
}: {
  id: string;
  epoch: number;
  navigate: (path: string) => void;
}) {
  const { data, error, loading } = useData<RunDetailData>(`runs/${id}`, epoch);
  const [verification, setVerification] = useState<string>();
  const [verifyError, setVerifyError] = useState<unknown>();
  if (loading) return <Loading />;
  if (error) return <ErrorBox error={error} />;
  if (!data) return null;
  const d = data;
  return (
    <>
      <button className="back-link" onClick={() => navigate("runs")}>
        <ArrowLeft size={15} />
        All runs
      </button>
      <SectionTitle
        eyebrow="RETAINED RUN RECORD"
        title={d.run.id}
        text={`Worker identity · ${d.run.agent_id}`}
        action={<Badge value={d.run.verifier} />}
      />
      <div className="binding-grid">
        {[
          { title: "Requested", v: d.requested_policy, sub: d.request.reason },
          {
            title: "Approved",
            v: d.approved_policy,
            sub: d.request.decision_reason,
          },
          {
            title: "Actually admitted",
            v: d.admitted_policy,
            sub: "Permanent version and digest binding",
          },
        ].map(({ title, v, sub }) => (
          <section className="panel binding" key={title}>
            <span className="eyebrow">{title}</span>
            <h3>Version {v.number}</h3>
            <RightsView rights={v.rights} />
            <code title={v.digest}>{v.digest.slice(0, 16)}…</code>
            <p>{sub}</p>
          </section>
        ))}
      </div>
      <section className="panel evidence-summary">
        <div className="panel-title">
          <h2>Evidence summary</h2>
          <Badge value={d.run.verifier} />
        </div>
        <div className="metadata">
          {[
            {
              label: "Retained decisions",
              value: d.seal?.retained || "Not reported",
            },
            {
              label: "Reported loss",
              value: d.seal?.reported_loss || "Not reported",
            },
            {
              label: "Terminal seal",
              value: d.seal?.present ? "Present" : "Missing",
            },
            {
              label: "Node signature",
              value: d.seal?.node_signature ? "Present" : "Missing",
            },
            {
              label: "Authority receipt",
              value: d.seal?.authority_receipt ? "Present" : "Missing",
            },
          ].map((x) => (
            <div key={x.label}>
              <span>{x.label}</span>
              <strong>{x.value}</strong>
            </div>
          ))}
        </div>
        <p className="form-note">
          The verifier checks these retained claims. Signature presence alone
          does not establish integrity or successful effects.
        </p>
      </section>
      <section className="panel run-evidence">
        <div className="panel-title">
          <div>
            <h2>Kernel decision timeline</h2>
            <p>
              These records describe attempts and decisions. A permit does not
              establish that an operation completed.
            </p>
          </div>
          <button
            className="secondary"
            onClick={async () => {
              setVerifyError(undefined);
              try {
                const result = await api<{ verifier: string }>(
                  `runs/${id}/verification`,
                );
                setVerification(result.verifier);
              } catch (e) {
                setVerifyError(e);
              }
            }}
          >
            <ShieldCheck size={16} />
            Verify retained evidence
          </button>
        </div>
        {verification && (
          <div className="verification-result">
            <Badge value={verification} />
            <span>
              Verification uses the pinned authority and enrolled node keys.
            </span>
          </div>
        )}
        {Boolean(verifyError) && <ErrorBox error={verifyError} />}{" "}
        {d.run.verifier !== "VALID_COMPLETE" && (
          <div className="evidence-warning">
            This record needs review. Its retained evidence does not establish a
            complete run.
          </div>
        )}
        <div className="timeline">
          {d.events.map(({ decision: e }) => (
            <div className="timeline-row" key={e.seq}>
              <span
                className={`timeline-icon ${e.allowed ? "allowed" : "denied"}`}
              >
                {e.allowed ? <Check size={15} /> : <X size={15} />}
              </span>
              <div>
                <strong>
                  {e.hook === 1
                    ? "Write-open attempt"
                    : "IPv4 TCP connect attempt"}
                </strong>
                <p>
                  {e.hook === 1
                    ? e.path.split("/").slice(-2).join("/")
                    : `Controlled endpoint · port ${((e.port & 255) << 8) | (e.port >> 8)}`}
                </p>
                <small>
                  Sequence {e.seq} · process {e.pid}
                </small>
              </div>
              <Badge value={e.allowed ? "allowed" : "denied"} />
            </div>
          ))}
        </div>
        {d.events.length === d.event_limit && (
          <p className="form-note">
            This view shows the first {d.event_limit} retained decisions. The
            signed record contains the complete retained stream.
          </p>
        )}
      </section>
    </>
  );
}

export function AuditExplorer({
  epoch,
  actor,
  versionID,
}: {
  epoch: number;
  actor: Actor;
  versionID?: string;
}) {
  const [draft, setDraft] = useState({
    actor: "",
    resource: "",
    run: "",
    action: "",
    after: "",
    before: "",
    version: versionID || "",
  });
  const [filter, setFilter] = useState(draft);
  const pg = usePaging(JSON.stringify(filter));
  const params = new URLSearchParams(
    Object.entries(filter).filter(([, v]) => v),
  );
  params.set("cursor", pg.cursor);
  const { data, error, loading } = useData<Page<Audit>>(
    `audit?${params}`,
    epoch,
  );
  const [detail, setDetail] = useState<Audit>();
  return (
    <>
      <SectionTitle
        eyebrow="APPEND-ONLY CHANGE LOG"
        title="Audit explorer"
        text={versionID ? `Audit records bound to policy version ${short(versionID)}.` : "Search authenticated policy, request, admission, and evidence changes."}
        action={
          can(actor, "auditor") && (
            <a
              className="button secondary"
              href={`/api/v1/audit/export?${params}`}
            >
              <Download size={16} />
              Export this page
            </a>
          )
        }
      />
      <form
        className="audit-filters"
        onSubmit={(e) => {
          e.preventDefault();
          pg.reset();
          setFilter(draft);
        }}
      >
        {(["actor", "resource", "run", "action"] as const).map((k) => (
          <label key={k}>
            {k}
            <input
              value={draft[k]}
              onChange={(e) => setDraft({ ...draft, [k]: e.target.value })}
              placeholder={`Filter by ${k}`}
            />
          </label>
        ))}
        <label>
          After
          <input
            type="datetime-local"
            onChange={(e) =>
              setDraft({
                ...draft,
                after: e.target.value
                  ? new Date(e.target.value).toISOString()
                  : "",
              })
            }
          />
        </label>
        <label>
          Before
          <input
            type="datetime-local"
            onChange={(e) =>
              setDraft({
                ...draft,
                before: e.target.value
                  ? new Date(e.target.value).toISOString()
                  : "",
              })
            }
          />
        </label>
        <button className="secondary">
          <Search size={15} />
          Apply filters
        </button>
      </form>
      {error ? (
        <ErrorBox error={error} />
      ) : loading ? (
        <Loading />
      ) : !data?.items.length ? (
        <Empty
          title="No changes match these filters"
          text="Use a different actor, resource, action, or time range."
        />
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Result</th>
                <th>
                  <span className="sr-only">Details</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((a) => (
                <tr key={a.id}>
                  <td>
                    {when(a.time)}
                    <small>Entry {a.id}</small>
                  </td>
                  <td>
                    <strong>{a.actor}</strong>
                    <small>{a.actor_kind}</small>
                  </td>
                  <td>{a.action.replaceAll(".", " · ")}</td>
                  <td>
                    <code>{short(a.resource)}</code>
                  </td>
                  <td>
                    <Badge value={a.result} />
                  </td>
                  <td>
                    <button
                      className="icon-button"
                      onClick={() => setDetail(a)}
                      aria-label={`Inspect audit entry ${a.id}`}
                    >
                      <ChevronRight size={18} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Pager
        next={data?.next_cursor}
        onNext={pg.next}
        onBack={pg.previous}
        back={pg.back}
      />
      {detail && (
        <Modal
          title={`Audit entry ${detail.id}`}
          onClose={() => setDetail(undefined)}
        >
          <div className="metadata">
            <div>
              <span>Actor</span>
              <strong>
                {detail.actor} · {detail.actor_kind}
              </strong>
            </div>
            <div>
              <span>Action</span>
              <strong>{detail.action}</strong>
            </div>
            <div>
              <span>Reason</span>
              <strong>{detail.reason}</strong>
            </div>
            <div>
              <span>Result</span>
              <Badge value={detail.result} />
            </div>
            <div>
              <span>Correlation</span>
              <code>{detail.correlation_id || "—"}</code>
            </div>
          </div>
          <h3 className="subheading">Structured change</h3>
          <div className="json-diff">
            <div>
              <span>Before</span>
              <pre>{JSON.stringify(detail.before, null, 2)}</pre>
            </div>
            <div>
              <span>After</span>
              <pre>{JSON.stringify(detail.after, null, 2)}</pre>
            </div>
          </div>
          <p className="form-note">
            This entry records a control-plane transaction. Kernel evidence
            belongs to its run record.
          </p>
        </Modal>
      )}
    </>
  );
}
