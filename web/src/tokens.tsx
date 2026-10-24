// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// API tokens let the agentgate CLI act for you. A token carries a subset of
// your roles, expires, is shown once and can be revoked here.

import React, { useState } from "react";
import { Plus, TerminalSquare } from "lucide-react";
import { Actor, api, when } from "./api";
import { Empty, ErrorBox, Loading, Modal, SectionTitle } from "./components";
import { APIToken, Items, ROLES, permissions, roleText, useResource } from "./prov-api";
import { CodeBlock, ConfirmDialog, Gate, OneTimeSecret } from "./prov-components";
import { ClientPager, useClientPages } from "./prov-paging";

const LIFETIMES = [
  { label: "1 hour", seconds: 3600 },
  { label: "1 day", seconds: 86400 },
  { label: "7 days", seconds: 7 * 86400 },
  { label: "30 days", seconds: 30 * 86400 },
  { label: "90 days (maximum)", seconds: 90 * 86400 },
];
const NAME = /^[A-Za-z0-9 ._-]{1,64}$/;

function CreateToken({ actor, onClose, onDone }: { actor: Actor; onClose: () => void; onDone: () => void }) {
  const admin = actor.roles.includes("admin");
  const held = admin ? ROLES : ROLES.filter((r) => actor.roles.includes(r));
  const [name, setName] = useState("");
  const [roles, setRoles] = useState<string[]>(held.includes("launcher") ? ["launcher"] : held.slice(0, 1));
  const [lifetime, setLifetime] = useState(30 * 86400);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [created, setCreated] = useState<{ id: string; token: string; expires_at: string; roles: string[] }>();
  const close = () => {
    setCreated(undefined);
    if (created) onDone();
    onClose();
  };
  if (created)
    return (
      <Modal title="API token created" onClose={close}>
        <OneTimeSecret label="API token" value={created.token} note="Store it now; the service keeps only its hash. Anyone holding it acts as you with these roles until it expires or you revoke it." />
        <CodeBlock label="Use it with the CLI" text={`agentgate login ${location.origin}\n# paste the token when asked; the CLI stores it with mode 0600`} />
        <p className="form-note">
          Roles: {created.roles.join(", ")} · expires {when(created.expires_at)}. Each use is limited to the roles you still hold.
        </p>
        <div className="modal-actions">
          <button onClick={close}>I stored the token</button>
        </div>
      </Modal>
    );
  return (
    <Modal title="Create an API token for the CLI" onClose={close}>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(undefined);
          try {
            setCreated(await api("api-tokens", "POST", { name, roles, expires_in_seconds: lifetime, reason }));
          } catch (cause) {
            setError(cause);
          } finally {
            setBusy(false);
          }
        }}
      >
        <p className="form-note">Tokens are for the agentgate CLI and scripts. They reach the provisioning, overview and audit endpoints only; they cannot manage users or create tokens.</p>
        <label>
          Token name
          <input autoFocus value={name} onChange={(e) => setName(e.target.value)} maxLength={64} placeholder="laptop" />
        </label>
        <fieldset>
          <legend>Roles (a subset of yours{admin ? "; an administrator may grant any" : ""})</legend>
          {ROLES.map((r) => (
            <label className="check-row" key={r}>
              <input type="checkbox" disabled={!held.includes(r)} checked={roles.includes(r)} onChange={(e) => setRoles(e.target.checked ? [...roles, r] : roles.filter((x) => x !== r))} />
              <span>
                {r}
                {!held.includes(r) && <small>You do not hold this role.</small>}
              </span>
            </label>
          ))}
        </fieldset>
        <label>
          Expires after
          <select value={lifetime} onChange={(e) => setLifetime(Number(e.target.value))}>
            {LIFETIMES.map((l) => (
              <option key={l.seconds} value={l.seconds}>
                {l.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Reason
          <textarea value={reason} onChange={(e) => setReason(e.target.value)} minLength={3} maxLength={512} placeholder="CLI on my laptop" />
        </label>
        {Boolean(error) && <ErrorBox error={error} />}
        <div className="modal-actions">
          <button type="button" className="secondary" onClick={close}>
            Cancel
          </button>
          <button disabled={busy || !NAME.test(name) || !roles.length || reason.trim().length < 3}>{busy ? "Creating…" : "Create token"}</button>
        </div>
      </form>
    </Modal>
  );
}

export function Tokens({ actor, epoch }: { actor: Actor; epoch: number }) {
  const p = permissions(actor);
  const { data, error, loading, reload } = useResource<Items<APIToken>>(p.tokens ? "api-tokens" : null, epoch);
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<APIToken>();
  const items = data?.items || [];
  const pages = useClientPages(items, 25);
  const now = Date.now();
  return (
    <>
      <SectionTitle
        eyebrow="CLI ACCESS"
        title="API tokens"
        text={p.admin ? "Tokens for the agentgate CLI. As an administrator you see and can revoke every token." : "Tokens for the agentgate CLI that act for you."}
        action={
          <Gate allowed={p.tokens} reason={`Tokens need a signed-in person with at least one role. Your roles: ${roleText(actor)}.`} onClick={() => setCreating(true)}>
            <Plus size={17} aria-hidden="true" /> Create token
          </Gate>
        }
      />
      <section className="panel cli-hint">
        <TerminalSquare size={19} aria-hidden="true" />
        <p>
          The CLI and this page use the same API. Anything you do here, <code>agentgate</code> can do with a token, and the reverse. A token's use is audited as you.
        </p>
      </section>
      {error ? (
        <ErrorBox error={error} />
      ) : loading ? (
        <Loading />
      ) : !items.length ? (
        <Empty title="No API tokens" text="Create one to use the agentgate CLI." />
      ) : (
        <div className="table-wrap">
          <table>
            <caption className="sr-only">API tokens</caption>
            <thead>
              <tr>
                <th scope="col">Token</th>
                <th scope="col">Holder</th>
                <th scope="col">Roles</th>
                <th scope="col">Expires</th>
                <th scope="col">Last used</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {pages.items.map((t) => {
                const expired = new Date(t.expires_at).getTime() <= now;
                return (
                  <tr key={t.id}>
                    <td>
                      <strong>{t.name}</strong>
                      <small>created {when(t.created_at)}</small>
                    </td>
                    <td>{t.subject}</td>
                    <td>{t.roles.join(", ")}</td>
                    <td>
                      {when(t.expires_at)}
                      {t.revoked_at ? <small className="badge rejected">revoked {when(t.revoked_at)}</small> : expired ? <small className="badge incomplete">expired</small> : null}
                    </td>
                    <td>{t.last_used_at ? when(t.last_used_at) : "never"}</td>
                    <td>
                      {!t.revoked_at && (
                        <button className="secondary danger" onClick={() => setRevoking(t)}>
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <ClientPager {...pages} bound={200} />
      {creating && <CreateToken actor={actor} onClose={() => setCreating(false)} onDone={reload} />}
      {revoking && (
        <ConfirmDialog
          title={`Revoke ${revoking.name}`}
          confirmLabel="Revoke token"
          danger
          onClose={() => setRevoking(undefined)}
          onConfirm={async (reason) => {
            await api(`api-tokens/${revoking.id}`, "DELETE", { reason });
            setRevoking(undefined);
            reload();
          }}
        >
          <p>The CLI using this token stops working at once. Revoking twice changes nothing.</p>
        </ConfirmDialog>
      )}
    </>
  );
}
