// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// The sandbox part of the Overview: target health, launches by state,
// launches waiting for this person's decision, and launches about to expire.

import React from "react";
import { ArrowUpRight, Clock, Rocket, Server, UserCheck } from "lucide-react";
import { Actor } from "./api";
import { ErrorBox } from "./components";
import { Items, LAUNCH_STATES, Launch, Target, isTerminal, permissions, targetName, useResource } from "./prov-api";
import { KernelNotice, StateBadge } from "./prov-components";
import { lifetimeText } from "./launch-spec";

export const EXPIRING_WINDOW_MS = 30 * 60 * 1000;

export function ProvisioningOverview({ actor, epoch, navigate }: { actor: Actor; epoch: number; navigate: (p: string) => void }) {
  const p = permissions(actor);
  const targets = useResource<Items<Target>>("targets", epoch);
  const launches = useResource<Items<Launch>>("launches?limit=200", epoch);
  const t = (targets.data?.items || []).filter((x) => x.state !== "retired");
  const l = launches.data?.items || [];
  const now = Date.now();
  const online = t.filter((x) => x.state === "active" && x.online).length;
  const offline = t.filter((x) => x.state === "active" && !x.online).length;
  const awaiting = t.filter((x) => x.state === "awaiting_key_approval").length;
  const rekey = t.filter((x) => x.state === "rekey_required").length;
  const byState = LAUNCH_STATES.map((s) => ({ state: s, count: l.filter((x) => x.state === s).length })).filter((x) => x.count > 0);
  const mine = p.approve ? l.filter((x) => x.state === "approval_pending" && x.requested_by !== actor.subject) : [];
  const expiring = l
    .filter((x) => !isTerminal(x.state) && x.expires_at && new Date(x.expires_at).getTime() - now < EXPIRING_WINDOW_MS)
    .sort((a, b) => new Date(a.expires_at!).getTime() - new Date(b.expires_at!).getTime());
  return (
    <section className="prov-overview" aria-label="Agent sandbox">
      {Boolean(targets.error || launches.error) && <ErrorBox error={targets.error || launches.error} />}
      <div className="stats">
        <button className="stat" onClick={() => navigate("targets")}>
          <div>
            <Server size={20} aria-hidden="true" />
            <ArrowUpRight size={17} aria-hidden="true" />
          </div>
          <strong>{targets.data ? `${online}/${online + offline}` : "—"}</strong>
          <span>Targets online{awaiting ? ` · ${awaiting} awaiting key approval` : ""}{rekey ? ` · ${rekey} need re-enrollment` : ""}</span>
        </button>
        <button className="stat" onClick={() => navigate("launches")}>
          <div>
            <Rocket size={20} aria-hidden="true" />
            <ArrowUpRight size={17} aria-hidden="true" />
          </div>
          <strong>{launches.data ? l.filter((x) => x.state === "running").length : "—"}</strong>
          <span>Launches running</span>
        </button>
        <button className="stat" onClick={() => navigate("launches")}>
          <div>
            <UserCheck size={20} aria-hidden="true" />
            <ArrowUpRight size={17} aria-hidden="true" />
          </div>
          <strong>{launches.data ? (p.approve ? mine.length : "—") : "—"}</strong>
          <span>{p.approve ? "Waiting for your approval" : "Approvals need the approver role"}</span>
        </button>
        <button className="stat" onClick={() => navigate("launches")}>
          <div>
            <Clock size={20} aria-hidden="true" />
            <ArrowUpRight size={17} aria-hidden="true" />
          </div>
          <strong>{launches.data ? expiring.length : "—"}</strong>
          <span>Expiring within 30 minutes</span>
        </button>
      </div>
      <div className="overview-grid">
        <section className="panel">
          <div className="panel-title">
            <h2>Launches by state</h2>
          </div>
          {byState.length ? (
            <ul className="state-counts">
              {byState.map((x) => (
                <li key={x.state}>
                  <StateBadge state={x.state} /> <strong>{x.count}</strong>
                </li>
              ))}
            </ul>
          ) : (
            <p className="form-note">No launches yet.</p>
          )}
          <p className="form-note">Counts cover the newest 200 launches.</p>
        </section>
        <section className="panel">
          <div className="panel-title">
            <h2>Needs attention</h2>
          </div>
          {!mine.length && !expiring.length && <p className="form-note">Nothing waits for you.</p>}
          <ul className="plain-list">
            {mine.slice(0, 8).map((x) => (
              <li key={x.id}>
                <button className="row-link" onClick={() => navigate(`launches/${x.id}`)}>
                  Approve or reject {x.name}
                </button>{" "}
                <small>
                  requested by {x.requested_by} on {targetName(targets.data?.items, x.target_id)}
                </small>
              </li>
            ))}
            {expiring.slice(0, 8).map((x) => (
              <li key={x.id}>
                <button className="row-link" onClick={() => navigate(`launches/${x.id}`)}>
                  {x.name}
                </button>{" "}
                <small>
                  <StateBadge state={x.state} /> ends in {lifetimeText(Math.max(0, Math.round((new Date(x.expires_at!).getTime() - now) / 1000)))}
                </small>
              </li>
            ))}
          </ul>
          <KernelNotice compact />
        </section>
      </div>
    </section>
  );
}
