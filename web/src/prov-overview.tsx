// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// The sandbox part of the Overview: target health, launches by state,
// launches waiting for this person's decision, and launches about to expire.

import React from "react";
import { ArrowUpRight, Clock, Rocket, Server, UserCheck } from "lucide-react";
import { Actor } from "./api";
import { ErrorBox } from "./components";
import { Items, LAUNCH_STATES, LaunchSummary, Target, permissions, targetName, useResource } from "./prov-api";
import { KernelNotice, StateBadge } from "./prov-components";
import { lifetimeText } from "./launch-spec";

export const EXPIRING_WINDOW_MS = 30 * 60 * 1000;

export function ProvisioningOverview({ actor, epoch, navigate }: { actor: Actor; epoch: number; navigate: (p: string) => void }) {
  const p = permissions(actor);
  const targets = useResource<Items<Target>>("targets", epoch);
  const launches = useResource<LaunchSummary>("launches/summary", epoch);
  const t = (targets.data?.items || []).filter((x) => x.state !== "retired");
  const sum = launches.data;
  const now = Date.now();
  const online = t.filter((x) => x.state === "active" && x.online).length;
  const offline = t.filter((x) => x.state === "active" && !x.online).length;
  const awaiting = t.filter((x) => x.state === "awaiting_key_approval").length;
  const rekey = t.filter((x) => x.state === "rekey_required").length;
  const byState = LAUNCH_STATES.map((s) => ({ state: s, count: sum?.counts[s] || 0 })).filter((x) => x.count > 0);
  const mine = p.approve ? sum?.awaiting_your_decision.items || [] : [];
  const expiring = sum?.expiring_soon.items || [];
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
          <strong>{sum ? sum.counts.running || 0 : "—"}</strong>
          <span>Launches running</span>
        </button>
        <button className="stat" onClick={() => navigate("launches")}>
          <div>
            <UserCheck size={20} aria-hidden="true" />
            <ArrowUpRight size={17} aria-hidden="true" />
          </div>
          <strong>{sum ? (p.approve ? sum.awaiting_your_decision.count : "—") : "—"}</strong>
          <span>{p.approve ? "Waiting for your approval" : "Approvals need the approver role"}</span>
        </button>
        <button className="stat" onClick={() => navigate("launches")}>
          <div>
            <Clock size={20} aria-hidden="true" />
            <ArrowUpRight size={17} aria-hidden="true" />
          </div>
          <strong>{sum ? sum.expiring_soon.count : "—"}</strong>
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
          <p className="form-note">{sum ? `Counts cover all ${sum.total} launches (${sum.active} not ended).` : "Counts come from the service."}</p>
        </section>
        <section className="panel">
          <div className="panel-title">
            <h2>Needs attention</h2>
          </div>
          {!mine.length && !expiring.length && <p className="form-note">Nothing waits for you.</p>}
          {sum && (sum.awaiting_your_decision.count > mine.length || sum.expiring_soon.count > expiring.length) && (
            <p className="form-note">Showing the first {Math.max(mine.length, expiring.length)}; the Launches page filters the rest.</p>
          )}
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
