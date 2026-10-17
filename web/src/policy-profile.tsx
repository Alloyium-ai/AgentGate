// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

import React from "react";
import { isCustomerPolicy } from "./api";

export function PolicyWorkflow() {
  const steps = [
    ["Draft", "An editor records each explicit permission and the reason."],
    ["Submit", "The editor sends this exact version for review."],
    ["Approve", "An approver accepts the policy version."],
    ["Publish", "The approver makes this version available for requests."],
    ["Grant", "A separate agent request needs approval before a signed grant can issue."],
    ["Admitted run", "The node verifies the grant and installs its rights before the workload starts."],
  ];
  return (
    <section className="panel policy-workflow" aria-label="Policy workflow">
      <h2>From a draft to an admitted run</h2>
      <ol>{steps.map(([name, text]) => <li key={name}><strong>{name}</strong>{isCustomerPolicy() && <small>{["Draft", "Submit"].includes(name) ? " · inspection available" : " · blocked pending qualification"}</small>}<p>{text}</p></li>)}</ol>
      <p className="form-note">Publication permits requests. Each run still needs a signed grant bound to its agent, node, and workload.</p>
      {isCustomerPolicy() && <p className="form-note">Community workload admission is unavailable until the deny-all engine and explicit runtime permissions qualify. Compatibility drafts are inspection-only.</p>}
    </section>
  );
}

export function PolicyProfile() {
  return (
    <section className="panel policy-profile" aria-label="Policy capabilities">
      <div className="panel-title"><h2>Current policy capabilities</h2><span className="pill">{isCustomerPolicy() ? "Inspection-only" : "Limited fixture"}</span></div>
      <p>{isCustomerPolicy()
        ? "The full policy builder exposes the versioned deny-all contract. Draft fields do not grant workload rights. Each enforcement capability requires target qualification."
        : "Fixture mode: choose controlled IPv4 TCP endpoint A or B. These endpoints serve disposable acceptance tests."}</p>
      <div className="capability-grid">
        <div><h3>{isCustomerPolicy() ? "Inspection available now" : "Supported fixture scope"}</h3><ul>
          <li>Guided full policy fields, JSON/YAML validation, and immutable draft versions.</li>
          <li>Explicit permission previews and signed target compatibility checks.</li>
          <li>Local audit history and evidence export. Community grants and activation remain blocked.</li>
        </ul></div>
        <div><h3>Planned, not enforced by this profile</h3><ul>
          <li>File reads, create/delete/rename/link/symlink, and full filesystem coverage.</li>
          <li>Executable rules and held executable approvals.</li>
          <li>UDP, IPv6, multiple targets, prefixes, port ranges, and DNS rules.</li>
        </ul></div>
      </div>
      <p className="form-note">No read, loader, library, syscall, or other runtime permission is inherited. Reviewed runtime templates must show every explicit allowance. Full inventory and enforcement qualification remain pending.</p>
    </section>
  );
}
