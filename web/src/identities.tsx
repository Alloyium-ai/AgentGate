// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Linked identities: subjects an administrator recorded as one person (for
// example local:alice and her OIDC identity). Their only effect is that none
// of them may decide a launch another requested. This page lists them; the
// CLI and the API change them (agentgate identity link / unlink).

import React from "react";
import { TerminalSquare } from "lucide-react";
import { Actor, when } from "./api";
import { Empty, ErrorBox, Loading, SectionTitle } from "./components";
import { IdentityLink, Items, permissions, roleText, useResource } from "./prov-api";

export function Identities({ actor, epoch }: { actor: Actor; epoch: number }) {
  const p = permissions(actor);
  const { data, error, loading } = useResource<Items<IdentityLink>>(p.admin ? "identity-links" : null, epoch);
  const items = data?.items || [];
  return (
    <>
      <SectionTitle
        eyebrow="TWO-PERSON CONTROL"
        title="Linked identities"
        text="Accounts of one person. A launch requested by any of them can be approved only by someone outside the group; the link grants no role."
      />
      <section className="panel cli-hint">
        <TerminalSquare size={19} aria-hidden="true" />
        <p>
          Change them with <code>agentgate identity link SUBJECT SUBJECT…</code> and <code>agentgate identity unlink SUBJECT</code> (administrators;
          another administrator unlinks a group that holds your own account). Without a link, every account counts as its own person.
        </p>
      </section>
      {!p.admin ? (
        <ErrorBox error={new Error(`Only an administrator sees linked identities. Your roles: ${roleText(actor)}.`)} />
      ) : error ? (
        <ErrorBox error={error} />
      ) : loading ? (
        <Loading />
      ) : !items.length ? (
        <Empty title="No linked identities" text="Each account is treated as its own person when launches are approved." />
      ) : (
        <div className="table-wrap">
          <table>
            <caption className="sr-only">Linked identities</caption>
            <thead>
              <tr>
                <th scope="col">Person</th>
                <th scope="col">Subjects</th>
                <th scope="col">Last linked</th>
              </tr>
            </thead>
            <tbody>
              {items.map((link) => (
                <tr key={link.person}>
                  <td>
                    <code>{link.person.slice(0, 12)}</code>
                  </td>
                  <td>{link.subjects.join(", ")}</td>
                  <td>
                    {when(link.linked_at)}
                    <small>by {link.linked_by}</small>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
