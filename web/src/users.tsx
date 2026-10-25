// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

import React, { useState } from 'react';
import { api } from './api';
import { useData } from './pages';
import { ErrorBox, Loading } from './components';
type User = { username: string; name: string; roles: string[]; enabled: boolean; revision: number };
const roles = ['admin', 'editor', 'approver', 'auditor', 'viewer'];
export function Users({ epoch, refresh }: { epoch: number; refresh: () => void }) {
  const { data, error } = useData<{items: User[]}>('users', epoch);
  const [selected, setSelected] = useState<User>();
  const [failure, setFailure] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  async function save(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setFailure(undefined);
    const form = event.currentTarget;
    const fields = new FormData(form);
    try {
      await api('users', 'POST', {
        username: selected?.username || fields.get('username'), name: fields.get('name'),
        roles: fields.getAll('roles'), enabled: fields.get('enabled') === 'on',
        parent_revision: selected?.revision || 0, reason: fields.get('reason'),
        ...(fields.get('password') ? { password: fields.get('password') } : {}),
      });
      form.reset(); setSelected(undefined); refresh();
    } catch (cause) { setFailure(cause); } finally { setBusy(false); }
  }
  return <section>
    <h1>Local users</h1>
    <p>Local user records supply the account roles. A second administrator changes your password or status. A new password or disabling an account signs that user out everywhere and revokes every API token they hold; enabling the account again does not restore them.</p>
    {Boolean(error) && <ErrorBox error={error} />}
    {!data && !error && <Loading />}
    {data && <div className="table-wrap"><table><thead><tr><th>User</th><th>Roles</th><th>Status</th><th>Action</th></tr></thead><tbody>
      {data.items.map(user => <tr key={user.username}><td>{user.name}<small>{user.username}</small></td><td>{user.roles.join(' · ')}</td><td>{user.enabled ? 'Enabled' : 'Disabled'}</td><td><button onClick={() => {setSelected(user); setFailure(undefined);}}>Edit</button></td></tr>)}
    </tbody></table></div>}
    <h2>{selected ? 'Edit ' + selected.username : 'Create a local user'}</h2>
    <form key={selected?.username + ':' + selected?.revision} onSubmit={save}>
      {!selected && <label>Username<input name="username" pattern="[a-z][a-z0-9_.-]{2,63}" required maxLength={64} /></label>}
      <label>Display name<input name="name" defaultValue={selected?.name} required maxLength={128} /></label>
      <fieldset><legend>Basic roles</legend>{roles.map(role => <label className="check-row" key={role}><input type="checkbox" name="roles" value={role} defaultChecked={selected?.roles.includes(role) || (!selected && role === 'viewer')} />{role}</label>)}</fieldset>
      <label className="check-row"><input type="checkbox" name="enabled" defaultChecked={selected?.enabled ?? true} />Enabled</label>
      <label>{selected ? 'New password (optional)' : 'Password'}<input type="password" name="password" autoComplete="new-password" required={!selected} minLength={16} maxLength={256} /></label>
      <label>Reason<textarea name="reason" required minLength={3} maxLength={512} /></label>
      {Boolean(failure) && <ErrorBox error={failure} />}
      <button disabled={busy}>{busy ? 'Saving…' : 'Save user'}</button>
      {selected && <button type="button" className="secondary" onClick={() => setSelected(undefined)}>Cancel</button>}
    </form>
  </section>;
}
