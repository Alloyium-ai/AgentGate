// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

import React, { useState } from 'react';
export function LocalLogin() {
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError('');
    const fields = new FormData(event.currentTarget);
    try {
      const challengeResponse = await fetch('/auth/local/challenge');
      const challenge = await challengeResponse.json();
      if (!challengeResponse.ok) throw new Error(challenge.error?.message || 'The login challenge failed.');
      const response = await fetch('/auth/local/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': challenge.csrf_token },
        body: JSON.stringify({ username: fields.get('username'), password: fields.get('password') }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error?.message || 'Sign-in failed.');
      location.replace('/');
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Sign-in failed.'); }
    finally { setBusy(false); }
  }
  return <form onSubmit={submit}>
    <label>Username<input name="username" autoComplete="username" required minLength={3} maxLength={64} /></label>
    <label>Password<input name="password" type="password" autoComplete="current-password" required maxLength={256} /></label>
    {error && <div className="error-box" role="alert">{error}</div>}
    <button disabled={busy}>{busy ? 'Signing in…' : 'Sign in with a local account'}</button>
  </form>;
}
