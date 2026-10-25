// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Secrets: metadata only. A new value is sealed in this browser to the
// target host's verified seal key (web/src/secretseal.ts) and only the sealed
// envelope is sent. The value lives in one uncontrolled password field, never
// in React state, the URL, storage, the console or error text, and the field
// is cleared before the request is sent. The broker policy (upstreams,
// header, scheme, rules, extra and forwarded headers) is shown before the
// value is sealed and its digest is sealed with it: the host stores and uses
// the value only under that policy, and an answer whose settings make another
// digest is reported as a substitution.

import React, { useEffect, useRef, useState } from "react";
import { KeyRound, Lock, Plus, Trash2 } from "lucide-react";
import { Actor, ApiError, api, when } from "./api";
import { Empty, ErrorBox, Loading, Modal, SectionTitle } from "./components";
import { Items, Profile, Secret, Target, permissions, roleText, targetName, useResource } from "./prov-api";
import { ConfirmDialog, Digest, Gate, LiveRegion, StateBadge } from "./prov-components";
import { ClientPager, useClientPages } from "./prov-paging";
import { BASIC_USER, HeaderRow, RuleRow, SECRET_HEADER, headerIssues, ruleIssues, sealFailureText } from "./secret-rules";
import {
  BROKER_METHODS,
  SealError,
  SealReceipt,
  Sealed,
  SecretPolicy,
  SignedKeyRecord,
  VerifiedKey,
  b64urlStrict,
  brokerValueOK,
  encodeEnvelope,
  envelopeDigest,
  hostKeyFingerprint,
  hostKeyID,
  newSecretPolicy,
  policyDigest,
  readPin,
  seal,
  sealSupport,
  settingsDigest,
  utf8,
  verifyKeyRecord,
  verifyReceipt,
  wipe,
  writePin,
} from "./secretseal";

const NAME = /^[a-z0-9][a-z0-9-]{0,39}$/;
const UPSTREAM = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+(:[0-9]{1,5})?$/;
const HEADER = SECRET_HEADER;
const SUBJECT = /^[A-Za-z0-9_.:-]{1,100}$/;
// GET /targets/{id}/seal-key as requested in docs/BROKER.md (integration
// request 2). host_key_fingerprint is the service's claim and is ignored: the
// browser computes the fingerprint from host_public_key itself.
type SealKey = { record: SignedKeyRecord; host_public_key: string; host_key_fingerprint?: string };
type StoredSecret = Secret & { receipt?: SealReceipt | string };

// The receipt may be relayed as an object or as the raw JSON the host sent.
function parseReceipt(r: SealReceipt | string | undefined): SealReceipt | undefined {
  if (!r) return undefined;
  if (typeof r !== "string") return r;
  try {
    return JSON.parse(r) as SealReceipt;
  } catch {
    return undefined;
  }
}
type Verified = { target: Target; key: VerifiedKey; fingerprint: string; hostKeyID: string; pinned: boolean };

const words = (s: string) => s.split(/[\s,]+/).filter(Boolean);

// PolicyReview shows every field of the injection policy the digest covers.
function PolicyReview({ policy, digest }: { policy: SecretPolicy; digest: string }) {
  return (
    <div className="metadata" data-policy-review="true">
      <div>
        <span>Upstreams</span>
        <code>{policy.upstreams.map((u) => `https://${u.host}:${u.port}`).join(", ")}</code>
      </div>
      <div>
        <span>Header</span>
        <code>
          {policy.header}
          {policy.scheme ? ` (${policy.scheme}${policy.username ? `, user ${policy.username}` : ""})` : ""}
        </code>
      </div>
      <div>
        <span>Requests forwarded with the credential</span>
        <span>
          {policy.wildcard
            ? "WILDCARD: every method on every path"
            : policy.rules.length
              ? policy.rules.map((r) => `${r.methods.join(",")} ${r.path} (${r.match})`).join("; ")
              : "none: every launch is refused (deny by default)"}
        </span>
      </div>
      <div>
        <span>Extra headers set</span>
        <span>{policy.extra_headers.length ? policy.extra_headers.map((h) => `${h.name}: ${h.value}`).join("; ") : "none"}</span>
      </div>
      <div>
        <span>Request headers forwarded beyond the defaults</span>
        <span>{policy.forward_headers.length ? policy.forward_headers.join(", ") : "none"}</span>
      </div>
      <div>
        <span>Policy digest (sealed with the value)</span>
        <code>{digest}</code>
      </div>
    </div>
  );
}

// PolicyCheck recomputes a stored secret's policy from the settings the
// service shows and compares it with the digest sealed with the value.
function PolicyCheck({ secret }: { secret: Secret }) {
  const [ok, setOk] = useState<boolean>();
  useEffect(() => {
    let live = true;
    settingsDigest(secret).then((d) => live && setOk(Boolean(d) && d === secret.policy_digest));
    return () => {
      live = false;
    };
  }, [secret.id, secret.revision, secret.policy_digest]);
  if (ok === undefined) return null;
  return ok ? (
    <small>
      policy <Digest value={secret.policy_digest} />
    </small>
  ) : (
    <small className="field-issue">The settings shown differ from the policy sealed with the value: no launch can use it. Delete it.</small>
  );
}

function SealFailure({ error }: { error: unknown }) {
  // POST /secrets refusals; a missing seal key on GET (404) is explained by
  // verify() itself.
  if (error instanceof ApiError && error.status !== 404 && sealFailureText(error.code, error.message))
    return (
      <div className="error-box" role="alert">
        <div>
          <strong>
            The service refused the secret (<code>{error.code}</code>)
          </strong>
          <p>{sealFailureText(error.code, error.message)}</p>
        </div>
      </div>
    );
  if (error instanceof SealError)
    return (
      <div className="error-box" role="alert">
        <div>
          <strong>Nothing was sealed or sent</strong>
          <p>{error.message}</p>
          {error.code === "fingerprint" || error.code === "signature" ? <p>This can mean the service or the network substituted a key. Do not retry until an administrator has compared the host key on the host console.</p> : null}
        </div>
      </div>
    );
  return <ErrorBox error={error} />;
}

function NewSecret({ actor, onClose, onDone }: { actor: Actor; onClose: () => void; onDone: () => void }) {
  const targets = useResource<Items<Target>>("targets");
  const profiles = useResource<Items<Profile>>("profiles");
  const [support, setSupport] = useState<{ ok: boolean; missing: string[] }>();
  const [targetID, setTargetID] = useState("");
  const [name, setName] = useState("");
  const [upstreams, setUpstreams] = useState("");
  const [header, setHeader] = useState("x-api-key");
  const [scheme, setScheme] = useState<"" | "Bearer" | "Basic">("");
  const [username, setUsername] = useState("");
  const [rules, setRules] = useState<RuleRow[]>([{ methods: "POST", path: "/v1/messages", match: "exact" }]);
  const [wildcard, setWildcard] = useState(false);
  const [wildcardConfirmed, setWildcardConfirmed] = useState(false);
  const [extra, setExtra] = useState<HeaderRow[]>([]);
  const [forward, setForward] = useState("");
  const [policy, setPolicy] = useState<{ policy: SecretPolicy; digest: string }>();
  const [policyResult, setPolicyResult] = useState<{ ok: boolean; text: string }>();
  const [allowedProfiles, setAllowedProfiles] = useState<string[]>([]);
  const [launchers, setLaunchers] = useState(actor.subject);
  const [reason, setReason] = useState("");
  const [verified, setVerified] = useState<Verified>();
  const [typed, setTyped] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState<"" | "verify" | "seal">("");
  const [error, setError] = useState<unknown>();
  const [stored, setStored] = useState<StoredSecret>();
  const [sentDigest, setSentDigest] = useState("");
  const [receipt, setReceipt] = useState<{ ok: boolean; text: string }>();
  const [announce, setAnnounce] = useState("");
  const valueRef = useRef<HTMLInputElement>(null);
  const sealedRef = useRef<Sealed | null>(null);
  useEffect(() => {
    sealSupport().then(setSupport);
    return () => {
      if (valueRef.current) valueRef.current.value = "";
      wipe(sealedRef.current);
      sealedRef.current = null;
    };
  }, []);
  useEffect(() => {
    if (!stored || stored.state === "stored" || stored.state === "failed") return;
    const controller = new AbortController();
    let tries = 0;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      tries++;
      try {
        const list = await api<Items<StoredSecret>>("secrets", "GET", undefined, undefined, undefined, controller.signal);
        const now = list.items.find((x) => x.id === stored.id);
        if (now && now.state !== stored.state) {
          // The host's receipt for this envelope: GET /secrets/{id}/receipt.
          if (now.state === "stored") {
            const r = await api<{ receipt: SealReceipt | string }>(`secrets/${encodeURIComponent(stored.id)}/receipt`, "GET", undefined, undefined, undefined, controller.signal).catch(() => undefined);
            setStored({ ...now, receipt: r?.receipt ?? now.receipt });
          } else setStored(now);
          return;
        }
      } catch {
        if (controller.signal.aborted) return;
      }
      if (tries < 40) timer = setTimeout(tick, 3000);
    };
    timer = setTimeout(tick, 3000);
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [stored?.id, stored?.state]);
  useEffect(() => {
    if (!stored?.receipt || !sealedRef.current) return;
    const relayed = parseReceipt(stored.receipt);
    if (!relayed) {
      setReceipt({ ok: false, text: "The service relayed a receipt this page cannot read. Treat the stored secret as unverified." });
      return;
    }
    verifyReceipt(sealedRef.current, relayed)
      .then((fp) =>
        setReceipt({ ok: true, text: `The host proved it opened exactly this envelope and stored it under the sealed policy ${relayed.policy_digest}. Value fingerprint ${fp}.` }),
      )
      .catch(() =>
        setReceipt({
          ok: false,
          text: "The receipt does not authenticate: the host did not open the envelope this browser sealed, or stored it under another policy. Treat the stored secret as untrusted and delete it.",
        }),
      )
      .finally(() => {
        wipe(sealedRef.current);
        sealedRef.current = null;
      });
  }, [stored?.receipt]);
  const ups = words(upstreams);
  const subjects = words(launchers);
  const forwards = words(forward);
  const ruleBody = wildcard
    ? [{ methods: ["*"], path: "/" }]
    : rules.map((r) => ({ methods: r.methods.split(/[\s,]+/).filter(Boolean).map((m) => m.toUpperCase()), path: r.path, match: r.match }));
  const policyKey = JSON.stringify([ups, header, scheme, username, ruleBody, extra, forwards, wildcard]);
  // The policy this form makes, as the host will enforce it.
  useEffect(() => {
    let live = true;
    let made: SecretPolicy | undefined;
    try {
      made = newSecretPolicy({
        upstreams: ups,
        header,
        scheme,
        username: scheme === "Basic" ? username : "",
        rules: wildcard ? [{ methods: BROKER_METHODS, path: "/", match: "prefix" }] : (ruleBody as { methods: string[]; path: string; match: string }[]),
        extra_headers: extra.length ? Object.fromEntries(extra.map((h) => [h.name, h.value])) : undefined,
        forward_headers: forwards,
        wildcard,
      });
    } catch {
      made = undefined;
    }
    if (!made) {
      setPolicy(undefined);
      return;
    }
    const p = made;
    policyDigest(p).then((digest) => live && setPolicy({ policy: p, digest }));
    return () => {
      live = false;
    };
  }, [policyKey]);
  const metaIssues = [
    !targetID && "Choose a target.",
    !NAME.test(name) && "A secret name is 1 to 40 lowercase letters, digits and -.",
    (ups.length < 1 || ups.length > 8 || ups.some((u) => !UPSTREAM.test(u) || u.length > 253) || new Set(ups).size !== ups.length) && "List 1 to 8 unique lowercase host names (optionally with :port).",
    !HEADER.test(header) && "The header is an HTTP header name such as x-api-key or Authorization.",
    scheme && header.toLowerCase() !== "authorization" && `The ${scheme} scheme needs the Authorization header.`,
    scheme === "Basic" && !BASIC_USER.test(username) && "The Basic scheme needs a user name of 1 to 64 visible ASCII characters without a colon.",
    ...ruleIssues(rules, wildcard, wildcardConfirmed),
    ...headerIssues(extra, header),
    (forwards.length > 16 || forwards.some((f) => !HEADER.test(f)) || new Set(forwards.map((f) => f.toLowerCase())).size !== forwards.length) &&
      "List at most 16 unique header names to forward.",
    (allowedProfiles.length < 1 || allowedProfiles.length > 32) && "Choose at least one profile that may use the secret.",
    (subjects.length < 1 || subjects.length > 64 || subjects.some((s) => !SUBJECT.test(s)) || new Set(subjects).size !== subjects.length) && "List 1 to 64 unique people (subjects such as local:alice) who may launch with it.",
    reason.trim().length < 3 && "Give a reason.",
  ].filter(Boolean) as string[];
  const clearValue = () => {
    if (valueRef.current) valueRef.current.value = "";
  };
  const close = () => {
    clearValue();
    wipe(sealedRef.current);
    sealedRef.current = null;
    if (stored) onDone();
    onClose();
  };
  const changeTarget = (id: string) => {
    clearValue();
    setVerified(undefined);
    setTyped("");
    setConfirmed(false);
    setTargetID(id);
  };
  async function verify() {
    setBusy("verify");
    setError(undefined);
    setVerified(undefined);
    try {
      const target = await api<Target>(`targets/${encodeURIComponent(targetID)}`);
      if (target.state !== "active") throw new ApiError(409, "target_unavailable", "The target is not enrolled and active.", "");
      let sk: SealKey;
      try {
        sk = await api<SealKey>(`targets/${encodeURIComponent(target.id)}/seal-key`);
      } catch (cause) {
        if (cause instanceof ApiError && cause.status === 404)
          throw new ApiError(
            404,
            "seal_key_unavailable",
            cause.code === "seal_key_unavailable"
              ? `${cause.message} This browser cannot verify the host key without it. Nothing was sealed or sent.`
              : "This service does not publish a signed seal key for the target yet (GET /targets/{id}/seal-key), so this browser cannot verify the host key. Nothing was sealed or sent.",
            cause.requestID,
          );
        throw cause;
      }
      let pub: Uint8Array;
      try {
        pub = b64urlStrict(sk.host_public_key);
      } catch {
        throw new SealError("key_record", "The service sent a malformed host key.");
      }
      if (pub.length !== 32) throw new SealError("key_record", "The service sent a malformed host key.");
      const id = await hostKeyID(pub);
      if (id !== target.host_key_id) throw new SealError("fingerprint", "The host key the service sent is not the key an administrator approved for this target.");
      const fingerprint = await hostKeyFingerprint(pub);
      // The pin is the host_key_id this browser approved or confirmed, like
      // the CLI's known-targets.json.
      const pin = readPin(target.id);
      if (pin && pin !== id) throw new SealError("fingerprint", "The host key differs from the one this browser pinned for this target. Re-enrollment needs the old pin removed deliberately.");
      const key = await verifyKeyRecord(sk.record, pub, fingerprint, target.id, Date.now());
      setVerified({ target, key, fingerprint, hostKeyID: id, pinned: Boolean(pin) });
      setAnnounce(pin ? "Seal key verified against the pinned host key." : "Seal key signature verified. Compare the host key fingerprint before sealing.");
    } catch (cause) {
      setError(cause);
    } finally {
      setBusy("");
    }
  }
  // At first use the operator types the fingerprint from the host console, in
  // either form: host_key_id (ed25519:…) or the SHA256:… fingerprint.
  const typedMatches = Boolean(verified) && (typed.trim() === verified!.hostKeyID || typed.trim() === verified!.fingerprint);
  const trusted = verified && (verified.pinned || (typedMatches && confirmed));
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!verified || !trusted || metaIssues.length || !valueRef.current || !policy) return;
    const sealedPolicy = policy;
    setBusy("seal");
    setError(undefined);
    const raw = valueRef.current.value;
    clearValue();
    const value = utf8(raw);
    try {
      if (!brokerValueOK(value)) throw new SealError("value", "The broker can inject only 8 to 8192 visible ASCII characters (no spaces or line breaks). Nothing was sealed or sent.");
      if (!verified.pinned) writePin(verified.target.id, verified.hostKeyID);
      const sealed = await seal(verified.key, verified.target.id, name, sealedPolicy.digest, value, Date.now());
      value.fill(0);
      wipe(sealedRef.current);
      sealedRef.current = sealed;
      const ciphertext = encodeEnvelope(sealed.envelope);
      const sent = await envelopeDigest(ciphertext);
      const body: Record<string, unknown> = {
        name,
        target: verified.target.id,
        upstreams: ups,
        header,
        rules: ruleBody,
        ciphertext,
        allowed_profiles: allowedProfiles,
        allowed_launchers: subjects,
        reason: reason.trim(),
      };
      if (scheme) body.scheme = scheme;
      if (scheme === "Basic") body.username = username;
      if (extra.length) body.extra_headers = Object.fromEntries(extra.map((h) => [h.name, h.value]));
      if (forwards.length) body.forward_headers = forwards;
      let out: StoredSecret;
      try {
        out = await api<StoredSecret>("secrets", "POST", body);
      } catch (cause) {
        // A changed seal key means this browser must verify the new one.
        if (cause instanceof ApiError && cause.code === "seal_key_changed") setVerified(undefined);
        throw cause;
      }
      // The service must record exactly the sealed policy: the digest it
      // reports and the one its settings make.
      const shown = await settingsDigest(out);
      setPolicyResult(
        out.policy_digest === sealedPolicy.digest && shown === sealedPolicy.digest
          ? { ok: true, text: `The service recorded exactly the sealed policy ${sealedPolicy.digest}.` }
          : {
              ok: false,
              text: `The service recorded other broker settings (policy ${out.policy_digest || "none"}) than the policy this browser sealed (${sealedPolicy.digest}). Treat the service as compromised and delete the secret; the host refuses every launch under another policy.`,
            },
      );
      setStored(out);
      setSentDigest(sent);
      setAnnounce(`Secret ${out.name} sent for ${verified.target.name}.`);
    } catch (cause) {
      setError(cause);
    } finally {
      value.fill(0);
      setBusy("");
    }
  }
  if (stored)
    return (
      <Modal title="Secret stored" onClose={close}>
        <LiveRegion message={announce} />
        <p>
          The browser sealed the value to {verified?.target.name}'s verified key and sent only the envelope. The service relays it to the host in a secret-put job
          and keeps a fingerprint of the ciphertext.
        </p>
        <div className="metadata">
          <div>
            <span>Name</span>
            <strong>{stored.name}</strong>
          </div>
          <div>
            <span>State</span>
            <StateBadge state={stored.state} />
          </div>
          <div>
            <span>Ciphertext fingerprint</span>
            <span>
              <Digest value={stored.ciphertext_sha256} />{" "}
              <strong className={stored.ciphertext_sha256 === sentDigest ? "match ok" : "match bad"}>
                {stored.ciphertext_sha256 === sentDigest ? "matches the envelope this browser sent" : "differs from the envelope this browser sent"}
              </strong>
            </span>
          </div>
        </div>
        {policyResult && (
          <p role={policyResult.ok ? "status" : "alert"} className={policyResult.ok ? "match ok" : "match bad"}>
            {policyResult.text}
          </p>
        )}
        {receipt ? (
          <p role="status" className={receipt.ok ? "match ok" : "match bad"}>
            {receipt.text}
          </p>
        ) : (
          <p className="form-note">
            The state moves to stored when the host reports it accepted the value. Keep this dialog open to check the host's sealed receipt when the service relays
            it; until then the "stored" state rests on the host's word alone.
          </p>
        )}
        <div className="modal-actions">
          <button onClick={close}>Done</button>
        </div>
      </Modal>
    );
  return (
    <Modal title="Store a secret" onClose={close}>
      <LiveRegion message={announce} />
      {support && !support.ok && (
        <div className="error-box" role="alert">
          <div>
            <strong>This browser cannot seal secrets</strong>
            <p>
              It lacks {support.missing.join(", ")} in WebCrypto, which the host key check and the sealing need. Nothing falls back to sending the value. Use a current
              Chrome, Edge, Firefox or Safari, or the CLI, which reads the value from standard input: <code>agentgate secret set NAME --target TARGET --upstream HOST --allow-profile PROFILE</code>.
            </p>
          </div>
        </div>
      )}
      <form onSubmit={submit} autoComplete="off">
        <label>
          Target
          <select value={targetID} onChange={(e) => changeTarget(e.target.value)}>
            <option value="">Choose an active target</option>
            {targets.data?.items
              .filter((t) => t.state === "active")
              .map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
          </select>
        </label>
        <label>
          Secret name
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="model-api" maxLength={40} />
        </label>
        <label>
          Upstreams (exact host names the broker may send it to)
          <textarea rows={2} value={upstreams} onChange={(e) => setUpstreams(e.target.value)} placeholder="api.model.example" spellCheck={false} />
        </label>
        <label>
          Header the broker sets
          <input value={header} onChange={(e) => setHeader(e.target.value)} spellCheck={false} />
        </label>
        <label>
          Scheme
          <select value={scheme} onChange={(e) => setScheme(e.target.value as "" | "Bearer" | "Basic")}>
            <option value="">The value as it is{header.toLowerCase() === "authorization" ? " (Bearer, the broker's default for Authorization)" : ""}</option>
            <option value="Bearer">Bearer (Authorization: Bearer VALUE)</option>
            <option value="Basic">Basic (Authorization: Basic user:VALUE)</option>
          </select>
        </label>
        {scheme === "Basic" && (
          <label>
            Basic user name
            <input value={username} onChange={(e) => setUsername(e.target.value)} spellCheck={false} autoComplete="off" maxLength={64} />
          </label>
        )}
        <fieldset>
          <legend>Requests the broker may forward with the credential</legend>
          <p className="form-note">Deny by default: the broker forwards only requests that match a rule. A secret without rules cannot be used by any launch.</p>
          {!wildcard &&
            rules.map((r, i) => (
              <div className="row-edit" key={i}>
                <label>
                  Methods
                  <input value={r.methods} onChange={(e) => setRules(rules.map((x, n) => (n === i ? { ...x, methods: e.target.value } : x)))} placeholder="POST" spellCheck={false} />
                </label>
                <label>
                  Path
                  <input value={r.path} onChange={(e) => setRules(rules.map((x, n) => (n === i ? { ...x, path: e.target.value } : x)))} placeholder="/v1/messages" spellCheck={false} />
                </label>
                <label>
                  Match
                  <select value={r.match} onChange={(e) => setRules(rules.map((x, n) => (n === i ? { ...x, match: e.target.value as "exact" | "prefix" } : x)))}>
                    <option value="exact">exact path</option>
                    <option value="prefix">path prefix</option>
                  </select>
                </label>
                <button type="button" className="icon-button" aria-label={`Remove rule ${i + 1}`} onClick={() => setRules(rules.filter((_, n) => n !== i))}>
                  <Trash2 size={15} />
                </button>
              </div>
            ))}
          {!wildcard && (
            <button type="button" className="secondary" disabled={rules.length >= 64} onClick={() => setRules([...rules, { methods: "GET", path: "/", match: "prefix" }])}>
              <Plus size={15} aria-hidden="true" /> Add a rule
            </button>
          )}
          <label className="check-row warn-row">
            <input
              type="checkbox"
              checked={wildcard}
              onChange={(e) => {
                setWildcard(e.target.checked);
                setWildcardConfirmed(false);
              }}
            />
            <span>
              Allow every method on every path (wildcard)
              <small>Not recommended. Every plan that uses this secret warns and needs a second person's approval.</small>
            </span>
          </label>
          {wildcard && (
            <div className="evidence-warning" role="alert">
              <strong>Warning:</strong> with the wildcard the broker forwards every method on every path of {ups.length ? ups.join(", ") : "the upstreams"} with the
              credential, so an agent can use it as fully as the upstream permits.
              <label className="check-row">
                <input type="checkbox" checked={wildcardConfirmed} onChange={(e) => setWildcardConfirmed(e.target.checked)} />
                <span>I understand, and I want the wildcard for this secret.</span>
              </label>
            </div>
          )}
        </fieldset>
        <fieldset>
          <legend>Extra headers (not secret)</legend>
          <p className="form-note">Headers the broker sets on every forwarded request, for example an API version. Never put a credential here.</p>
          {extra.map((h, i) => (
            <div className="row-edit" key={i}>
              <label>
                Header name
                <input value={h.name} onChange={(e) => setExtra(extra.map((x, n) => (n === i ? { ...x, name: e.target.value } : x)))} placeholder="anthropic-version" spellCheck={false} />
              </label>
              <label>
                Header value
                <input value={h.value} onChange={(e) => setExtra(extra.map((x, n) => (n === i ? { ...x, value: e.target.value } : x)))} placeholder="2023-06-01" spellCheck={false} />
              </label>
              <button type="button" className="icon-button" aria-label={`Remove extra header ${i + 1}`} onClick={() => setExtra(extra.filter((_, n) => n !== i))}>
                <Trash2 size={15} />
              </button>
            </div>
          ))}
          <button type="button" className="secondary" disabled={extra.length >= 8} onClick={() => setExtra([...extra, { name: "", value: "" }])}>
            <Plus size={15} aria-hidden="true" /> Add an extra header
          </button>
        </fieldset>
        <label>
          Request headers to forward beyond the broker's defaults (optional)
          <input value={forward} onChange={(e) => setForward(e.target.value)} placeholder="x-request-id" spellCheck={false} />
          <small className="help">
            The broker forwards Accept, Content-Type, User-Agent, Idempotency-Key and the model SDKs' headers. It never forwards credentials, cookies or proxy and
            override headers, whatever is listed here.
          </small>
        </label>
        <fieldset>
          <legend>Profiles whose launches may use it</legend>
          {profiles.data?.items.map((x) => (
            <label className="check-row" key={x.id}>
              <input type="checkbox" checked={allowedProfiles.includes(x.name)} onChange={(e) => setAllowedProfiles(e.target.checked ? [...allowedProfiles, x.name] : allowedProfiles.filter((n) => n !== x.name))} />
              <span>{x.name}</span>
            </label>
          ))}
          {!profiles.data?.items.length && <p className="form-note">Create an access profile first.</p>}
        </fieldset>
        <label>
          People who may launch with it (subjects)
          <textarea rows={2} value={launchers} onChange={(e) => setLaunchers(e.target.value)} spellCheck={false} />
        </label>
        <label>
          Reason
          <textarea value={reason} onChange={(e) => setReason(e.target.value)} minLength={3} maxLength={512} />
        </label>
        {metaIssues.length > 0 && (
          <ul className="field-issues">
            {metaIssues.map((m) => (
              <li key={m}>{m}</li>
            ))}
          </ul>
        )}
        <h3 className="subheading">1. Verify the host's seal key</h3>
        <p className="form-note">
          The browser checks that the host's Ed25519 key is the one an administrator approved (host_key_id), that it matches this browser's pin, and that it
          signed the X25519 seal key. A key the service made up fails these checks.
        </p>
        <button type="button" className="secondary" disabled={!targetID || busy !== "" || !support?.ok} onClick={verify}>
          <KeyRound size={15} aria-hidden="true" /> {busy === "verify" ? "Verifying…" : "Verify seal key"}
        </button>
        {verified && (
          <div className="fingerprint-compare">
            <span>Verified signature from host key</span>
            <code className="fingerprint">{verified.hostKeyID}</code>
            <small>{verified.fingerprint}</small>
            {verified.pinned ? (
              <p className="match ok">Matches the fingerprint this browser pinned for {verified.target.name}.</p>
            ) : (
              <>
                <p className="form-note">First use in this browser: type the host key fingerprint from the host console, as ed25519:… or SHA256:…. The browser pins it for later.</p>
                <label>
                  Fingerprint on the host
                  <input value={typed} onChange={(e) => setTyped(e.target.value)} placeholder="ed25519:…" spellCheck={false} autoComplete="off" />
                </label>
                <p role="status" className={typed ? (typedMatches ? "match ok" : "match bad") : "match"}>
                  {!typed ? "Waiting for the fingerprint." : typedMatches ? "Match." : "No match. Do not seal a secret to this key."}
                </p>
                <label className="check-row">
                  <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
                  <span>I read this fingerprint on the host itself.</span>
                </label>
              </>
            )}
          </div>
        )}
        <h3 className="subheading">2. Review the broker policy sealed with the value</h3>
        <p className="form-note">
          The host stores the value with exactly this policy and refuses every launch under any other, so neither the service nor anyone with its database can send
          the credential elsewhere or use it differently.
        </p>
        {policy ? <PolicyReview policy={policy.policy} digest={policy.digest} /> : <p className="form-note">Complete the broker settings above to see the policy.</p>}
        <h3 className="subheading">3. Enter the value</h3>
        <label>
          Secret value
          <input
            ref={valueRef}
            type="password"
            autoComplete="new-password"
            spellCheck={false}
            disabled={!trusted || !support?.ok}
            aria-describedby="value-help"
            data-secret-value="true"
          />
        </label>
        <small id="value-help" className="help">
          <Lock size={12} aria-hidden="true" /> 8 to 8192 visible ASCII characters (what the broker can inject). Sealed in this browser; the field is cleared before
          anything is sent. The service and the agent never see it; only the host and its broker do.
        </small>
        {Boolean(error) && <SealFailure error={error} />}
        <div className="modal-actions">
          <button type="button" className="secondary" onClick={close}>
            Cancel
          </button>
          <button disabled={!trusted || busy !== "" || metaIssues.length > 0 || !support?.ok || !policy}>{busy === "seal" ? "Sealing…" : "Seal in this browser and store"}</button>
        </div>
      </form>
    </Modal>
  );
}

export function Secrets({ actor, epoch }: { actor: Actor; epoch: number }) {
  const p = permissions(actor);
  const list = useResource<Items<Secret>>(p.secretsAdmin ? "secrets" : null, epoch);
  const targets = useResource<Items<Target>>("targets", epoch);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<Secret>();
  const [showDeleted, setShowDeleted] = useState(false);
  const items = (list.data?.items || []).filter((s) => showDeleted || s.state !== "deleted");
  const pages = useClientPages(items, 25);
  return (
    <>
      <SectionTitle
        eyebrow="CREDENTIALS"
        title="Secrets"
        text="Credentials held outside every sandbox. This page shows metadata only; a launch reaches a secret through the host's broker, by name."
        action={
          <Gate allowed={p.secretsAdmin} reason={`Only an administrator stores secrets. Your roles: ${roleText(actor)}.`} onClick={() => setAdding(true)}>
            <Plus size={17} aria-hidden="true" /> Store a secret
          </Gate>
        }
      />
      {!p.secretsAdmin ? (
        <Empty title="Secrets are managed by administrators" text="Launchers reference a secret by name in a launch; the plan checks that it is scoped to them and their profile." />
      ) : (
        <>
          <div className="table-toolbar">
            <label className="check-row inline">
              <input type="checkbox" checked={showDeleted} onChange={(e) => setShowDeleted(e.target.checked)} />
              <span>Show deleted</span>
            </label>
            <span>{items.length} secrets</span>
          </div>
          {list.error ? (
            <ErrorBox error={list.error} />
          ) : list.loading ? (
            <Loading />
          ) : !items.length ? (
            <Empty title="No secrets" text="Store one to let launches use an upstream API without the agent ever holding the credential." />
          ) : (
            <div className="table-wrap">
              <table>
                <caption className="sr-only">Secrets (metadata only)</caption>
                <thead>
                  <tr>
                    <th scope="col">Secret</th>
                    <th scope="col">Target</th>
                    <th scope="col">Upstreams and header</th>
                    <th scope="col">Scope</th>
                    <th scope="col">Ciphertext fingerprint</th>
                    <th scope="col">State</th>
                    <th scope="col">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {pages.items.map((s) => (
                    <tr key={s.id}>
                      <td>
                        <strong>{s.name}</strong>
                        <small>
                          {when(s.created_at)} by {s.created_by}
                        </small>
                      </td>
                      <td>{targetName(targets.data?.items, s.target_id)}</td>
                      <td>
                        {s.upstreams.join(", ")}
                        <small>
                          header <code>{s.header}</code>
                          {s.scheme ? ` · ${s.scheme}` : ""}
                          {s.username ? ` · user ${s.username}` : ""}
                        </small>
                        {s.wildcard_rules ? (
                          <small className="field-issue">Wildcard rules: every method on every path.</small>
                        ) : s.rules?.length ? (
                          <small>Rules: {s.rules.map((r) => `${r.methods.join(",")} ${r.path}${r.match ? ` (${r.match})` : ""}`).join("; ")}</small>
                        ) : (
                          <small className="field-issue">No broker rules: no launch can use it (secret_rules_missing).</small>
                        )}
                      </td>
                      <td>
                        Profiles: {s.allowed_profiles.join(", ")}
                        <small>Launchers: {s.allowed_launchers.join(", ")}</small>
                      </td>
                      <td>
                        <Digest value={s.ciphertext_sha256} />
                        {s.value_fingerprint && <small>value {s.value_fingerprint}</small>}
                        <PolicyCheck secret={s} />
                      </td>
                      <td>
                        <StateBadge state={s.state} />
                        {s.removal === "unconfirmed" && <small className="field-issue">Removal unconfirmed: the value may remain on the retired host.</small>}
                      </td>
                      <td>
                        {s.state !== "deleted" && s.state !== "deleting" && (
                          <button className="secondary danger" onClick={() => setRemoving(s)}>
                            Delete
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <ClientPager {...pages} bound={500} />
        </>
      )}
      {adding && <NewSecret actor={actor} onClose={() => setAdding(false)} onDone={list.reload} />}
      {removing && (
        <ConfirmDialog
          title={`Delete ${removing.name}`}
          confirmLabel="Delete secret"
          danger
          typeToConfirm={removing.name}
          onClose={() => setRemoving(undefined)}
          onConfirm={async (reason) => {
            await api(`secrets/${removing.id}`, "DELETE", { reason });
            setRemoving(undefined);
            list.reload();
          }}
        >
          <p>This queues a secret-delete job that removes the value from the host. The service refuses while a launch that has not ended uses the secret.</p>
        </ConfirmDialog>
      )}
    </>
  );
}
