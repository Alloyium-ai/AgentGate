# The web UI: provision, grant access and launch agents

The React app in `web/` is one of the two clients of the control plane; the other is the `agentgate` CLI
([CLI.md](CLI.md)). Both call the same `/api/v1` endpoints with the same roles, so anything one can do the other can
do, and every action lands in the same audit log. The contract they build on is [PROVISIONING.md](PROVISIONING.md).

**Kernel enforcement is not verified.** No target has been verified on a BPF LSM kernel, and protocol v1 carries no
verification report, so the API reports `kernel_verified: false` for every target and launch. Every target, plan,
launch and receipt view says "kernel enforcement not yet verified on this host". The UI shows what the API reports and
what was requested; it never presents a permission as proven behavior.

## Tasks

### Bring a host online (administrator)

1. **Targets → Add target.** Give a name (`^[a-z0-9][a-z0-9-]{0,39}$`), choose the runtime (Docker host or appliance
   VM) and a reason. The dialog shows the one-time enrollment token **once** (15 minutes, single use; the service
   keeps only its hash) and the exact command to run on the host as root:

   ```sh
   umask 077
   printf '%s\n' 'agtenr_…' > agentgate-enroll.token
   sudo agentgate-hostd install \
     --service-url https://control.example \
     --token-file agentgate-enroll.token \
     --runtime docker-host
   rm -f agentgate-enroll.token
   ```

   The token goes in a file because arguments are visible to other users. A loopback `http://` origin adds
   `--allow-loopback-http`; the appliance runtime adds `--appliance-state` and `--source` placeholders to edit.
   Closing the dialog drops the token from the page.
2. The target moves to **Awaiting host key approval** when the host enrolls. Open it and choose **Approve host key**.
   The page shows the fingerprint the service received (`host_key_id`, `ed25519:…`). Read the fingerprint on the host
   console (`agentgate-hostd install` prints `host key id (compare and approve this): ed25519:…` and the SHA-256
   fingerprint; `sudo agentgate-hostd status` shows both again as `host_key_id` and `host_key_fingerprint`) and type
   or paste it; the page says *Match* or *No match. Do not approve* as you type. Approval also needs
   a confirmation that you read it on the host itself, and a reason. The service compares the value again in constant
   time. Approving also pins that fingerprint in this browser for sealing secrets later.
3. **New enrollment token** re-enrolls a host (reinstall, job key rotation); when the host enrolls again, the target's
   secrets are removed from it and must be stored again. **Rename**; **Retire** asks you to type the target name and is
   refused while a launch on the target has not ended. When the host may hold secrets, the target becomes **Retiring**:
   the service queues one removal per secret, the host collects only those, and its last confirmation retires the
   target and revokes its host key. **Retire without the host's confirmation…** (for a host that is gone) finishes it
   at once and marks those secrets *removal unconfirmed* on the Secrets page.
4. **Mount roots…** (administrators) sets the host folders launches on the target may mount. The target page also
   shows the roots the host itself allows (its operator sets them on the host with `agentgate-hostd mount-roots`; the
   service cannot), says which of the service's roots the host refuses, and shows the host's clock against the
   service's at its last heartbeat.

### Define access (editor)

1. **Access profiles → New profile**: start from a preset (the presets' descriptions and their web, writable and
   executable trees are shown) or the shipped example policy. New profiles require a second person's approval for every
   launch; only an administrator can create one that does not.
2. The profile page shows the selected version: its digest, the parent chain (`v3 ← v2 ← v1`), who created it, the
   reason, the edits that produced it, and the diff from its parent. **Compare with** diffs any two versions.
3. **What can this agent do?** explains the version in plain sentences and a table: area, permission, value, what it
   means, and its risk (*High risk*, *Medium risk*, *Low risk*, *Restricts access*). **Show policy JSON** shows the stored
   document read-only.
4. **Change access** is a typed editor, never raw JSON. Sections: Network (public web per protocol, DNS resolvers),
   Files (workspace, write, read, execute, devices from the six the policy allows, deny), Mounts (host folder name and read-only or read-write),
   Processes (signals) and Memory (executable anonymous memory), plus *Replace with a preset*. Each control stages one
   typed grant edit (at most 16) with a plain-language description and risk, for example "Let the agent run programs
   from /opt/tool. It must not overlap a writable folder." Paths are pre-checked like `access.ContainerPath`.
5. **Preview (dry run)** sends the staged edits with `"dry_run": true` and shows the service's answer without storing
   anything: whether a version would be created, the parent and result digests, the service's change list (the same rows
   the version diff uses), and its messages and notices. A refused edit shows the service's code and message.
6. **Apply as version N+1** sends the edits to `POST /profiles/{id}/versions/{n}/grants` on the latest version. The page
   shows the new version's digest, the diff from its parent and the service's messages and notices verbatim; that result
   stays on the page after the editor moves to the new latest version. A refused edit shows the service's code and
   message verbatim, for example `grant_conflict: /var/lib/agentgate/workspace/bin overlaps the writable tree
   /var/lib/agentgate/workspace; writable trees never run code`. Nothing is edited in place: to undo, apply the
   opposite edit as another version.
7. **Launch approval** (administrator) switches whether launches of the profile need a second person, with an
   explanation of what changes. **Advanced: new version from a document** stores a whole document as the next version
   (for a document the CLI produced).

### Store a secret (administrator)

**Secrets → Store a secret**: choose an active target, a name, the exact upstream host names, the header the broker
sets, the profiles and people (subjects) that may use it, and a reason, and say how the broker uses the credential:

- **Scheme**: the value as it is, `Bearer` (`Authorization: Bearer VALUE`, the service's default for an Authorization
  header) or `Basic` with a user name (`Authorization: Basic base64(user:VALUE)`). A scheme needs the Authorization
  header.
- **Requests the broker may forward**: the broker forwards nothing by default, so the form needs at least one rule:
  methods (GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS), a canonical path, and *exact path* or *path prefix*; at most
  64. **Allow every method on every path (wildcard)** replaces the rules with `[{"methods":["*"],"path":"/"}]` only
  after a warning naming the upstreams and an explicit "I understand" confirmation; every plan that uses such a secret
  warns and needs a second person's approval.
- **Extra headers (not secret)**: at most 8 headers the broker sets on every forwarded request, such as an API
  version. The credential header, Authorization, X-Api-Key, Host, Cookie, `Proxy-*` and `X-Forwarded-*` are refused.
- **Request headers to forward beyond the broker's defaults** (optional, at most 16). The broker never forwards
  credential, cookie, proxy or override headers, whatever is listed.

These are checked in the browser as `hostproto.CheckInjection` checks them, and again by the service with the broker's
own validator. Then:

1. **Verify seal key.** The browser fetches the target and `GET /targets/{id}/seal-key` and checks, with WebCrypto:
   the host's Ed25519 key hashes to the `host_key_id` an administrator approved; it matches this browser's pin; it signed
   the seal key record; the record names this target, uses the documented suite, has a matching key id and is in date.
   At first use in this browser you type the fingerprint from the host console (`ed25519:…` or `SHA256:…`) and confirm
   it; the browser pins it (`localStorage`, key `agentgate.known-targets.v1`). A pin is never replaced silently.
2. **Review the broker policy sealed with the value.** The dialog shows the injection policy the settings make, as the
   host will enforce it (every upstream as `https://host:port`, the header and scheme, the rules, the extra and
   forwarded headers) and its policy digest, computed in the browser byte for byte as `hostproto.SecretPolicy`
   (`web/src/secretseal.ts` `newSecretPolicy`, `canonicalPolicy`, `policyDigest`). The host stores and uses the value
   only under this policy; changing it later means storing the secret again.
3. **Enter the value** (enabled only after verification): 8 to 8192 visible ASCII characters, which is what the broker
   can inject (`broker.ValidSecret`).
4. **Seal in this browser and store.** The value is sealed with RFC 9180 HPKE (DHKEM(X25519, HKDF-SHA256),
   HKDF-SHA256, ChaCha20-Poly1305, base mode) exactly as `internal/secretseal.Seal`: the associated data binds the
   format (`agentgate.secretseal.v2`), suite, target id, secret name, version (the sealing time in milliseconds), key
   id, a fresh nonce and the policy digest. The request carries `ciphertext` = `Envelope.Encode()` (base64url of the
   envelope JSON) and never the value. The page checks that the `ciphertext_sha256` the service records equals the
   SHA-256 of what it sent and that the settings it recorded make the sealed policy digest (otherwise it says the
   service recorded other broker settings and to delete the secret), and, when the host has stored it, reads
   `GET /secrets/{id}/receipt` while the dialog is open and verifies the receipt's tag (which covers the policy the host
   stored) with the HPKE exporter secret it kept in memory, then shows the host's value fingerprint (`sfp1_…`).

The service's refusals are explained: `seal_key_changed` (the host published a new seal key after this browser
verified it; the page drops the verification so you verify the new key and seal again), `seal_key_unavailable` (the
host has not published a signed seal key), `invalid_ciphertext` (the envelope names another target or name),
`invalid_secret` (the broker would refuse the settings; the service's message names the field) and `policy_mismatch`
(the settings sent are not the policy sealed). Nothing is stored in any of these cases.

The secrets list shows each secret's upstreams, header, scheme and user, its rules (or *Wildcard rules*), the
ciphertext digest, the host's value fingerprint and its sealed policy digest, which the browser recomputes from the
settings shown; a secret whose settings do not make it is marked as unusable, to be deleted. A secret stored without rules by an older client is marked
"No broker rules: no launch can use it (secret_rules_missing)".

The value lives only in one uncontrolled password field: never in React state, the URL, storage, the console or error
text. The field is cleared before sealing starts, the value's bytes are zeroed after sealing, and the receipt secret is
wiped when the dialog closes. A browser without Ed25519 or X25519 in WebCrypto gets an unsupported-browser message and
the CLI command. There is no fallback: nothing is sealed without a verified, host-signed seal key, and nothing is sent
in plaintext.

### Launch an agent (launcher)

**Launch** is a guided form for one `agentgate.launch.v1` spec:

1. *What and where*: name, an active target (with its capabilities), one-shot or session, and the lifetime in seconds,
   minutes or hours within the contract's bounds (one-shot 1 s to 1 h, session 1 min to 24 h). The clock starts when the
   launch is queued.
2. *The agent*: image digest (`name[:tag]@sha256:<64 hex>`), command one argument per line (no shell), working
   directory, and non-secret environment. Names that look like credentials or are reserved are refused with the
   service's rule (`KEY`, `TOKEN`, `*_KEY`, `PASSWORD`, `LD_*`, `AGENTGATE_*`, …).
3. *Access*: a stored profile and version, with its "What can this agent do?" summary, or an inline document (always
   needs approval, cannot use secrets).
4. *Host folders*: name, host folder and mode. Modes the target does not advertise are disabled (`live-mounts` for
   read-only and read-write, `snapshot-mounts` for snapshot). Protected trees, credential stores, home directories and
   overlaps are flagged as you type; the service and the host check again.
5. *Brokered secrets*: every launcher sees the target's pending and stored secrets from `GET /targets/{id}/secrets`
   (name, state, upstream hosts, rule count or wildcard, and whether they and the chosen profile may use it, with the
   reason when not); no fingerprint, envelope or scope list reaches the page. Each secret gets the variable that
   receives the broker address. The agent never sees the value.
6. *Approval*: automatic when allowed, or always required, with the reasons the form can predict.

**Review & plan** is mandatory. It calls `POST /launch-plans` (creates nothing) and shows the spec digest, policy
digest, target, profile version, mode, lifetime and expiry rule, image, command, working directory, whether approval
is needed and every reason, the service's notices, the effective permissions (the service's summary and the plain
language table for the effective launch policy, including the task board and the secret broker rows), each mount with
its path inside the agent, and, for a launch with secrets, the broker endpoint (`plan.broker`: address and port, the
launch's only private destination, its network and the agent's address) and each brokered secret: the variable and the
`base_url` it receives, the upstreams, header, scheme and user, the extra headers, the requests the broker forwards
(or a wildcard warning) and the host's value fingerprint. Validator errors appear verbatim with their code; the secret
refusals `secret_rules_missing`, `secret_unavailable` and `secret_scope` add what to do. **Launch** appears only
after a plan and sends exactly the planned document; editing the form afterwards disables it until you plan again.

**Import spec JSON** loads a file or pasted document strictly (one object, no unknown fields, no duplicate keys, no
`value` field). **Copy spec JSON** and **Copy as CLI commands** give the same document as
`cat > NAME.json <<'SPEC' … SPEC`, `agentgate launch --dry-run -f NAME.json` and `agentgate launch -f NAME.json`.

### Approve, follow and stop (approver, launcher)

"A different person" in this section means a different person as the service knows it: the service compares the
approver's subject (`local:alice`, `oidc:...`) with the requester's and with the subjects an administrator linked as the
same person. **Linked identities** (administrators) lists those groups; `agentgate identity link` and `unlink` change
them. Accounts nobody linked count as different people, so each person should hold one account with the launcher or
approver role, or have their accounts linked ([PROVISIONING.md](PROVISIONING.md)).

**Launches** lists launches newest first with state, target, requester, lifetime and remaining time. The service applies
every filter (state, or not ended / ended; target; name contains; only mine) and pages the result 25 at a time with its
cursor; Previous returns to exactly the page seen before.

The launch page shows:

- the state, the spec and policy digests, the lifetime and expiry (or the end time), the decision and reasons;
- **Approve** and **Reject** for an approver who did not request the launch, with the plan's digests, each brokered
  secret's sealed policy digest and the approval reasons in the confirmation. A disabled button says why: no approver
  role, not waiting for approval, "You requested this launch. A different person must decide it.", or that the plan's
  broker settings for a secret do not make the sealed policy digest it names (the browser recomputes each digest from
  the settings the plan shows; such a plan shows something other than what the host would run, and only **Reject**
  is offered). The plan marks each secret "These settings are the policy sealed with the value." or "These settings do
  not make the sealed policy digest: do not approve.";
- **Stop** with confirmation; it is idempotent. While stopping, the page says the launch ends stopped or expired only
  when the host confirms an empty domain and released enforcement;
- the **state timeline**: every event with its sequence, from → to, actor, reason and data (digests, expiry), live
  over Server-Sent Events. The client resumes after the last sequence (`?after=` and `Last-Event-ID`), reconnects with
  backoff (1, 2, 4 … 30 s), and after four failures polls the JSON events every 5 s while retrying the stream each
  minute. The status line says Live, Reconnecting or Polling;
- **agent output**: streamed from `/logs` as Server-Sent Events (one `log` event per line, resumed after the last line
  with `?after=` and `Last-Event-ID`, ended by the service's `end` event once the launch is terminal); when the stream
  keeps failing, or the service does not stream, the page polls `/logs?after=` every 4 s and retries the stream each
  minute. Follow or pause, search (text or `stderr`),
  download as plain text. Output is rendered only as text; control characters and bidirectional overrides appear as
  escapes such as `\x1b` and `‮`. The page keeps the newest 20,000 lines and shows the newest 2,000 matches. When
  the service's 1 MiB / 20,000-line bound was hit, a banner says so and the marker line is highlighted;
- the **evidence receipt**: spec and policy digests compared with the launch, BPF object and guard digests, domain
  empty and enforcement released, exit and reason, host folder identities, broker requests per upstream, and the
  guard's per-operation allowed and denied counts, lost and complete flags and first denials with paths. A terminal
  launch without a receipt shows its `evidence_missing` reason prominently with what it means;
- the stored plan (with the broker endpoint and each secret's `base_url` and rules, as in Review & plan), the
  canonical spec, the host jobs, **Launch again from this spec** and the matching CLI commands.

### API tokens for the CLI

**API tokens** creates a token with a subset of your roles (an administrator may grant any) and a lifetime of 1 hour
to 90 days. The token is shown once with `agentgate login ORIGIN --token-stdin`; the list shows holder, roles, expiry,
last use and revocation, and **Revoke** asks for a reason. Tokens reach only the provisioning, overview and audit
endpoints and cannot mint tokens.

### Overview

The Overview adds targets online (with keys awaiting approval and targets needing re-enrollment) and, from
`GET /launches/summary`, running launches, launches waiting for *your* approval, launches expiring within 30 minutes and
launches by state over every launch, with links to each.

## Permissions

The UI hides navigation an actor cannot use and disables actions with a visible reason, but the service enforces every
rule again; hiding is never the control.

| Action | viewer | auditor | editor | launcher | approver | admin |
| --- | --- | --- | --- | --- | --- | --- |
| See targets, profiles, versions, launches, events, logs, receipts | yes | yes | yes | yes | yes | yes |
| Add, approve the key of, re-enroll, rename or retire a target | | | | | | yes |
| Create a profile, apply grants, add a version from a document | | | yes | | | yes |
| Create a profile without launch approval; change a profile's approval setting | | | | | | yes |
| Plan, launch and stop launches (any launch) | | | | yes | | yes |
| Approve or reject a launch (never one you or a subject linked to you requested) | | | | | yes | yes |
| See linked identities | | | | | | yes |
| List, store and delete secrets | | | | | | yes |
| Create, list and revoke your own API tokens | yes | yes | yes | yes | yes | yes (all tokens) |

Navigation: *Launch* appears for launchers and administrators, *Secrets* and *Linked identities* for administrators,
*API tokens* for any signed-in person with a role.

## UI and CLI

| UI | CLI | API |
| --- | --- | --- |
| Targets list, target page | `target ls`, `target status NAME` | `GET /targets`, `GET /targets/{id}` |
| Add target | `target add NAME` | `POST /targets` |
| Approve host key | `target approve-key NAME` | `POST /targets/{id}/approve-key` |
| New enrollment token, Rename, Retire | `target enroll`, `target rename`, `target retire` | `POST …/enrollment`, `PATCH`, `DELETE /targets/{id}` |
| Mount roots… | `target mount-roots NAME --root PATH` | `POST /targets/{id}/mount-roots` |
| Linked identities (list) | `identity ls`, `identity link`, `identity unlink` | `GET`, `POST`, `DELETE /identity-links` |
| Access profiles, versions, compare | `profile ls`, `profile show`, `profile versions` | `GET /profiles…` |
| New profile | `profile new NAME --preset P` | `POST /profiles` |
| Change access: preview / apply | `grant P ACTION … --dry-run` / `grant P ACTION …` | `POST /profiles/{id}/versions/{n}/grants` |
| Launch approval setting (approves the selected version and digest) | `profile approval NAME required\|auto --version N` | `PATCH /profiles/{id}` |
| Launch: Review & plan / Launch | `launch --dry-run -f SPEC` / `launch -f SPEC` | `POST /launch-plans`, `POST /launches` |
| Launches, launch page | `ps`, `show ID` | `GET /launches`, `GET /launches/{id}` |
| State timeline (live) | `events ID -f` | `GET /launches/{id}/events` (SSE) |
| Agent output | `logs ID -f` | `GET /launches/{id}/logs` |
| Approve, Reject | `approve ID --reason R`, `reject ID --reason R` | `POST /launches/{id}/approve`, `/reject` |
| Stop | `stop ID --reason R` | `POST /launches/{id}/stop` |
| Store a secret, delete | `secret set NAME … --rule M:PATH`, `secret rm NAME` | `GET /targets/{id}/seal-key`, `POST /secrets`, `GET /secrets/{id}/receipt`, `DELETE /secrets/{id}` |
| Launch form secret list | `secret ls --for-launch --target T --profile P` | `GET /targets/{id}/secrets` |
| API tokens | `token create`, `token ls`, `token revoke` | `/api-tokens` |

Pins differ by client: the CLI keeps `~/.config/agentgate/known-targets.json`; the browser keeps its own pins in
`localStorage`. A browser that has no pin asks you to compare the fingerprint before it seals.

## Security and accessibility notes

- Writes send `X-CSRF-Token`, `Content-Type: application/json` and an `Idempotency-Key` (the QA checks every write).
- React renders all text; there is no `dangerouslySetInnerHTML`. Log lines, denial paths and evidence fields are shown
  as text with visible escapes for control and bidi characters.
- One-time tokens are shown in read-only fields with copy buttons and dropped from the page when their dialog closes.
- Leaving a page aborts its requests. A 401 that means the session ended (`session_expired`, `authentication_required`,
  …) returns to the sign-in page, and a banner warns five minutes before the session expires.
- Lists are bounded by the API (targets and secrets 500, profile versions 200) and paged 25 per page in the browser; the
  pager says when the API bound applies. Launches are paged by the service with a cursor.
- Inputs have labels; tables have captions and header scopes; dialogs use the native modal `<dialog>` (focus stays inside
  and Escape closes); state changes and copy results are announced in polite live regions; badges, health and stream
  status always carry text, so color is never the only signal; layouts work at 390 px wide without horizontal scrolling.

## Development and tests

```sh
cd web
npm ci                                  # lockfile only; no dependency was added for these pages
npm run typecheck                       # tsc -p .
npm run build                           # vite build into web/dist (ignored by git)
npm run test:unit                       # node --test: policy schema, provisioning logic, secret sealing
QA_OUTPUT=/tmp/qa npm run test:provisioning-browser
QA_OUTPUT=/tmp/qa npm run test:policy-browser
```

The browser QA needs a build and Playwright's Chromium. Where the pinned Playwright's browser is not downloaded, point
`QA_CHROMIUM` at an installed one, for example `/opt/pw-browsers/chromium_headless_shell-1194/chrome-linux/headless_shell`.

- `qa/provisioning.node.mjs`: the spec builder and importer; parity with the Go validators (it reads
  `prov_launchspec.go` and `hostproto/jobs.go` and compares the env, name, image and mount patterns, the protected trees
  and lifetime bounds); access summaries, risks and diffs; the SSE parser and the stream client (resume, polling
  fallback, 401); logs; receipt parsing; broker rule and extra header checks against `hostproto` (methods and bounds
  read from `jobs.go`); the explanations of every secret refusal in the recorded service answers.
- `qa/secretseal.node.mjs`: the RFC 9180 A.2.1 vector reproduced byte for byte with its ephemeral key; ChaCha20-Poly1305
  against OpenSSL; the Go known-answer vector (`fixtures/secretseal-vector-v2.json`, a copy of
  `internal/secretseal/testdata/vector-v2.json` that the test compares with the original) verified, opened and its
  receipt checked, and refused under another policy digest; every Go policy vector
  (`fixtures/secret-policy-vectors.json`, written by `internal/hostproto` with `AGENTGATE_WRITE_WEB_FIXTURES=1`)
  reproduced (normalized policy, canonical bytes and digest) and every refused vector refused; browser-sealed
  envelopes opened by an independent node:crypto implementation (`qa/hpke-node.mjs`);
  key substitution, forged signatures, swapped seal keys, other targets, expired records and bad receipts refused.
- `qa/provisioning.mjs`: an owned API fixture drives every flow in Chromium: add target and approve key; profile from a
  preset, the service's grant dry run, grant, conflict shown verbatim, version diff; launch form rules, plan, stale
  plan, launch; requester cannot approve, another approver does; live updates and resume; stream failure to polling;
  logs as text; stop, receipt and evidence; `evidence_missing`; secret sealing with missing, substituted, forged and
  rewritten keys refused, the value never sent, stored or logged, and the host's receipt verified; broker rules, the
  wildcard confirmation, Basic, `seal_key_changed` and `secret_rules_missing`; brokered secrets in a plan with the
  broker endpoint; the sealed policy shown before sealing and carried by the envelope; a plan whose settings do not
  make its sealed digest cannot be approved; a service that records other settings than the sealed policy is caught;
  strict import; API tokens; overview; launch list filters and paging; a viewer's disabled controls;
  session expiry; retiring a target; CSRF on every write; labelled inputs; 390 px layouts. Its last step compares
  every answer the fixture gave with the real service's recorded answers (`qa/api-shapes.mjs`): no invented field, no
  field of another type, and every field the service always sends.
- `web/qa/fixtures/api/*.json` are answers of the real service, written by
  `AGENTGATE_WRITE_WEB_FIXTURES=1 go test ./internal/control -run TestWebFixtures`; without the variable that test fails
  when the service's answers no longer have the committed shapes.

## Limits

- Kernel enforcement is unverified everywhere; the UI only reports what the API says.
- The browser flows are tested against an owned API fixture whose answers are checked, field by field, against
  answers of the real service (`web/qa/fixtures/api`, recorded by `internal/control/web_fixtures_test.go`, which drives
  the real service over HTTP with an in-process fake host). They were not run against a deployed service, and the
  sealing code was checked against the Go package's vector and its `Open`, not against a real host.
- Browser pins live in `localStorage`: a private window or cleared site data loses them, and the page then asks for the
  fingerprint again. They are not shared with the CLI.
- The receipt check only works while the dialog that sealed the secret is open, because the browser keeps the receipt
  secret in memory only.

## Resolved

The backend requests this page once listed are implemented in the service and used by the UI and the CLI:

1. **Grant dry run.** `POST /profiles/{id}/versions/{n}/grants` with `"dry_run": true` answers the would-be document,
   the parent and result digests, the structured change list, messages and notices, creates no version and is audited
   as `profile.grant.previewed`. The UI preview and `agentgate grant --dry-run` both use it.
2. **Seal key publication.** `GET /targets/{id}/seal-key` returns the host-signed `secretseal.SignedKeyRecord` verbatim
   with `host_public_key`, `host_key_id`, `seal_key_id` and `not_after`, and 404 `seal_key_unavailable` while the host
   has not published one.
3. **Envelope acceptance.** `POST /secrets` takes `ciphertext` = `Envelope.Encode()` and the broker settings (`scheme`,
   `username`, `rules`, `extra_headers`), refusing with `409 seal_key_changed`, `409 seal_key_unavailable`,
   `422 invalid_ciphertext` or `422 invalid_secret`.
4. **Receipt relay.** `GET /secrets/{id}/receipt` (and `receipt` on the secret record) relays the host's
   `secretseal.Receipt`.
5. **Secret names for launchers.** `GET /targets/{id}/secrets` (`launch:write`) lists names, states, upstream hosts,
   rule summaries and whether the caller and profile may use each one, without fingerprints, envelopes or scope lists.
6. **Launch list filters and paging.** `GET /launches?state=&target=&name=&requester=&mine=&limit=&cursor=` with an
   opaque `next_cursor`, and `GET /launches/summary` for the overview.
7. **Log streaming.** `GET /launches/{id}/logs` with `Accept: text/event-stream` streams `log` events with sequence ids,
   resumes with `Last-Event-ID`, sends heartbeats and ends with an `end` event once the launch is terminal.
