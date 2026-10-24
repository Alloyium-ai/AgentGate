# Provisioning, access and agent launch

This is the contract for the single control plane. The Go service (`cmd/community`), its React UI, and one Go CLI
(`cmd/agentgate`) share one REST API, one set of roles, and one audit trail. Nothing here is implemented by this
document; it fixes the shapes that each part builds against. Status of each part is tracked in the last section.

Kernel enforcement is the existing guarded SSH POC (`poc/ssh-diagnostic`, `bpf/`). It has not been run on a BPF LSM
kernel. Every launch record states that, until a verification report says otherwise.

## Vocabulary

| Term | Meaning |
| --- | --- |
| Target | A Linux host or appliance VM that can enforce policy. It runs `agentgate-hostd`. |
| Access profile | A named, versioned policy: network, filesystem, executables, processes, mounts, bridges. |
| Launch spec | One immutable request to run an agent: what, where, for how long, with which access and secrets. |
| Launch | One execution of a launch spec on a target. It has a state machine and an evidence receipt. |
| Secret | A credential held outside every sandbox. An agent reaches it only through a broker. |
| Broker | A host-side service that injects a secret into allowed upstream requests. |

## Single surface

- **Service:** `agentgate serve` (today `cmd/community`) owns state, users, roles, approvals and audit.
- **UI:** the existing React app gains Targets, Profiles, Launch, Launches and Secrets pages. It uses only `/api/v1`.
- **CLI:** `cmd/agentgate` is a thin client of the same API. It holds no policy logic of its own. Anything the CLI can
  do, the UI can do, and the reverse, because both call the same endpoints.
- **Host agent:** `agentgate-hostd` runs on each target. It makes only outbound calls to the service, verifies every job
  signature, and is the only component that touches Docker, cgroups, BPF or the appliance scripts.
- **Bring-up:** `agentgate up` starts the service, enrolls this machine as a target, and prints the UI address.

## Launch spec: `agentgate.launch.v1`

```json
{
  "version": "agentgate.launch.v1",
  "name": "repo-fixer",
  "target": "local",
  "mode": "session",
  "lifetime_seconds": 3600,
  "agent": {
    "image": "agentgate-coding@sha256:<64 hex>",
    "command": ["claude", "--print", "fix the failing tests"],
    "env": {"EDITOR": "vi"},
    "workdir": "/var/lib/agentgate/workspace"
  },
  "access": {"profile": "python-dev", "version": 3},
  "mounts": [{"name": "repo", "source": "/srv/repos/app", "mode": "read-only"}],
  "secrets": [{"ref": "anthropic", "expose": {"env": "ANTHROPIC_BASE_URL"}}],
  "approval": "auto"
}
```

Rules every implementation enforces (`internal/control/prov_launchspec.go`; JSON Schema at `GET /launch-spec-schema`):

- The document is one JSON object of at most 64 KiB with no unknown fields and no duplicate keys.
- `name` and `target` match `^[a-z0-9][a-z0-9-]{0,39}$`. `mode` is `oneshot` or `session`.
- `oneshot` runs `agent.command` once and ends. `lifetime_seconds` is 1 to 3600 and `agent.command` is required.
  `session` is a long-running agent. It allows 60 to 86400. The lifetime is the hard cap. The service writes the mode
  and lifetime into the launch policy (`pocpolicy.Document.ForLaunch`), so the kernel policy expires at the lifetime.
  The lifetime starts when the launch is queued (after approval), not when it was requested.
- `agent.image` is an immutable digest reference (`name[:tag]@sha256:<64 hex>`). `agent.command` has at most 128
  arguments and 32 KiB. `agent.env` holds at most 64 entries and no secrets: a validator rejects names that look like
  credentials (`KEY`, `TOKEN`, `SECRET`, `PAT`, `*_KEY`, `*_PAT`, `*_AUTH`, and names containing `PASSWORD`, `PASSWD`,
  `SECRET`, `TOKEN`, `APIKEY`, `API_KEY`, `PRIVATE_KEY`, `CREDENTIAL`, `AUTHORIZATION` or `COOKIE`) and reserved
  names (`LD_*`, `DYLD_*`, `AGENTGATE_*`). Secrets arrive only through `secrets`.
- `agent.workdir` defaults to `/var/lib/agentgate/workspace` and must be inside the workspace, `/tmp` or a spec mount.
- `access` is either `{"profile": NAME, "version": N}` or `{"inline": DOCUMENT}`, never both. A launch policy is
  always `agentgate.poc.v2` (filesystem and process controls); a version one profile cannot launch. The effective
  policy is the profile document plus one access entry per mount, with the launch mode and lifetime. Its SHA-256 is
  recorded on the launch.
- `mounts[]` (at most 8): `name` matches `^[a-z0-9][a-z0-9_-]{0,31}$` and is unique; `mode` is `read-only` (a live
  bind), `snapshot` (a read-only copy) or `read-write` (a live writable bind). A live mount needs the target capability
  `live-mounts`; a snapshot needs `snapshot-mounts`. `source` is a canonical absolute path of safe characters that
  does not overlap a protected host tree (`/proc`, `/sys`, `/dev`, `/run`, `/etc`, `/root`, `/boot`, `/usr`, `/bin`,
  `/sbin`, `/lib*`, container runtime state, `/var/lib/agentgate`), a credential store (`.ssh`, `.gnupg`, `.aws`,
  `.config`, `.docker`, `.kube`, `.local`, ...), a home directory itself, or another mount. A writable mount is never
  executable (`internal/access` refuses the overlap). The host re-checks every rule.
- `secrets[]` (at most 8): `ref` names a secret on that target, by name only; `expose.env` names the variable that
  receives the broker address and may not also appear in `agent.env`. The spec never contains a value (an unknown
  field such as `value` is rejected).
- `approval` is `auto` or `required`. `auto` is honoured only when nothing requires a second human. Approval is
  required when any of these hold: the spec says `required`; the profile has `require_approval` (the default for a
  new profile; only an administrator creates or changes a profile that skips it); access is an inline document; any
  mount is live (`read-only` or `read-write`); any secret is referenced; the effective policy allows public web. The
  plan lists every reason. A launch that needs approval waits in `approval_pending` for a different human with the
  `approver` (or `admin`) role. The requester can never decide their own launch, with any credential.
- Brokered secrets need a stored profile. Each secret is scoped to the profiles (`allowed_profiles`) and human
  subjects (`allowed_launchers`) that may reference it; the scope is checked when the launch is planned and again when
  it is queued. The plan names the exact secret refs and secret ids, and the approval covers that plan.
- The service stores the canonical JSON (Go `encoding/json` of the decoded spec, so key order and whitespace do not
  matter) and its SHA-256. A launch refers to that digest. A stored spec never changes.

Creating a launch (`POST /launches`) or a dry run (`POST /launch-plans`) returns the resolved plan: spec digest,
policy digest, target, profile version, mode, lifetime, `expires_at` (once queued), image, command, workdir, approval
decision and reasons, effective permissions (network default, web protocols, DNS resolvers, read-only, writable,
executable and denied trees, devices, signals, anonymous execute), mounts with their in-agent paths, brokered secrets
(name, id, env, upstreams, header; never a value), `kernel_verified: false` and notices. The plan is stored with the
launch and never changes.

## Launch state machine

```
requested -> approval_pending -> approved -> queued -> provisioning -> running -> stopping -> stopped
                                                                                        \-> expired
(rejected, cancelled, failed and early stopping edges: see the table below)
```

The complete transition table is `LaunchTransitions` in `internal/control/prov_launches.go`:

| From | To |
| --- | --- |
| `requested` | `approval_pending`, `approved`, `rejected`, `cancelled` |
| `approval_pending` | `approved`, `rejected`, `cancelled` |
| `approved` | `queued`, `cancelled`, `failed` |
| `queued` | `provisioning`, `stopping`, `failed`, `cancelled` |
| `provisioning` | `running`, `stopping`, `failed` |
| `running` | `stopping`, `expired`, `failed` |
| `stopping` | `stopped`, `expired`, `failed` |

- One function (`transitionLaunch`) changes a launch state. It refuses every other pair, compares and sets the
  launch revision (a concurrent change fails with `launch_changed`), and writes the launch event and the audit
  record in the same SQL transaction. Database triggers also refuse any change to a terminal launch, to the launch
  binding (spec digest, policy, policy digest, plan, target, requester) and to a recorded receipt.
- Terminal states: `stopped`, `expired`, `failed`, `rejected`, `cancelled`. A terminal launch has an evidence receipt
  or an explicit `evidence_missing` reason (`not_started`, `lost_host`, `receipt_missing`, or the host's code). A
  launch is never marked `stopped` or `expired` unless its receipt has `domain_empty` and `enforcement_released`
  true; a receipt without both ends the launch `failed` with `cleanup_incomplete` and queues another `stop`.
- Every transition is one audit record (`launch.state.changed`): actor, from, to, spec digest, policy digest, reason.
- `running` must be backed by a heartbeat from the host. No verified poll for 3 poll intervals (30 seconds at the
  default 10 second interval) moves a `provisioning`, `running` or `stopping` launch, or a `queued` launch whose job
  was delivered, to `failed` with `lost_host`, and queues a `stop` job (valid for 24 hours) that the host executes
  when it returns. A receipt that arrives later is attached to the failed launch.
- A launch past its lifetime moves to `stopping` with a `stop` job; it ends `expired` when the host confirms cleanup.
- Stop is idempotent. A launch that never reached its host (`requested`, `approval_pending`, `approved`, or `queued`
  with an undelivered job) is `cancelled` with `not_started` and its jobs are cancelled. Otherwise it moves to
  `stopping` and exactly one `stop` job is queued. Stopping a `stopping` or terminal launch changes nothing.
- A launch waiting for approval for 24 hours is `cancelled`. A launch job that is never collected before its deadline
  expires and the launch fails with `not_started`.
- A profile edit creates a new version and never changes a launch: the launch holds its own copy of the policy.

## Host job protocol

The service never connects to a target. `agentgate-hostd` polls. The wire types, sign and verify helpers and golden
files are in `internal/hostproto` (standard library only; no dependency on the service).

**Signed envelope.** Every host request and every job is `{"domain","key_id","payload","signature"}`. `payload` is the
unpadded base64url of the exact JSON bytes that were signed, so neither side re-encodes. `key_id` is `ed25519:` and
the first 16 bytes of the key's SHA-256 in hex. The Ed25519 signature covers
`"agentgate-hostproto-v1" 0x00 domain 0x00 key_id 0x00 payload`, so a signature for one domain never verifies as
another. Domains: `agentgate.hostd.enroll.v1`, `.poll.v1`, `.events.v1`, `.resync.v1` (host to service, signed by
the host key) and `agentgate.hostd.job.v1` (service to host, signed by the service job key). Payloads decode strictly:
unknown fields, duplicate keys and trailing data are rejected. An envelope is at most 1 MiB, a payload 512 KiB.

- **Enrollment** (`POST /hostd/enroll`, `EnrollRequest`): an administrator creates a target (`POST /targets`) and
  receives a one-time token (`agtenr_` and 43 base64url characters, stored only as its SHA-256, shown once, never
  cached for idempotent replay). The token expires in 15 minutes and works once. The host sends the token, its
  Ed25519 public key, its X25519 encryption key, hostname, capabilities, version, nonce and timestamp, signed by the
  key it binds. The reply carries the target id, the host key id, the service job key and its id, the poll interval,
  and `token_mac` (HMAC-SHA256 keyed by the token over those fields), so the host detects a substituted job key. The
  binding is **not active** yet: the target is `awaiting_key_approval` and polls fail with `key_approval_pending`.
  The host prints its key fingerprint (`host_key_id`); an administrator compares it with the one the service shows
  and approves it with `POST /targets/{id}/approve-key` (`{"host_key_id","reason"}`, constant-time compared). A token
  intercepted in transit therefore cannot activate a foreign key without the administrator noticing a mismatch.
  Enrolling again (a new token from `POST /targets/{id}/enrollment`) retires the old key, cancels the target's queued
  jobs, and is refused while the target has a launch that is not terminal.
- **Signed request header** (poll and events): `host_id`, `nonce` (16 to 48 random bytes, base64url), `timestamp_ms`
  and `sequence`. The service rejects a timestamp more than 60 seconds from its clock, a nonce it saw in the last
  2 minutes (`replayed_request`), and a sequence not greater than the last accepted one (`sequence_replayed`, with
  `last_accepted_sequence` in the error body so an honest host can resynchronise). Gaps are allowed: a request lost
  before it reached the service leaves one. One counter covers every signed request of a host; the host serializes
  its signed requests and persists the counter before sending. A request that verifies but is then refused still
  advances the nonce and sequence, so it can never be replayed later.
- **Resync** (`POST /hostd/resync`, `ResyncRequest`): a host that lost its counter (crash before persisting, disk
  restore) sends `host_id`, `nonce`, `timestamp_ms` and a reason code, signed by its enrolled key. The service resets
  the last accepted sequence to 0 (`target.sequence.reset` audit record) and the host continues from 1. Replay of a
  resync is bounded by the same nonce window and timestamp skew, and no older request becomes valid again because
  every request is also timestamp-bound.
- **Poll** (`POST /hostd/poll`, `PollRequest`): the header, a heartbeat (`capabilities`, `running_launches`,
  `agent_version`, `kernel_verified`, which must be false) and `max_jobs` (1 to 16). The reply (`PollResponse`) holds
  the server time, the poll interval, the accepted sequence and zero or more job envelopes in queue order. A job
  delivered without any event is re-sent after one minute, at most 5 times. A host that reports a launch the service
  considers ended receives a `stop` job.
- **Job** (`hostproto.Job`): `{version: "agentgate.hostd.job.v1", id, type, target_id, launch_id, spec_digest,
  policy_digest, issued_at_ms, deadline_ms, payload}`, signed by the service job key when it is queued (so the
  delivered bytes are the audited bytes). `Job.Check(target_id, now)` verifies the version, type, target, issue time
  (at most 60 seconds ahead), deadline (in the future, at most 25 hours after issue), the digest binding and the
  typed payload. The host also verifies the envelope with the job key from enrollment and acts only when both pass.
- **Job types and payloads** (Go types in `internal/hostproto/jobs.go`; examples in `internal/hostproto/testdata/jobs`):

| Type | Binding | Payload |
| --- | --- | --- |
| `provision` | none | `{images: [digest refs], reason: code}`: pull images, check the guard; starts nothing |
| `apply-profile` | `policy_digest` = SHA-256 of `policy` | `{profile_id, profile_version, policy}`: stage and pre-check a policy |
| `launch` | `launch_id`, `spec_digest` = SHA-256 of `spec`, `policy_digest` = SHA-256 of `policy` | `{spec, policy, expires_at_ms, heartbeat_seconds, mounts: [{name, source, mode, path}], secrets: [{ref, secret_id, env, upstreams, header}]}` |
| `stop` | launch and both digests | `{reason: code, grace_seconds: 0..300}`: stop, kill the domain, release enforcement, return the receipt |
| `collect` | launch and both digests | `{reason: code}`: return the receipt without changing anything |
| `secret-put` | none | `{secret_id, name, upstreams, header, ciphertext, ciphertext_sha256}` |
| `secret-delete` | none | `{secret_id, name}`: remove the value from the host |
| `snapshot-mount` | `launch_id`, `spec_digest` | `{name, source, max_bytes: <=256 MiB, max_entries: <=20000}` |

  `secret-delete` was added to the original seven types: without it a deleted secret's value would stay on the host.
  For `launch`, `expires_at_ms` is at most the spec lifetime after issue and the deadline is the expiry plus 5 minutes.
- **Progress** (`POST /hostd/jobs/{id}/events`, `EventsRequest`): the header, `job_id` and 1 to 64 events
  (`{seq, time_ms, kind, message, stream, state, result}`, at most 256 KiB per batch, 8 KiB per message, 4096 per
  job). `seq` starts at 1 per job and is contiguous. Kinds: `progress`; `log` (`stream` stdout or stderr; the service
  keeps at most 1 MiB and 20000 lines per launch); `state` (`provisioning`, `running` or `stopping`, applied to the
  launch through the state machine); `result` (last event; `{status: succeeded|failed|rejected, reason: code,
  receipt | evidence_missing}`). Re-sending an event the service holds is accepted if byte-identical and refused with
  `event_conflict` otherwise; a gap is refused with `event_gap`. The reply `{accepted_through, completed, job_state}`
  acknowledges the events; the host retries until acknowledged and keeps the receipt on disk until `completed`.
- **Idempotence:** every job id runs at most once on the host. A repeated job returns its recorded result. A job
  result is recorded once (trigger-enforced).
- **Fail closed:** an unverifiable, expired or unknown job is dropped and reported with a `rejected` result. It is
  never run on a guess. A `rejected` or `failed` launch result without a receipt ends the launch `failed` with its
  `evidence_missing` reason.
- **Job key** (`jobs.key`, Ed25519, mode 0600 in the state directory, separate from the application authority key):
  generated at first start, pinned in the independent trust directory (`jobkey.json`), and verified at every start.
  `community job-key` (the `cmd/community` service command) prints it. **Rotation:** `community rotate-job-key REASON` refuses while any
  launch is not terminal, generates a new key, keeps the old file as `jobs.key.retired-<ns>`, retires the old key in
  `job_keys`, cancels its queued jobs, moves every active target to `rekey_required` (polls fail with
  `rekey_required` and no launch can target them), and re-pins the trust file. Each host then enrolls again with a new
  token and an approved fingerprint. A key file that differs from the recorded active key at start is handled the
  same way. Backups include the job key; a restore from a backup without one starts with a new key and requires
  re-enrollment.

## Evidence receipt

The host returns, per launch (`hostproto.Receipt`, at most 128 KiB): the launch, target, spec and policy digests
(which must equal the job's), object digests of every BPF program and the guard binary, the network and host-control
evidence blocks that `pilot-network-diagnostic` already writes, mount identities (`dev:ino` of a live bind or
`sha256:` of a snapshot), broker request counts per upstream (never bodies or secrets), start and end times, the exit
code or reason, `domain_empty`, `enforcement_released`, and a `kernel_verified` flag. `kernel_verified` is never a
host-asserted value: protocol v1 carries no verification report, so the service rejects a receipt or heartbeat that
claims `true`, and every launch and target record stores `false` (a database check constraint on launches). Setting
it requires a future verification report signed by an authority key distinct from every host key and validated by the
service; until that exists it is always `false`.

## REST API (`/api/v1`)

All endpoints require a browser session (with CSRF for writes) or an API token, and the role listed. Responses reuse
the service's error envelope (`{"error":{"code","message"},"request_id"}`). Every write and every denial is audited.

| Endpoint | Method | Role | Purpose |
| --- | --- | --- | --- |
| `/targets` | GET, POST | viewer, admin | list targets; create a target and its one-time enrollment token |
| `/targets/{id}` | GET, PATCH, DELETE | viewer, admin | status, capabilities, key fingerprint, encryption key; rename; retire (refused while a launch is live) |
| `/targets/{id}/enrollment` | POST | admin | a new one-time token (reinstall, job key rotation) |
| `/targets/{id}/approve-key` | POST | admin | approve the presented host key fingerprint; activates the target |
| `/profiles` | GET, POST | viewer, editor | list; create from a preset, a document or the full example |
| `/profiles/{id}` | GET, PATCH | viewer, admin | detail; change `require_approval` (admin only) |
| `/profiles/{id}/versions` | GET, POST | viewer, editor | immutable versions; a new version names the latest as its parent |
| `/profiles/{id}/versions/{n}` | GET | viewer | one version with its document and digest |
| `/profiles/{id}/versions/{n}/grants` | POST | editor | 1 to 16 typed edits (read, write, exec, deny, allow-web, deny-web, dns, signal, anon-exec, mount, unmount, preset, revoke) on the latest version, producing a new version or a no-op |
| `/access-presets` | GET | viewer | presets, edit actions and revoke kinds |
| `/launches` | GET, POST | viewer, launcher | list (`?state=`); create from a spec (validates, returns the plan) |
| `/launch-plans` | POST | launcher | the plan for a spec, creating nothing (`agentgate launch --dry-run`) |
| `/launches/{id}` | GET | viewer | state, spec, plan, policy, receipt, jobs |
| `/launches/{id}/approve`, `/reject` | POST | approver | a different human than the requester |
| `/launches/{id}/stop` | POST | launcher | request a stop; idempotent |
| `/launches/{id}/events` | GET | viewer | ordered events (`?after=`); `Accept: text/event-stream` streams them, resuming from `Last-Event-ID` |
| `/launches/{id}/logs` | GET | viewer | bounded agent output (`?after=`) |
| `/secrets` | GET, POST | admin | metadata only; POST carries a value sealed to the target's encryption key |
| `/secrets/{id}` | DELETE | admin | queue removal from the host (refused while a live launch uses it) |
| `/api-tokens` | GET, POST | any human (session) | list own tokens (admin: all); create one, shown once |
| `/api-tokens/{id}` | DELETE | holder or admin | revoke |
| `/hostd/enroll`, `/hostd/poll`, `/hostd/resync`, `/hostd/jobs/{id}/events` | POST | host key | enrollment, poll, resync, progress |
| `/launch-spec-schema` | GET | any | JSON Schema (draft 2020-12) for the launch spec |
| `/audit-catalog` | GET | viewer | every audit action the provisioning API writes |

Mutating endpoints take a `reason` (3 to 512 characters) except launch creation, which records the spec. Bodies are
at most 4 MiB (1 MiB for `/hostd/*`). An `Idempotency-Key` replays a recorded response, except for responses that
carry a one-time secret (target creation, enrollment tokens, API tokens) or a ciphertext (secrets), which are never
cached.

Roles: `viewer` (read), `auditor` (read and audit export), `editor` (profiles), `launcher` (create, plan and stop
launches), `approver` (decide launches of others), `admin` (everything, including targets, key approval, secrets and
profile approval settings). Scopes on `Actor.Can`: `launch:write` (launcher), `launch:approve` (approver),
`policy:write` (editor), and the admin-only `targets:admin`, `secrets:admin`, `profiles:admin`. No actor decides
their own launch. A policy edit never changes a running launch.

API tokens (`agt_` and 43 base64url characters) are for the CLI: `Authorization: Bearer <token>`. A token belongs to
one human, carries a subset of their roles (an administrator may grant any role), expires in 1 hour to 90 days, is
stored only as its SHA-256, is shown once, and is revocable. Each use takes the intersection of the token's roles and
the holder's current roles, and a restore from backup revokes every token. Tokens reach only the provisioning
endpoints and read-only overview and audit endpoints; they cannot manage users or mint tokens. Machine service
identities keep the existing `Alloyium-Proof` scheme.

## CLI (`agentgate`)

```
agentgate up [--target local]            bring up the service and enroll this machine
agentgate login URL                      store an API token (mode 0600)
agentgate target ls | add NAME | status NAME | retire NAME
agentgate profile ls | show NAME | new NAME [--preset python-dev]
agentgate grant NAME read|write|exec|deny PATH | web https | dns IP | signal TERM | mount SRC --as N
agentgate launch -f spec.json | --name N --target T --mode session --profile P --image I -- CMD...
agentgate ps | logs ID [-f] | stop ID | approve ID | audit [--launch ID]
agentgate secret set NAME --upstream HOST [--header x-api-key]   # reads the value from stdin
```

Every command supports `--json` and has documented exit codes. `launch --dry-run` prints the resolved plan and policy
digest without creating anything.

## Credentials

A secret value is entered once, on the target host's side, through a path the service relays but cannot read: the
host publishes an X25519 key, the client encrypts to it, and the service stores only ciphertext in transit and metadata
afterwards. The host keeps the value in a root-owned file. A broker on the host listens on an exact private endpoint,
holds an upstream allowlist, adds the credential to requests it forwards, and records counts. The sandbox sees only the
broker address. The kernel network policy allows that one endpoint and nothing else private.

## Security invariants

1. The sandbox never receives a secret, a signing key, an API token or Docker access.
2. Every grant, launch, approval and stop is audited with the actor and the digests it acted on.
3. A launch is bound to its spec digest and policy digest. Changing either creates a new launch.
4. A target accepts only jobs signed by the service key it was enrolled with.
5. Failure never widens access: invalid policy, expired job, lost heartbeat and partial setup all end in a stopped,
   cleaned-up target, or in a `failed` launch with a queued stop until the host confirms cleanup.
6. Lifetimes are enforced in the kernel policy and by the host, not by the agent. Caveat: an expired kernel policy
   denies new operations (opens, connects, executions), but it does not tear down connections or file descriptors the
   agent already holds. The stop and expiry path therefore kills every process in the domain and empties it, and a
   launch ends `stopped` or `expired` only when the receipt confirms `domain_empty` and `enforcement_released`.
7. A host key binds to a target only after an administrator approves its fingerprint; a token alone is not enough.
8. `kernel_verified` is never taken from a host. It stays `false` until a verification report signed by an authority
   distinct from every host key is validated by the service.

## Trusted computing base

The service, its database, its job key and the administrator are trusted. **`agentgate-hostd` is fully trusted for
its target**: it holds the host key, the secret values for that target and Docker, BPF and cgroup control. A
compromised `agentgate-hostd` (or root on its host) can:

- run any job differently from its payload, or run agents the service never asked for;
- forge receipts: claim an empty domain, released enforcement, broker counts, mount identities or exit codes;
- assert `kernel_verified` (the service ignores it, but nothing proves the kernel actually enforced the policy);
- read every secret value delivered to that target and bypass the broker entirely;
- report false heartbeats, so lost-host detection does not fire;
- withhold or reorder its own events within the protocol's rules.

It cannot sign jobs, enroll another target, change another target's state, approve launches or alter the service's
audit log. The audit log records what the service decided and what each host reported, attributed to that host's
key; it is not evidence of what actually ran on a compromised host. A compromise of one host is contained to the
targets that host enrolled and the secrets scoped to them; rotate those secrets and re-enroll the host.



## API cookbook

The examples use an API token in `$T` and the service origin in `$U`. Browser sessions send the same bodies with the
session cookie, `Origin` and `X-CSRF-Token`. Every response is JSON; errors are `{"error":{"code","message"}}`.

Create an API token (from a signed-in browser session; shown once):

```sh
curl -sS -X POST "$U/api/v1/api-tokens" -H 'Content-Type: application/json' -H "Origin: $U" \
  -H "X-CSRF-Token: $CSRF" -b "__Host-enforcer-session=$SESSION" \
  -d '{"name":"laptop","roles":["launcher"],"expires_in_seconds":2592000,"reason":"CLI on my laptop"}'
```

Add a target and enroll its host (admin):

```sh
curl -sS -X POST "$U/api/v1/targets" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"name":"local","reason":"Enroll the build host"}'
# -> {"target":{"id":"<target id>","state":"pending",...},"enrollment":{"token":"agtenr_...","expires_at":"..."}}
# On the host: agentgate-hostd enrolls with the token and prints its key fingerprint (ed25519:...).
curl -sS "$U/api/v1/targets/local" -H "Authorization: Bearer $T"        # state awaiting_key_approval, host_key_id
curl -sS -X POST "$U/api/v1/targets/local/approve-key" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"host_key_id":"ed25519:<the fingerprint the host printed>","reason":"Matches the host console"}'
```

Create a profile and grant access (editor; an admin may pass `"require_approval":false`):

```sh
curl -sS -X POST "$U/api/v1/profiles" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"name":"python-dev","preset":"python-dev","reason":"Python work"}'
curl -sS -X POST "$U/api/v1/profiles/python-dev/versions/1/grants" -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' -d '{"edits":[{"action":"read","values":["/srv/data"]},
  {"action":"deny-web","values":["quic"]},{"action":"mount","values":["repo"],"mode":"read-only"}],
  "reason":"Read the data set"}'
# -> {"changed":true,"version":{"number":2,"digest":"..."},"messages":[...],"notices":[...]}
```

Plan, create, approve, follow and stop a launch:

```sh
curl -sS -X POST "$U/api/v1/launch-plans" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -d @spec.json
curl -sS -X POST "$U/api/v1/launches" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -d @spec.json
# -> {"launch":{"id":"<id>","state":"approval_pending",...},"plan":{"approval":"required","approval_reasons":[...]}}
curl -sS -X POST "$U/api/v1/launches/<id>/approve" -H "Authorization: Bearer $APPROVER_T" \
  -H 'Content-Type: application/json' -d '{"reason":"Reviewed the plan"}'
curl -sS -N "$U/api/v1/launches/<id>/events" -H "Authorization: Bearer $T" -H 'Accept: text/event-stream'
curl -sS "$U/api/v1/launches/<id>/logs?after=0" -H "Authorization: Bearer $T"
curl -sS -X POST "$U/api/v1/launches/<id>/stop" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"reason":"Done"}'
curl -sS "$U/api/v1/launches/<id>" -H "Authorization: Bearer $T"       # state, plan, policy, receipt, jobs
```

Store a secret (admin). The client seals the value to the target's `encryption_key` with
`hostproto.SealSecret(key, value, hostproto.SecretAAD(target_id, name))`; the service never sees the value:

```sh
curl -sS -X POST "$U/api/v1/secrets" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"name":"model-api","target":"local","upstreams":["api.model.example"],"header":"x-api-key",
  "ciphertext":"<base64url sealed value>","allowed_profiles":["python-dev"],"allowed_launchers":["local:lin"],
  "reason":"Model access for the coding agent"}'
curl -sS -X DELETE "$U/api/v1/secrets/<id>" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"reason":"Rotate"}'
```

Rotate the job key (on the service host, with no live launches), then re-enroll each target:

```sh
community rotate-job-key "Scheduled rotation"
curl -sS -X POST "$U/api/v1/targets/local/enrollment" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"reason":"Re-enroll after job key rotation"}'
```

## Parts and status

| Part | Owner area | Status |
| --- | --- | --- |
| This contract | `docs/PROVISIONING.md` | written |
| Control plane: store, API, roles, job queue, audit | `internal/control`, `internal/access`, `internal/hostproto`, `cmd/community` | implemented and tested in the build sandbox (no BPF LSM kernel, no real host); see the cookbook |
| Host agent and long-running launch runtime | `cmd/agentgate-hostd`, `internal/hostd`, `poc/ssh-diagnostic` | implemented and unit-tested with fakes; Docker, systemd and the BPF LSM kernel were not exercised. The launch runtime (`launch.py`) runs a verified job in the guarded-target path; the daemon enrolls, polls, verifies and runs jobs at most once, retries uploads from a durable outbox, enforces the lifetime and the lost-service grace, and reconciles after a crash. `agentgate-hostd provision` and the `provision` job wrap `appliance.py start`. `verify-kernel.sh` is the kernel verification kit |
| Credential broker | `cmd/agentgate-broker`, `internal/broker` | not started |
| CLI | `cmd/agentgate` | not started |
| UI pages | `web/src` | not started |
| Kernel verification on a BPF LSM host | `docs/QUALIFICATION.md` | not possible in the build sandbox |
