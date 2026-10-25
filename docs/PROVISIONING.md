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

- **Service:** `cmd/community` (built as `community`; the image runs it) owns state, users, roles, approvals and audit.
- **UI:** the React app has Overview, Targets, Access profiles, Launch, Launches, Secrets, API tokens and Linked
  identities pages for the provisioning API. They use only `/api/v1`.
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
  `/sbin`, `/lib*`, container and VM runtime state (`/var/lib/docker`, `containerd`, `containers`, `rancher`,
  `kubelet`, `libvirt`, `lxd`, `incus`), `/var/lib/systemd`, `/var/lib/private`, `/var/lib/sss`, `/var/lib/polkit-1`,
  `/var/lib/sudo`, `/var/backups`, `/var/log`, `/var/mail`, `/var/spool`, `/lost+found`, `/var/lib/agentgate`), a
  credential store (`.ssh`, `.gnupg`, `.aws`, `.config`, `.docker`, `.kube`, `.local`, ...), a home directory itself,
  or another mount, and that is at or below one of the target's **mount roots**: the host folders an administrator
  lists for the target (`POST /targets/{id}/mount-roots`, audited as `target.mount_roots.changed`, at most 16 roots
  that pass the same source rules). A new target has none, so every mount is refused (`422 mount_root_not_allowed`)
  until its administrator lists roots. The roots are checked when the launch is planned and again when it is queued:
  a launch approved after its root was removed is not queued (`409 mount_root_not_allowed`, or
  `mount_root_not_on_host` for the host's own list) and stays waiting until it is rejected or the root is listed again. Every mount brings host data into the sandbox and needs a second human's
  approval, a snapshot as much as a live folder; the reason names the mount and its source. A writable mount is never
  executable (`internal/access` refuses the overlap). The host re-checks every source rule and applies **its own
  operator's mount roots** as well (see [Host mount roots](#host-mount-roots)): a host that reports its roots makes the
  service refuse, when the launch is planned, a mount outside them (`422 mount_root_not_on_host`), and the host
  refuses it in any case.
- `secrets[]` (at most 8): `ref` names a secret on that target, by name only; `expose.env` names the variable that
  receives the broker address and may not also appear in `agent.env`. The spec never contains a value (an unknown
  field such as `value` is rejected).
- `approval` is `auto` or `required`. `auto` is honoured only when nothing requires a second human. Approval is
  required when any of these hold: the spec says `required`; the profile has `require_approval` (the default for a
  new profile); the launched profile version is not the one an administrator approved for launches without approval
  (below); access is an inline document; any host folder is mounted (`read-only`, `read-write` or `snapshot`); any secret is referenced;
  the effective policy allows public web. The plan lists every reason.
- Automatic approval is per profile **version**, not per profile. Only an administrator relaxes a profile
  (`PATCH /profiles/{id}` with `require_approval: false`, the `version` they reviewed and its `digest`; or creating a
  profile with `require_approval: false`, which approves its first version), and the service stores that version's
  id and digest with the administrator and the time (`approved_version`, `approved_digest`, `approved_by`,
  `approved_at`; audited as `profile.approval.changed`; a trigger keeps the pair naming a real version of the
  profile). Creating a version never approves it, so an editor who widens an approved profile cannot start the wider
  version alone: a launch of any version whose digest differs from `approved_digest` needs a second human, and its
  approval reasons name the drift from the approved version (DNS resolvers, the taskboard endpoint, public web, any
  workspace, scratch, read-only, execute, device or signal not in the approved version, any deny tree removed, new
  anonymous executable memory), plus what the version grants beyond the shipped defaults (DNS resolvers other than
  `1.1.1.1`, a taskboard endpoint other than `10.10.10.10:8080`, the taskboard bridge, anonymous executable memory,
  devices and signals beyond the defaults). A launch of exactly the approved version lists the latter as notices.
  Requiring approval again clears the approved version; a profile migrated from schema 7 without one launches
  nothing alone until an administrator approves a version. A launch that needs approval waits in `approval_pending` for a different human with the
  `approver` (or `admin`) role. The requester can never decide their own launch, with any credential.
- **"A different human" means a different person, as far as the service knows it.** The service compares the
  approver's subject with the requester's (`local:alice`, `oidc:<issuer subject>`; an API token acts as the subject
  that created it) and with every subject an administrator **linked** to the requester as the same person
  (`identity_links`, schema 11; `agentgate identity link local:alice oidc:<subject>`, `POST /identity-links`, audited
  as `identity.linked`): no subject of a person decides a launch another requested (`403 self_approval`, naming the
  link), and the overview's "awaiting your decision" leaves those launches out. A link grants nothing and changes no
  role; it is used for nothing else. Linking a subject that already belongs to a person merges the two (at most 8
  subjects). `DELETE /identity-links` removes one subject (`identity.unlinked`); a group of one is removed with it, and
  an administrator whose own subject is in a group cannot unlink it (`403 self_unlink`: another administrator must).
  The service still cannot discover by itself that two accounts are one person: link them when you create them, or
  give each person one account with launch or approval rights, and compare the actor of each `launch.approved` audit
  entry with the launch's `requested_by` when reviewing approvals.
- Brokered secrets need a stored profile. Each secret is scoped to the profiles (`allowed_profiles`) and human
  subjects (`allowed_launchers`) that may reference it; the scope is checked when the launch is planned and again when
  it is queued. The plan names the exact secret refs and secret ids, and the approval covers that plan. A secret
  stored without broker rules is refused when a launch is planned (`secret_rules_missing`, deny by default); a secret
  with the explicit wildcard rule adds a `WARNING:` notice and an approval reason. A launch with secrets is assigned its
  own broker endpoint, which the effective policy carries (see [Credentials](#credentials)).
- The service stores the canonical JSON (Go `encoding/json` of the decoded spec, so key order and whitespace do not
  matter) and its SHA-256. A launch refers to that digest. A stored spec never changes.

Creating a launch (`POST /launches`) or a dry run (`POST /launch-plans`) returns the resolved plan: spec digest,
policy digest, target, profile version, mode, lifetime, `expires_at` (once queued), image, command, workdir, approval
decision and reasons, effective permissions (network default, web protocols, DNS resolvers, read-only, writable,
executable and denied trees, devices, signals, anonymous execute, the broker endpoint), mounts with their in-agent
paths, brokered secrets (name, id, env, upstreams, header, scheme, username, rules, `wildcard_rules`, extra headers,
`base_url` and the host's `value_fingerprint`; never a value), the broker endpoint (`broker: {address, port, subnet,
target_address}`), `kernel_verified: false` and notices. The plan is stored with the
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
  jobs, moves the target's secrets to `deleting` with a `secret-delete` each (delivered once the new key is approved;
  the secrets must be stored again), and is refused while the target has a launch that is not terminal.
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
  `agent_version`, `kernel_verified`, which must be false, and `seal_key`, the host's signed seal key record of at
  most 4 KiB) and `max_jobs` (1 to 16). The service stores a `seal_key` only when it verifies against the target's
  approved host key, and serves it verbatim (see [Credentials](#credentials)). The reply (`PollResponse`) holds
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
| `launch` | `launch_id`, `spec_digest` = SHA-256 of `spec`, `policy_digest` = SHA-256 of `policy` | `{spec, policy, expires_at_ms, heartbeat_seconds, mounts: [{name, source, mode, path}], secrets: [{ref, secret_id, env, upstreams, header, scheme, username, rules: [{methods, path, match}], extra_headers}]}`; with secrets, `policy.broker` is the launch's broker endpoint and `rules` holds 1 to 64 rules |
| `stop` | launch and both digests | `{reason: code, grace_seconds: 0..300}`: stop, kill the domain, release enforcement, return the receipt |
| `collect` | launch and both digests | `{reason: code}`: return the receipt without changing anything |
| `secret-put` | none | `{secret_id, name, upstreams, header, ciphertext, ciphertext_sha256}`: `ciphertext` is `secretseal.Envelope.Encode()` sealed for this target and name; the success result carries `secret_receipt` |
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
- **Idempotence:** every job id runs at most once on the host. A repeated job whose result is not yet queued gets
  its recorded result queued again; once the service has acknowledged a job as `completed`, the host answers a
  repeat with nothing (no ledger entry and no event), even after it pruned the job's ledger entry, so re-delivered
  jobs never reopen the outbox. A job result is recorded once (trigger-enforced).
- **Spec binding on the host:** `agentgate-hostd` and `launch_job.py` refuse a launch whose resolved `secrets` differ
  from `spec.secrets` (refs and variables, in order: `secret_binding_differs`) or whose resolved `mounts` differ from
  `spec.mounts` in count or, in order, in name, mode or source (`mount_binding_differs`): the host mounts only the
  folders the signed spec, and so the approval, names, and then checks each against its own rules and mount roots.
- **Host mount roots** (`internal/hostd/mountroots.go`, `poc/ssh-diagnostic/mounts.py`): the host folders a host's
  own operator allows launches to mount or snapshot, in `/etc/agentgate/mount-roots.json`
  (`{"version":"agentgate.hostd-mount-roots.v1","roots":[...]}`, root-owned, mode 0644, in a root-owned directory that
  group and others cannot write, read without following a link). Only `agentgate-hostd install --mount-root PATH ...`
  (or `--no-mount-roots`), `agentgate-hostd mount-roots --root PATH ... | --clear` or root editing the file changes it;
  no job can. A missing file means no roots, so **by default every host folder is refused**. A root passes the same
  rules as a mount source (canonical, safe characters, outside the protected trees, credential stores and home
  directories, at most 16, unique) and may not overlap the host agent's state directory (which holds the broker
  configurations) or its secret store; an invalid or unsafe file allows nothing and is reported by `status` and in the
  log. Before a `launch` or `snapshot-mount` job uses a folder, the host requires it to be inside a root component by
  component (`/srv/dataevil` is not inside `/srv/data`), the deepest such root and the folder to resolve to themselves
  (no symbolic link on either path, `..` is refused as non-canonical), no mount point inside that root at, above or
  below the folder (a bind mount inside a root could bring in any tree; list such a mount as its own root), and neither
  the folder nor its root to be the same directory (device and inode) as a protected tree, the state directory or the
  secret store; otherwise the job is `rejected` with `mount_root_not_allowed` or `invalid_mount` and nothing runs.
  `launch.py`/`mounts.py` apply the same file and rules again right before Docker binds a folder or a snapshot is
  copied (a Go test keeps the two readers and their protected lists equal). The file is read for every check, so an
  edit applies to the next job without a restart, and a running launch whose folder is no longer inside a root is
  stopped at the next poll (`mount_root_removed`; it ends `failed`). Every heartbeat reports the roots the host
  enforces (`heartbeat.mount_roots`, an explicit list; absent only from an older host); the target shows them as
  `host_mount_roots`, the service's own roots outside them as `mount_roots_not_on_host`, and the host's clock against
  the service's at that heartbeat as `host_clock_skew_ms`. Limits: a root that is itself a bind of a subdirectory of a
  protected tree (not of the tree itself) is not detected; and a host user who can write inside a root could replace
  a folder with a link between the last check and Docker's bind, which Docker would follow, so keep the roots writable
  only by users you trust (an agent's own read-write mount is inside a root, but only one launch runs on a target at a
  time and its links are refused at the next launch's check).
- **Fail closed:** an unverifiable, expired or unknown job is dropped and reported with a `rejected` result. It is
  never run on a guess. A `rejected` or `failed` launch result without a receipt ends the launch `failed` with its
  `evidence_missing` reason.
- **Job key** (`jobs.key`, Ed25519, mode 0600 in the state directory, separate from the application authority key):
  generated at first start, pinned in the independent trust directory (`jobkey.json`), and verified at every start.
  `community job-key` (the `cmd/community` service command) prints it. **Rotation:** `community rotate-job-key REASON` refuses while any
  launch is not terminal, generates a new key, keeps the old file as `jobs.key.retired-<ns>`, retires the old key in
  `job_keys`, cancels its queued jobs (each cancellation audited as `job.cancelled`), moves every target bound to the
  old key, active or still waiting for its host key approval, to `rekey_required` (audited as
  `target.rekey.required`; polls fail with `rekey_required` and no launch can target them), and re-pins the trust file.
  Each host then enrolls again with a new token and an approved fingerprint. `POST /targets/{id}/approve-key` refuses
  (`409 rekey_required`) a host that enrolled with a key other than the active one, so a rotation can never leave an
  active target whose jobs its host would refuse. A poll never sends a job signed with a key the host did not enroll
  with: the job is cancelled and audited (`job.cancelled`, reason `job_key_mismatch`) and a launch queued for it fails
  (`evidence_missing: not_started`). A key file that differs from the recorded active key at start is handled the
  same way. Backups include the job key; a restore from a backup without one starts with a new key and requires
  re-enrollment.

## Evidence receipt

The host returns, per launch (`hostproto.Receipt`, at most 128 KiB): the launch, target, spec and policy digests
(which must equal the job's), object digests of every BPF program and the guard binary, the network and host-control
evidence blocks that `pilot-network-diagnostic` already writes, mount identities (`dev:ino` of a live bind or
`sha256:` of a snapshot), broker request counts per upstream (`broker_counts`, never bodies or secrets), the broker's
evidence for a launch with secrets (`broker_evidence`, below), start and end times, the exit code or reason,
`domain_empty`, `enforcement_released`, and a `kernel_verified` flag. `kernel_verified` is never a
host-asserted value: protocol v1 carries no verification report, so the service rejects a receipt or heartbeat that
claims `true`, and every launch and target record stores `false` (a database check constraint on launches). Setting
it requires a future verification report signed by an authority key distinct from every host key and validated by the
service; until that exists it is always `false`.

`broker_evidence` (`agentgate.broker-evidence.v1`) is the host's summary of the launch broker's stats document after
it checked the launch, target, configuration digest and endpoint: `config_sha256`, `listen`, `state`, `stop_reason`,
`complete`, `started_at`, `updated_at`, `hardening` (uid, gid, not dumpable, core limit zero, no new privileges, no
capabilities, memory locked), `connections` and `requests` counts, `denied` counts by fixed reason, per-route
`{upstream, requests, forwarded, status, errors, bytes_in, bytes_out, redactions}`, and how many denials were recorded.
It holds no path, header, query, body, client address or value. When the stats are missing or do not verify, only
`version` and `missing` (`broker_stats`, `broker_stats_invalid`, `broker_evidence_unreadable`) are set. The receipt
check requires `broker_counts` to equal the evidence's forwarded counts per upstream. On ingest the service refuses
broker evidence for a launch without secrets, counts or routes for an upstream outside the plan, and a `listen` other
than the plan's endpoint (`invalid_receipt`). A broker container or network that may remain is reported as
`broker_cleanup_errors` in the network evidence.

## REST API (`/api/v1`)

All endpoints require a browser session (with CSRF for writes) or an API token, and the role listed. Responses reuse
the service's error envelope (`{"error":{"code","message"},"request_id"}`). Every write and every denial is audited.

| Endpoint | Method | Role | Purpose |
| --- | --- | --- | --- |
| `/targets` | GET, POST | viewer, admin | list targets; create a target and its one-time enrollment token |
| `/targets/{id}` | GET, PATCH, DELETE | viewer, admin | status, capabilities, key fingerprint, encryption key, mount roots and the host's own (`host_mount_roots`, `mount_roots_not_on_host`), the host's clock skew; rename; retire (refused while a launch is live; with secrets on the host it queues one `secret-delete` per secret and the target is `retiring` until the host confirms them, then retired; `{"force": true}` finishes without the host and records those secrets `removal: unconfirmed`) |
| `/targets/{id}/enrollment` | POST | admin | a new one-time token (reinstall, job key rotation) |
| `/targets/{id}/approve-key` | POST | admin | approve the presented host key fingerprint; activates the target |
| `/targets/{id}/mount-roots` | POST | admin | replace the host folders launches on the target may mount or snapshot (`mount_roots`, at most 16; empty refuses every mount) |
| `/profiles` | GET, POST | viewer, editor | list; create from a preset, a document or the full example |
| `/profiles/{id}` | GET, PATCH | viewer, admin | detail; change `require_approval` (admin only): `false` approves exactly one reviewed `version` and `digest`, `true` clears it |
| `/profiles/{id}/versions` | GET, POST | viewer, editor | immutable versions; a new version names the latest as its parent |
| `/profiles/{id}/versions/{n}` | GET | viewer | one version with its document and digest |
| `/profiles/{id}/versions/{n}/grants` | POST | editor | 1 to 16 typed edits (read, write, exec, deny, allow-web, deny-web, dns, signal, anon-exec, mount, unmount, device, preset, revoke) on the latest version, producing a new version or a no-op; `"dry_run": true` answers the same (document, `from_digest`, `digest`, `changes`) and stores nothing |
| `/access-presets` | GET | viewer | presets, edit actions and revoke kinds |
| `/launches` | GET, POST | viewer, launcher | list newest first with filters `state` (a state, `active` or `ended`), `target`, `name` (substring), `requester`, `mine`, pages of `limit` (1 to 200, default 100) and an opaque `cursor` (`next_cursor` of the previous page, bound to the same filters); create from a spec (validates, returns the plan) |
| `/launches/summary` | GET | viewer | counts by state of every launch, and up to 8 launches waiting for this actor's decision and 8 expiring within 30 minutes, with their totals |
| `/launch-plans` | POST | launcher | the plan for a spec, creating nothing (`agentgate launch --dry-run`) |
| `/launches/{id}` | GET | viewer | state, spec, plan, policy, receipt, jobs |
| `/launches/{id}/approve`, `/reject` | POST | approver | a different subject (account) than the requester |
| `/launches/{id}/stop` | POST | launcher | request a stop; idempotent |
| `/launches/{id}/events` | GET | viewer | ordered events (`?after=`); `Accept: text/event-stream` streams them, resuming from `Last-Event-ID` |
| `/launches/{id}/logs` | GET | viewer | bounded agent output (`?after=`); `Accept: text/event-stream` streams it: `event: log` per line (`id` = line sequence, data = the line as JSON), resume with `Last-Event-ID`, keepalives every 15 s, `event: end` once the launch is terminal; at most 64 lines are read ahead of a client, and a write blocked for 20 s ends the stream |
| `/targets/{id}/seal-key` | GET | viewer | the host's signed seal key record, verbatim, with the host public key and fingerprint |
| `/targets/{id}/secrets` | GET | launcher | what a launch spec needs (`?profile=`): each pending or stored secret's name, state, upstream hosts, rule count and wildcard flag, and whether this human and profile may use it; no fingerprint, envelope, rule path or scope list |
| `/secrets` | GET, POST | admin | metadata only; POST carries a `secretseal` envelope sealed to the target's published seal key, and the broker settings |
| `/secrets/{id}` | DELETE | admin | queue removal from the host (refused while a live launch uses it) |
| `/secrets/{id}/receipt` | GET | admin | the host's receipt for the relayed envelope, for the sealing client to verify |
| `/identity-links` | GET, POST, DELETE | admin | the subjects linked as one person; link 2 to 8 subjects (`{subjects, reason}`; groups merge); unlink one (`{subject, reason}`; never a group holding your own subject) |
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
`policy:write` (editor), and the admin-only `targets:admin`, `secrets:admin`, `profiles:admin`, `identities:admin`. No
actor decides their own launch or one requested by a subject linked to it. A policy edit never changes a running launch.

API tokens (`agt_` and 43 base64url characters) are for the CLI: `Authorization: Bearer <token>`. A token belongs to
one human, carries a subset of their roles (an administrator may grant any role), expires in 1 hour to 90 days, is
stored only as its SHA-256, is shown once, and is revocable. Each use takes the intersection of the token's roles and
the holder's current roles, and a restore from backup revokes every token. Resetting a local account's password or
disabling it revokes every API token of that account along with its sessions (each audited as `apitoken.revoked`
with cause `password_reset` or `account_disabled`), so a token minted from a stolen session dies with the reset and
enabling the account again does not bring an old token back. Tokens reach only the provisioning
endpoints (identity links included) and read-only overview and audit endpoints; they cannot manage users or mint
tokens. Machine service
identities keep the existing `Alloyium-Proof` scheme.

## CLI (`agentgate`)

The full reference, quickstart and exit codes are in [CLI.md](CLI.md). The surface, with the API it calls:

```
agentgate up [--target local] [--service-url URL] [--compose-file F] [--approve]   bring this machine online
             [--broker-image REF [--broker-egress-network NET] [--broker-uid N] [--broker-gid N] [--broker-pool CIDR]]
             [--secret-root DIR] [--mount-root PATH]...
agentgate login URL [--token-stdin] | logout [--revoke] | whoami | context ls|use|rm   API token in a 0600 config
agentgate target ls | add NAME | enroll NAME | status NAME | approve-key NAME --host-key-id ID
agentgate target pin NAME --host-key-id ID | rename NAME NEW | retire NAME
agentgate profile ls | show NAME | new NAME [--preset P | --file DOC] | versions NAME | approval NAME required|auto --version N
agentgate preset ls
agentgate grant PROFILE read|write|exec|deny PATH | web [allow|deny] PROTO... | dns IP... | signal SIG...
                        | anon-exec | mount NAME [--mode read-only|read-write] | unmount NAME | device DEVICE | preset NAME
                        | revoke KIND VALUE...        [--dry-run] [--upgrade]
agentgate launch -f spec.json | --name N --target T --mode oneshot|session --lifetime D --profile P[@V]
                 --image I --mount SRC:NAME[:ro|snapshot|rw] --secret REF[:ENV] --env K=V -- CMD...
                 [--dry-run] [--wait [--until running|done]]
agentgate ps [--state S] [--target T] [--name N] [--mine] [--limit N] [--cursor C | --all] | show ID | logs ID [-f]
agentgate events ID [-f] | stop ID [--wait] | approve ID | reject ID
agentgate audit [--launch ID] [--since T] | audit catalog
agentgate secret set NAME --upstream HOST --allow-profile P (--rule M:PATH[:prefix]... | --allow-any-path) [--scheme S] [--wait] | ls | rm NAME
agentgate token create [--save] | ls | revoke ID      (password sign-in: a token cannot manage tokens)
agentgate identity ls | link SUBJECT SUBJECT... | unlink SUBJECT                       (administrators)
agentgate schema launch-spec | completion bash|zsh|fish | version
```

- Every command takes `--json` (the API's field names), `--quiet` and `--no-color`, and returns the exit codes in
  [CLI.md](CLI.md#exit-codes): 0 ok, 2 usage, 3 auth, 4 forbidden, 5 not found, 6 conflict, 7 rejected, 8 approval
  pending, 9 timeout, 10 server, 11 network, 12 launch ended, 13 trust, 130 interrupted.
- `launch --dry-run` posts to `/launch-plans` and prints the resolved plan: digests, effective permissions, mounts,
  brokered secrets by name, lifetime and expiry, and every approval reason. `launch --wait` follows the event stream
  (resuming with `Last-Event-ID`) through `approval_pending` to `running`; interrupting it never stops the launch.
- `grant` sends one typed edit to `/profiles/{id}/versions/{n}/grants` and prints the diff of the version the service
  stored. `grant --dry-run` sends the same edit with `"dry_run": true`; the service answers with the resulting document,
  digests and change list and stores nothing. The CLI holds no grant engine.
- `secret set` reads the value from a hidden prompt or stdin, never argv or the environment. It requires a client-side
  pin of the target's approved `host_key_id` (`~/.config/agentgate/known-targets.json`, written by `target approve-key`,
  `target pin` or `up`), fetches `GET /targets/{id}/seal-key` (see
  [BROKER.md](BROKER.md#integration-status)), checks `hostproto.KeyID(host_public_key)` against the pin and the
  record's signature with `secretseal.VerifyKeyRecord`, and uploads `Envelope.Encode()` as `ciphertext`. Until the
  service serves the seal key it refuses; it never seals to an unsigned key. Broker rules (`--rule`,
  `--allow-any-path`), `--scheme Bearer|Basic` and `--extra-header` are sent when the service's OpenAPI `SecretInput`
  has them (rules are then required: deny by default); `--wait` verifies the host's receipt from
  `GET /secrets/{id}/receipt` with `Sealed.VerifyReceipt`.
- `up` delegates every host-side action to `docker compose` (`control job-key`, `init`, `first-admin` with the
  password on stdin, `up -d`) and `agentgate-hostd` (`status`, `install --token-file` with the broker settings and
  mount roots given, `mount-roots`, `provision`) through argument vectors; each step checks the current state first,
  and the steps that need root refuse without it. It reports when `brokered-secrets` is not available and why. Under
  `sudo` the CLI's configuration is root's own (`/root/.config/agentgate` from the account database), never where `HOME`
  points ([CLI.md](CLI.md#1-first-time-setup-bring-this-machine-online)).

## Credentials

A secret value is entered once, on the operator's client, and reaches the target host through a path the service
relays but cannot read. The host keeps the value in a root-owned 0600 file outside every sandbox mount. A per-launch
broker on the host holds it, listens on one exact private endpoint, forwards only allowed requests to an exact HTTPS
origin allowlist, adds the credential to the requests it forwards, and records counts. The sandbox sees only the
broker address. Design, threat model, configuration and limits: [BROKER.md](BROKER.md).

### Sealed relay (`secret-put`)

- **Host seal key.** The host publishes an X25519 seal key in a record signed by its enrolled Ed25519 key
  (`secretseal.SignedKeyRecord`: target id, key id, suite, public key, validity of at most 90 days, and the host key
  fingerprint `SHA256:...`). The service stores and relays the record and never re-signs it. Because the service could
  otherwise substitute its own key and read every secret, the client verifies the signature against a host key
  fingerprint it obtained out of band (the value `agentgate-hostd` prints at enrollment) and pinned client side
  (`~/.config/agentgate/known-targets.json`, mode 0600). Trust on first use happens only when the operator asks for it
  and never replaces a different pin.
- **Injection policy.** Before it reads the value, the client shows the operator the secret's injection policy (its
  upstreams with ports, header and scheme, rules, extra headers and forwarded request headers) and its
  `policy_digest`, the SHA-256 of the canonical encoding in [BROKER.md](BROKER.md#sealed-relay-for-secret-put-internalsecretseal).
  The service refuses `POST /secrets` settings whose digest is not the envelope's (`422 policy_mismatch`), stores the
  digest with the secret (immutable, like its settings), shows it in every plan, and refuses to plan or queue a launch
  whose stored settings, sealed digest and receipt disagree (`secret_policy_mismatch`). The client refuses an answer
  whose settings make another digest. To change a policy, store the secret again with a new envelope.
- **Envelope.** The client seals with RFC 9180 HPKE (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, base
  mode). The associated data binds the secret name (the `ref`), the target id, a version (the sealing time in Unix
  milliseconds), a fresh 128-bit nonce and the policy digest (format `agentgate.secretseal.v2`). The envelope holds only
  ciphertext and that public context. The service keeps nothing it can decrypt: it relays the envelope and the policy
  settings in the `secret-put` job, then keeps only its SHA-256 and the host's fingerprint.
- **Host acceptance.** The host refuses relayed settings whose digest is not the envelope's (`policy_mismatch`; the
  AEAD would not open under another digest either) and stores the policy with the value. At launch it refuses a secret
  whose job settings or digest differ from that stored policy, and builds the broker from the stored policy, so neither
  the service nor its database decides where a credential goes. It refuses a different target or key, a version not newer than the stored one (replay or
  rollback of a rotated secret), an envelope older than 24 hours or more than 5 minutes ahead, and (with `Store.Validate` set to
  `broker.ValidSecret`) a value the broker cannot inject (it needs 8 to 8192 bytes of visible ASCII). It writes the value atomically to its 0600 file.
- **Receipt.** The job result carries `{target_id, name, version, key_id, nonce, policy_digest, fingerprint, tag}`; the
  service refuses a receipt whose policy digest is not the envelope's (`receipt_mismatch`). The fingerprint
  is a keyed hash (HMAC-SHA256 under a random key that never leaves the host, truncated to 128 bits), so a short or
  guessable secret cannot be recovered by guessing, and an unchanged value keeps its fingerprint. The tag is keyed by
  the HPKE exporter secret that only the sealing client shares with the host; the client verifies it, so a service
  that replaced the ciphertext with its own (for example its own account key) is detected.

### Brokered use in a launch

- `secrets[].expose.env` receives the route's base URL, `http://ADDRESS:PORT/REF` (for example
  `ANTHROPIC_BASE_URL=http://172.30.7.2:8443/anthropic`), never a value. A placeholder key variable for SDKs that
  refuse to start without one (`expose.placeholder_env`) is proposed in BROKER.md but not implemented; the spec
  validator refuses it.
- Each route binds exactly one secret to exactly one origin (`https://host:port`) and a set of method and path rules.
  A secret with several upstreams becomes one route per origin (`REF`, `REF-2`, ...); `expose.env` names the first.
  Secret metadata carries `scheme` (`""`, `Bearer`, `Basic`; `""` with an `authorization` header is stored as
  `Bearer`), `username` for Basic, `rules` (1 to 64 of `{methods, path, match}`) and up to 8 `extra_headers`, all
  checked by the broker's own validator when the secret is created. **Deny by default:** a secret without rules can be
  stored, but no launch can use it (`secret_rules_missing`). Every method on every path of the upstreams needs the
  explicit wildcard `rules: [{"methods":["*"],"path":"/"}]`, which is stored expanded with `wildcard_rules: true` and
  flagged in every plan that uses it.
- The broker routes by path only. A client `Host` must equal the broker's own address and never selects a destination.
  The broker resolves each upstream itself, refuses an answer containing any loopback, private, link-local (including
  `169.254.169.254`), CGNAT, multicast, documentation or reserved address (or the broker network, or the host's own
  addresses), connects only to a validated address with TLS verification and SNI equal to the configured name, and
  re-resolves and re-checks for every new connection. A private-by-design upstream lists its exact private addresses
  and nothing else is accepted for it. Redirects are returned to the agent and never followed, so a redirect to a
  private range never carries the credential.
- Request and response sizes, header sizes and counts, the request rate, concurrency and every timeout are capped; the
  broker exits at the launch deadline. It never logs headers, bodies, queries or secrets.
- **Network layout.** The service assigns each launch with secrets its own `/29` inside `172.30.0.0/16` when the
  launch is created: `.1` the Docker gateway, `.2` the broker on port 8443, `.3` the target. It records the block in
  `broker_allocations` (schema 10), so no two launches on one target hold the same block: a launch first takes the
  block its id hashes to, else the next free one in order (wrapping), and is refused with `409 broker_pool_exhausted`
  when all 8191 blocks of the target are held. A block is released when the launch ends with the host's receipt (the
  host tears its broker down before it reports), when it ends without having reached its host (rejected, cancelled,
  expired before collection, refused by the host before it started), when a late receipt arrives, or when the target
  is retired; a launch whose host went silent (`lost_host`) keeps its block until then. A dry run shows the block its
  example id prefers and holds nothing. The effective policy carries
  `broker: {address: .2, protocol: "tcp", port: 8443}` (`pocpolicy`, mutually exclusive with `taskboard`), so the policy
  digest and the approval cover the endpoint, and the guard allows that one exact endpoint and nothing else private:
  not the gateway, not the other addresses of the `/29`, not another port. The target keeps its own network and joins
  the internal broker network only after the guard is attached; the broker alone has an egress network. The host
  refuses an endpoint outside its pool (`--broker-pool`) or a network that overlaps an existing one. Today the guard
  holds one exact private endpoint, so a launch with secrets has no taskboard TCP endpoint.
- **Evidence.** The broker writes a bounded stats document (`agentgate.broker-stats.v1`): per route the upstream,
  request, forwarded, status-class and error counts, bytes in and out, masked echoes; denial counts by fixed reason;
  the first denials as method, sanitized host and a two-segment path prefix; the configuration digest and the process
  hardening achieved. The host derives `broker_counts` (forwarded requests per upstream) and `broker_evidence` (the
  same without denial records) from it. Neither holds a body, header value, query string or secret.

### Flow, end to end

1. **Seal key.** `agentgate-hostd` signs its X25519 enrollment key into a seal key record with its enrolled Ed25519 key
   (30 days, re-signed a week before expiry) and sends it in every heartbeat. The service verifies and stores it and
   serves it at `GET /targets/{id}/seal-key`.
2. **Seal.** The client checks the record against the host key it pinned, seals the value (`secretseal.SealForTarget`)
   and posts `{name, target, upstreams, header, scheme, username, rules, extra_headers, ciphertext, allowed_profiles,
   allowed_launchers, reason}` to `/secrets`. The service checks the envelope's target, name and key id and the broker
   settings, stores metadata, the envelope's SHA-256 and public context (format, key id, version, nonce), and queues
   `secret-put`.
3. **Store.** The host opens the envelope into `SECRET_ROOT/<target>/<name>` (default `/var/lib/agentgate/secrets`,
   root, 0700 directories, 0600 files; refusing replay, rollback, stale envelopes and values the broker cannot
   inject), binds the name to the secret id, and returns its receipt. The service checks that the receipt answers the
   relayed envelope, records `value_fingerprint`, sets the secret `stored`, and serves the receipt at
   `GET /secrets/{id}/receipt` for the client to verify.
4. **Plan and approve.** A launch referencing the secret is planned with its rules, endpoint and base URLs, and waits
   for approval by a different human.
5. **Launch.** The host checks the signed endpoint against its pool and the secret's binding, version and fingerprint,
   writes the broker configuration (root-owned 0600 in `STATE/brokers/<launch>/`, no value in it), starts the broker
   container with exactly that launch's store files mounted read-only, and waits for its stats to say `running` for
   this exact configuration. Only then does the launch runtime start the target, attach the guard, join the target to
   the broker network and run the agent with the base URLs in its environment. Any broker failure ends the launch
   before the agent starts and removes what was created.
6. **Stop.** After the agent ends, the host stops the broker (SIGTERM, 5 seconds), verifies its final stats, removes
   the container, the network and the configuration, proves they are gone, and returns the receipt with
   `broker_counts` and `broker_evidence`. A restarted host agent does the same for a broker a crash left behind.
7. **Delete.** `DELETE /secrets/{id}` (refused while a launch uses it) queues `secret-delete`; the host overwrites and
   removes the value and keeps a tombstone of its version, so the old envelope cannot set it again. Retiring or
   re-enrolling a target queues the same removal for each of its secrets (audited `secret.deletion.requested`); a
   retiring target polls only for those jobs, a refused removal is queued again up to 5 times, and the host's last
   confirmation (`secret.deleted`) retires the target and revokes its key.

**Integration status.** Connected and tested in process (real service, host agent, host protocol and broker; a TLS
fake upstream; Docker and the guard faked). Not exercised: Docker, the BPF LSM guard with a broker endpoint, real DNS
and upstreams, systemd. Not implemented: `expose.placeholder_env`, a taskboard endpoint in a launch with secrets (needs
a BPF change), brokers in the one-command appliance. The earlier `hostproto.SealSecret` format is removed. Details in
[BROKER.md](BROKER.md#integration-status).

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

The service, its database, its job key and the administrator are trusted for authorization: who may launch what,
which launches are approved and queued, and the audit log. They are **not** trusted with secret values or with where
and how a stored credential is used. A compromised service, or anyone who can write its database or sign jobs with
its job key, cannot read a stored credential (it relays only sealed envelopes) and cannot redirect it: the injection
policy (upstreams, header, scheme, extra and forwarded headers, rules) is sealed with the value by the operator's
client, and the host stores and uses the value only under that policy (see [BROKER.md](BROKER.md#sealed-relay-for-secret-put-internalsecretseal)).
Such a party can still:

- choose which launches to queue within the approval rules it enforces (it decides who is a launcher or approver,
  and it can queue a launch nobody approved), and so have the host run any profile with a credential under its sealed
  policy;
- deny service: drop jobs, secret-puts or results, or refuse every request;
- show a client a plan whose readable broker settings differ from the sealed policy. The CLI (`agentgate approve`) and
  the web UI recompute the digest from the settings shown and refuse to approve on a mismatch; a client that does
  not compare them can be misled about what it approves, though the host still enforces only the sealed policy.

**`agentgate-hostd` is fully trusted for its target**: it holds the host key, the secret values for that target and Docker, BPF and cgroup control. A
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



## Deploy

Build the release set on a machine with Go (static binaries, `-trimpath`):

```sh
make agentgate        # build/agentgate, agentgate-hostd, agentgate-broker, community,
                      # agentgate-broker@.service and build/SHA256SUMS
```

`make all` builds the control service as `build/community` (it was `build/agentgate`; that name is now the CLI).

Install it on each machine that runs the CLI or a host agent (`deploy/install.sh`, as root):

```sh
sudo deploy/install.sh --from build [--sha256sums <SHA-256 of SHA256SUMS from the release page>]
```

It checks the prerequisites (Linux, coreutils, `useradd`; it warns when Docker, Python 3, systemd, `setpriv` or a
BPF LSM kernel are missing, because a host that runs launches needs them), copies the release into a private
directory, verifies every file against `SHA256SUMS` there (and `SHA256SUMS` itself against `--sha256sums`), and
only then installs `/usr/local/bin/agentgate`, `/usr/local/sbin/agentgate-hostd`,
`/usr/local/libexec/agentgate/{agentgate-broker,community}` and the sample `agentgate-broker@.service`, creates the
system user `agentgate-broker` (uid and gid 10002 by default, the host agent's `--broker-uid`/`--broker-gid`), and
the root-owned directories `/etc/agentgate` (0755), `/etc/agentgate/broker` (0700), `/var/lib/agentgate` (0755),
`/var/lib/agentgate/secrets` (0700) and `/var/lib/agentgate/broker` (0711). It refuses, before changing anything, a
checksum mismatch, an unlisted or missing file, a symlink, a destination below a group- or world-writable or
non-root-owned directory, a user or id that already belongs to someone else, and a non-root run. A second run
reports every file unchanged. It does not enroll the host: `agentgate up` (or `agentgate-hostd install`) does that
and writes the `agentgate-hostd` unit. `--root DIR` stages the same tree below `DIR` without users or systemctl, for
packaging; the tests use it.

Run the control service with Docker Compose (`compose.yaml`: the service read-only, without capabilities, as user
10001, on an internal network; Caddy terminates TLS on `127.0.0.1:9443` with its local CA):

```sh
export AGENTGATE_IMAGE=registry.example/agentgate@sha256:<digest>     # the CI-built image
sudo -E agentgate up --compose-file compose.yaml --admin-user ada --target local \
  --broker-image registry.example/agentgate-broker@sha256:<digest> --mount-root /srv/repos
```

`-E` passes `AGENTGATE_IMAGE` through; under `sudo` the CLI still keeps its token, CA and pins in root's own
`/root/.config/agentgate` (from the account database), never in the invoking user's `HOME`, so it creates nothing
root-owned in that user's home ([CLI.md](CLI.md#1-first-time-setup-bring-this-machine-online)).

- To build the image from this checkout instead: `AGENTGATE_IMAGE=agentgate-local:dev docker compose -f
  compose.yaml -f deploy/compose.build.yaml build control`, then the same `agentgate up`.
- Hosts on other machines need the TLS front published: `AGENTGATE_PUBLIC_HOST=agentgate.example.internal docker
  compose -f compose.yaml -f deploy/compose.public.yaml up -d` (Compose 2.24.4 or later) with `public_url` set to
  `https://agentgate.example.internal:9443` in `settings.json`. It publishes only HTTPS on 9443
  (`deploy/Caddyfile.public`, still `tls internal`; give hosts the CA with `--ca-file`, or use your own
  certificate).

- **Client addresses behind the TLS front (deployment requirement).** The service limits requests per client address
  (1200 a minute for the API, 120 sign-in requests and 10 password attempts a minute) and samples the audit rows of
  anonymous denials per client address (at most 20 a minute; one `audit.denials.suppressed` row counts the rest).
  Behind a reverse proxy every request has the proxy's address, so the service must be told which peers are proxies:
  `trusted_proxies` in `settings.json` lists their CIDR networks (default empty: no proxy is trusted and every
  request is keyed by its TCP peer). The shipped `compose.yaml` pins the internal network to `10.231.207.0/28` and the
  shipped `settings.json` trusts exactly that network; `Caddyfile` and `deploy/Caddyfile.public` replace any
  client-sent `X-Forwarded-For` with the real client address (`header_up X-Forwarded-For {remote_host}`). A request
  from a trusted proxy is keyed by the rightmost `X-Forwarded-For` entry that is not itself a trusted proxy (the
  entries to its left are whatever the client sent); one without a well-formed `X-Forwarded-For` (at most 16 IP
  addresses) is refused with `400 invalid_forwarded_for`. IPv6 clients are keyed by their `/64`. Change the subnet in
  `compose.yaml` and `settings.json` together if `10.231.207.0/28` is taken on the machine; with another proxy, list
  its addresses. Do not list a network that untrusted clients can reach the service from directly.
- **Host requests are not limited by client address.** `POST /api/v1/hostd/{poll,resync,jobs/{id}/events}` first
  verifies the request's signature against its target's enrolled key (one row read and one Ed25519 verification on a
  bounded body), and only then is the request limited per host (1200 a minute); only failed verifications count
  against the client address (120 a minute, then `429` without an audit row). A flood of unauthenticated requests,
  from anywhere, therefore cannot refuse an honest host's polls and fail its running launches `lost_host`.

Then check everything from any machine with the CLI: `agentgate doctor --target NAME` reports the service, this
machine's clock skew, token, target state, host key approval and local pin, heartbeat age, the host's clock skew at its
last heartbeat, `bpf-lsm`, `brokered-secrets` (and why it is missing) and whether the host's own mount roots cover the
service's, each with the exact fix.

Not exercised here: `install.sh` as root on a real system (user creation, `systemctl daemon-reload`), both compose
overrides (`docker compose config` included) and the image build, because the build sandbox has no Docker, no
systemd and no BPF LSM kernel. `shellcheck` was not available.

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

Preview an edit without storing anything (`"dry_run": true`; audited as `profile.grant.previewed`), then allow a
device (one of `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/tty`):

```sh
curl -sS -X POST "$U/api/v1/profiles/python-dev/versions/2/grants" -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' -d '{"edits":[{"action":"device","values":["/dev/tty"]}],
  "reason":"Interactive tools","dry_run":true}'
# -> {"dry_run":true,"changed":true,"from_version":2,"from_digest":"...","digest":"...","document":{...},
#     "changes":[{"area":"Files","field":"devices","change":"added","after":"/dev/tty"}],
#     "messages":[...],"notices":[...]}
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

Which secrets a launch on a target may use (launcher; names and scope only, never fingerprints or envelopes):

```sh
curl -sS "$U/api/v1/targets/local/secrets?profile=python-dev" -H "Authorization: Bearer $T"
# -> {"target_id":"...","target":"local","profile":"python-dev","items":[{"name":"model-api","state":"stored",
#     "upstreams":["api.model.example"],"rule_count":1,"wildcard_rules":false,"launcher_allowed":true,
#     "profile_allowed":true,"usable":true}]}
```

List launches with the service's filters and cursor paging, and the overview counts:

```sh
curl -sS "$U/api/v1/launches?state=active&target=local&mine=true&limit=50" -H "Authorization: Bearer $T"
# -> {"items":[...],"limit":50,"next_cursor":"<opaque>"}     (next_cursor only when a full page was returned)
curl -sS "$U/api/v1/launches?state=active&target=local&mine=true&limit=50&cursor=<opaque>" -H "Authorization: Bearer $T"
curl -sS "$U/api/v1/launches/summary" -H "Authorization: Bearer $T"
# -> {"total":..,"active":..,"counts":{"running":..,...},"awaiting_your_decision":{"count":..,"items":[...]},
#     "expiring_soon":{"count":..,"window_seconds":1800,"items":[...]}}
```

Follow a launch's output as Server-Sent Events; after a disconnect, resume with the last `id` seen:

```sh
curl -sS -N "$U/api/v1/launches/<id>/logs" -H "Authorization: Bearer $T" -H 'Accept: text/event-stream'
# retry: 2000 / event: ready / data: {"after":0}
# id: 1 / event: log / data: {"seq":1,"time":"...","stream":"stdout","text":"..."}
# : keepalive                                        (every 15 s while nothing happens)
# event: end / data: {"state":"stopped","last_seq":42,"truncated":false}
curl -sS -N "$U/api/v1/launches/<id>/logs" -H "Authorization: Bearer $T" -H 'Accept: text/event-stream' \
  -H 'Last-Event-ID: 42'
```

Retire a target (admin). With secrets stored, it moves to `retiring` and the host deletes each value when it polls;
the last confirmation retires it. `"force": true` retires a host that is gone and marks its secrets
`removal: unconfirmed`:

```sh
curl -sS -X DELETE "$U/api/v1/targets/old-host" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"reason":"Decommissioned"}'
curl -sS -X DELETE "$U/api/v1/targets/old-host" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"reason":"The host is gone","force":true}'
```

Store a secret (admin). The client fetches the seal key, verifies it against the host key it pinned and seals the
value with `secretseal.SealForTarget(known, false, &record, hostPublicKey, targetID, name, policyDigest, value, now)`,
where `policyDigest` is `hostproto.NewSecretPolicy(...).Digest()` of exactly the settings it then posts; `agentgate
secret set` does all of this. The service never sees the value and cannot change the settings:

```sh
curl -sS "$U/api/v1/targets/local/seal-key" -H "Authorization: Bearer $T"
# -> {"target_id":"...","host_key_id":"ed25519:...","host_public_key":"...","host_key_fingerprint":"SHA256:...",
#     "seal_key_id":"...","not_after":"...","record":{...}}
curl -sS -X POST "$U/api/v1/secrets" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"name":"model-api","target":"local","upstreams":["api.model.example"],"header":"x-api-key",
  "rules":[{"methods":["POST"],"path":"/v1/messages","match":"exact"}],
  "ciphertext":"<Envelope.Encode()>","allowed_profiles":["python-dev"],"allowed_launchers":["local:lin"],
  "reason":"Model access for the coding agent"}'
# Basic authentication with the explicit wildcard (every method and path; plans warn and need approval):
curl -sS -X POST "$U/api/v1/secrets" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"name":"docs-api","target":"local","upstreams":["api.docs.example"],"header":"Authorization",
  "scheme":"Basic","username":"agent","rules":[{"methods":["*"],"path":"/"}],
  "extra_headers":{"docs-version":"2"},"ciphertext":"<Envelope.Encode()>","allowed_profiles":["python-dev"],
  "allowed_launchers":["local:lin"],"reason":"Docs access"}'
# Refusals: 409 seal_key_changed (reseal to the current key), 409 seal_key_unavailable, 422 invalid_ciphertext,
# 422 invalid_secret (the broker would refuse the settings), 422 policy_mismatch (the settings are not the policy
# sealed in the envelope); a plan with a secret stored without rules: 422 secret_rules_missing; with a secret whose
# stored settings, sealed digest and receipt disagree: 422 secret_policy_mismatch.
curl -sS "$U/api/v1/secrets/<id>/receipt" -H "Authorization: Bearer $T"   # verify with Sealed.VerifyReceipt
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

Nothing in this table ran on a BPF LSM kernel, with a Docker daemon, under systemd, on a real host or against a real
upstream API; every launch reports `kernel_verified: false`. "Tested" means automated tests in the build sandbox. The
[README](../README.md#status-and-verification) states the same in plain words and lists the first steps on a
disposable BPF-LSM VM.

| Part | Where | Status | Tested with | Not exercised |
| --- | --- | --- | --- | --- |
| This contract | `docs/PROVISIONING.md` | written | the API cookbook matches the routes (OpenAPI test, audit catalog test) | |
| Control plane: store, API, roles, job queue, audit | `internal/control`, `internal/access`, `internal/hostproto`, `cmd/community` | implemented (schema 11): targets (enrollment, key approval, retirement that waits for the host to delete its secrets, mount roots checked when a launch is planned and again when it is queued, the host's own mount roots and clock skew from its heartbeat), profiles and typed grants with a server-side dry run, automatic approval per reviewed profile version, launches (plans, approval by a different person including linked identities, cursor-paged lists, summary, events and logs as SSE), sealed secrets whose injection policy is sealed with the value, a broker network per launch from a per-target table, receipts, API tokens, rate limits keyed by the forwarded client behind trusted proxies | Go tests against the real store and HTTP server, with fake hosts on the real host protocol; every endpoint has negative tests (role, tenant, size, malformed) and an audited action; schema migrations from older versions | a production deployment |
| Web UI | `web/src` | implemented: Overview, Targets (with the host's own mount roots and clock), Access profiles, Launch, Launches, Secrets, API tokens, Linked identities (read only) | node unit tests (`qa/*.node.mjs`); Playwright QA in Chromium against an owned mock whose every answer is checked against answers recorded from the real service (`web/qa/fixtures/api`) | a deployed service |
| CLI | `cmd/agentgate`, `internal/cli`, `docs/CLI.md` | implemented, including `doctor` (this machine's and the host's clock, broker availability and why, mount roots), `up` with the broker settings and mount roots, `identity`, and a configuration that never follows `HOME` under `sudo` | a fake API built from the OpenAPI document; end to end against the real service in process (login, targets, key approval, grants, seal key, secret set with receipt, plans, launches, approval, logs, doctor, identity links); every documented command parses | `up` with real Docker, `sudo` and `agentgate-hostd` (a fake runner only) |
| Host agent | `cmd/agentgate-hostd`, `internal/hostd` | implemented: enroll (prints the host key id and fingerprint), poll, verify and run jobs once, durable outbox, lifetime and lost-service grace, crash reconciliation, sealed secret store enforcing each secret's sealed policy, per-launch broker, secret deletion on retirement, the operator's own mount roots (`mount-roots`, refusing links, `..`, prefix confusion, mounts inside a root and private paths; stopping a launch whose root is removed), a launch's mounts and secrets bound to its signed spec, `status` with the broker and roots | Go tests with fakes, a Docker command recorder, real temporary directory trees and a substituted mount table; the Go and Python launcher-job and mount-roots drift tests | systemd, Docker, a real kernel, a real host's mount table |
| Launch runtime | `poc/ssh-diagnostic` (`launch.py`, `launch_job.py`, `mounts.py`, `restart-target.sh`) | implemented on the guarded-target path; the taskboard bridge is mounted only when a launch asks; host folders checked again against the host's mount roots and the protected trees generated from `hostproto` | Python tests with fake hosts; `restart-target.sh` against a recording Docker stand-in | Docker, the BPF guard on a kernel |
| Credential broker | `cmd/agentgate-broker`, `internal/broker`, `internal/secretseal` | implemented and connected to the policy, service, host agent and launch runtime; see [BROKER.md](BROKER.md#integration-status) | in process end to end with a TLS fake upstream; fuzz targets for paths, rules and headers | the container recipe, systemd, real DNS and upstreams |
| Packaging | `Makefile` (`make agentgate`), `deploy/install.sh`, `compose.yaml`, `deploy/compose.*.yaml` | implemented | `install.sh --root` (checksums, refusals, idempotence); `make agentgate` builds | `install.sh` as root (users, systemctl), Docker Compose, the image build; `shellcheck` was not available |
| Kernel verification on a BPF LSM host | `poc/ssh-diagnostic/verify-kernel.sh`, `verify-probe.sh`, `verify_kernel.py`, `docs/QUALIFICATION.md` | kit written: per-program verifier results and guard A/B behaviour probes | its logic is unit-tested with fakes (`test_verify_kernel.py`), including a guard that silently enforces nothing | a BPF LSM kernel (not possible in the build sandbox) |

Not built: `expose.placeholder_env`, a taskboard endpoint in a launch with secrets (needs a BPF change), brokers in the
one-command appliance, a socket LSM guard and a syscall filter in the POC, `kernel_verified` from a signed verification
report.
