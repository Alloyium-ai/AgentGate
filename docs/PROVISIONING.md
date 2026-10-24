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

Rules every implementation enforces:

- `name` matches `^[a-z0-9][a-z0-9-]{0,39}$`. `mode` is `oneshot` or `session`.
- `oneshot` runs `agent.command` once and ends. `lifetime_seconds` is 1 to 3600. `session` is a long-running agent. It
  allows 60 to 86400. The lifetime is the hard cap. The kernel policy expires at the lifetime, so an expired launch
  denies everything.
- `agent.image` is an immutable digest reference. `agent.env` holds no secrets; a validator rejects names such as
  `*_KEY`, `*_TOKEN`, `*_SECRET`, `*PASSWORD*`. Secrets arrive only through `secrets`.
- `access` references a stored profile version, or embeds one inline document. The effective policy digest is recorded
  on the launch.
- `mounts[].mode` is `read-only` or `snapshot`. A read-write mount is allowed only where the target advertises
  `live-mounts`, and a writable mount can never be executable.
- `secrets[].ref` names a secret on that target. The spec never contains a value.
- `approval` is `auto` only if the actor's role and the profile permit it. Otherwise the launch waits in
  `approval_pending` for a different human.
- The service stores the canonical JSON and its SHA-256. A launch refers to that digest. A stored spec never changes.

## Launch state machine

```
requested -> approval_pending -> approved -> queued -> provisioning -> running -> stopping -> stopped
     \               \                                      \             \-> expired
      \-> rejected    \-> rejected/cancelled                 \-> failed      \-> failed
```

- Terminal states: `stopped`, `expired`, `failed`, `rejected`, `cancelled`. A terminal launch has an evidence receipt
  or an explicit `evidence_missing` reason. A launch is never marked `stopped` unless the host confirms the domain is
  empty and its enforcement is released.
- Every transition is one audit record: actor, from, to, spec digest, policy digest, reason.
- `running` must be backed by a heartbeat from the host. Missing heartbeats for 3 intervals move a launch to `failed`
  with `lost_host`, and queue a `stop` job that the host executes when it returns.

## Host job protocol

The service never connects to a target. `agentgate-hostd` polls.

- **Enrollment:** a one-time token, created by an admin, binds the host's Ed25519 public key to a target record. The
  token expires in 15 minutes and works once.
- **Poll:** `POST /api/v1/hostd/poll` with a signed body (host id, key id, nonce, timestamp, sequence). The reply holds
  zero or more jobs. Replays, stale timestamps and skipped sequences are rejected.
- **Job:** `{id, type, launch_id, spec_digest, policy_digest, deadline, payload}`, signed by the service's job key.
  The host verifies the signature, the digest binding and the deadline before acting.
- **Job types:** `provision`, `apply-profile`, `launch`, `stop`, `collect`, `secret-put`, `snapshot-mount`.
- **Progress:** `POST /api/v1/hostd/jobs/{id}/events` appends ordered, size-bounded events. The final event carries
  the receipt (see below). The host retries uploads until acknowledged and keeps the receipt on disk.
- **Idempotence:** every job id runs at most once. A repeated job returns its recorded result.
- **Fail closed:** an unverifiable, expired or unknown job is dropped and reported. It is never run on a guess.

## Evidence receipt

The host returns, per launch: the effective policy digest, object digests of every BPF program and the guard binary,
the network and host-control evidence blocks that `pilot-network-diagnostic` already writes, mount identities, broker
request counts per upstream (never bodies or secrets), start and end times, the exit code or reason, and a
`kernel_verified` flag. `kernel_verified` is `false` until a verification report for that kernel is attached.

## REST API (`/api/v1`)

All endpoints require a session or API token, CSRF for browser writes, and the role listed. Responses reuse the
service's error envelope. New writes are audited.

| Endpoint | Method | Role | Purpose |
| --- | --- | --- | --- |
| `/targets` | GET, POST | viewer, admin | list targets; create an enrollment token |
| `/targets/{id}` | GET, PATCH, DELETE | viewer, admin | status, capabilities, rename, retire |
| `/profiles` | GET, POST | viewer, editor | list; create a profile |
| `/profiles/{id}/versions` | GET, POST | viewer, editor | immutable versions of a policy document |
| `/profiles/{id}/versions/{n}/grants` | POST | editor | typed edit (read, write, exec, deny, web, dns, signal, mount) producing a new version |
| `/launches` | GET, POST | viewer, launcher | list; create from a spec (validates, returns the plan) |
| `/launches/{id}` | GET | viewer | state, spec, plan, receipt |
| `/launches/{id}/approve`, `/reject` | POST | approver | a different human than the requester |
| `/launches/{id}/stop` | POST | launcher | request a stop; idempotent |
| `/launches/{id}/events` | GET | viewer | state changes; supports Server-Sent Events |
| `/launches/{id}/logs` | GET | viewer | bounded agent output |
| `/secrets` | GET, POST, DELETE | admin | metadata only; a value goes straight to the target host |
| `/hostd/*` | POST | host key | enrollment, poll, progress |
| `/launch-spec-schema` | GET | any | JSON Schema for the launch spec |

Roles extend the existing set: `viewer`, `editor` (profiles), `launcher` (create and stop launches), `approver`,
`admin`. No actor approves their own launch. A policy edit never changes a running launch.

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
   cleaned-up target.
6. Lifetimes are enforced in the kernel policy and by the host, not by the agent.

## Parts and status

| Part | Owner area | Status |
| --- | --- | --- |
| This contract | `docs/PROVISIONING.md` | written |
| Control plane: store, API, roles, job queue, audit | `internal/control`, `cmd/community` | not started |
| Host agent and long-running launch runtime | `cmd/agentgate-hostd`, `internal/hostd`, `poc/ssh-diagnostic` | not started |
| Credential broker | `cmd/agentgate-broker`, `internal/broker` | not started |
| CLI | `cmd/agentgate` | not started |
| UI pages | `web/src` | not started |
| Kernel verification on a BPF LSM host | `docs/QUALIFICATION.md` | not possible in the build sandbox |
