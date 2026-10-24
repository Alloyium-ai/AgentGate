# agentgate: the command-line client

`agentgate` is the one command-line client of the AgentGate control plane. It provisions the eBPF-enforced agent
sandbox, defines agent access, and launches agents into it with the access and permissions given at launch, as one-shot
commands or long-running sessions. It is a thin client of the REST API in [PROVISIONING.md](PROVISIONING.md): every
command calls the same `/api/v1` endpoints as the UI, the service decides everything, and the CLI holds no policy logic
of its own. Anything the CLI does, the UI can do, and the reverse.

Kernel enforcement has not been verified on a BPF LSM kernel. Every plan and launch the CLI prints says
`kernel_verified: false` until a verification report says otherwise.

Build it from the source tree (standard library plus modules already in `go.mod`):

```sh
go build -trimpath -ldflags "-X alloyium.local/kernel-poc/internal/cli.version=$(cat VERSION)" -o agentgate ./cmd/agentgate
```

The image's `/opt/agentgate/agentgate` is the service (`cmd/community`), not this client.

## Quickstart

### 1. First-time setup: bring this machine online

On the machine that will run the service and be the first target, with Docker and the deployment files of the
AgentGate image (`compose.yaml`, `settings.json`, `Caddyfile`), as root:

```sh
export AGENTGATE_IMAGE=registry.example/agentgate@sha256:<digest of the CI-built image>
sudo -E agentgate up --compose-file /opt/agentgate/deployment/compose.yaml --admin-user ada --target local
```

`up` runs these steps, each of which reads the current state first and only does what is missing:

| Step | It checks | It does when needed | Needs root |
| --- | --- | --- | --- |
| 1 service | `GET /healthz` at the service URL (default `https://localhost:9443`) | `docker compose run control job-key` to see if the state exists, `control init`, `control first-admin` (password on stdin), `docker compose up -d`, then copies the local TLS front's CA to `~/.config/agentgate/ca-CONTEXT.pem` | no (Docker access) |
| 2 administrator credentials | the saved context's token is accepted and has `admin` | password sign-in, mints an `admin` API token (default 7 days), saves it as the context | no |
| 3 target | `GET /targets/NAME` | creates the target or issues a fresh one-time enrollment token, kept only in memory | no |
| 4 host agent | `agentgate-hostd status` | writes the token to a mode 0600 file in a private temporary directory, runs `agentgate-hostd install --service-url URL --token-file F [--ca-file CA]`, deletes the file | yes |
| 5 host key approval | the target state and the fingerprint this machine's agent reported | with `--approve`: you type the last 8 characters of the fingerprint, then `POST /targets/ID/approve-key`; without it: prints the approval command and waits (`--wait-timeout`, default 10 minutes) for an administrator; pins the key in `known-targets.json` | no |
| 6 provision | the runtime | `agentgate-hostd provision --state-dir DIR` for the appliance runtime; nothing for docker-host; waits for the target to poll | appliance only |
| 7 ready | | prints the UI address and next steps | |

If a step fails, `up` names the step, the service's error code and message, and what to do; fix it and run the same
command again. A step that needs root refuses without it, before minting any one-time token, and prints both the
`sudo agentgate up ...` line and the manual `agentgate-hostd install` command. `--skip-host` stops after the target
step and needs no root. `--approve` is honoured only on an interactive terminal, only when the signed-in token is an
administrator's, only after this machine's agent reported the same fingerprint the service shows, and never with
`--yes`. A fingerprint that differs between the host agent and the service stops `up` with exit code 13.

For an existing service, skip the compose part: `agentgate up --service-url https://agentgate.example:9443`.

### 2. Sign in from another machine

```sh
agentgate login https://agentgate.example:9443 --ca-file corp-ca.pem      # username and password prompts
agentgate whoami
```

`login` signs in with the local password flow, mints an API token with your roles (or `--role launcher`), and saves it
in `~/.config/agentgate/config.json`; the token is never printed. With SSO, create a token in the UI and run
`agentgate login URL --token-stdin`. Several services or identities are separate contexts:
`agentgate login URL --save-as lab`, `agentgate context ls`, `agentgate context use lab`, or `--context lab` on any
command.

### 3. Define a profile and grant access

```sh
agentgate preset ls
agentgate profile new python-dev --preset python-dev --description "Python work"
agentgate grant python-dev read /srv/data --dry-run      # the service previews the change; nothing is stored
agentgate grant python-dev read /srv/data --reason "Read the data set"
agentgate grant python-dev web deny quic
agentgate grant python-dev mount repo                     # lets a launch mount a host folder named repo, read-only
agentgate profile versions python-dev
agentgate profile show python-dev
```

Each `grant` sends one typed edit to `POST /profiles/ID/versions/N/grants` on the latest version and prints the
difference between the parent version and the version the service stored. The CLI never edits a policy document.

### 4. Launch a one-shot command

```sh
agentgate launch --profile python-dev --image registry.example/py@sha256:<digest> --mode oneshot --lifetime 10m \
  --wait --until done -- python3 -m pytest -q
agentgate logs <launch id>
```

### 5. Launch a long-running agent with a brokered API key and a read-only repo mount

An administrator stores the key once, sealed to the target's host key (see [secret set](#secret-set)):

```sh
agentgate secret set anthropic --target local --upstream api.anthropic.com --header x-api-key \
  --allow-profile python-dev --allow-launcher local:lin < ~/anthropic.key
```

On a service that enforces broker rules, add the requests the broker may forward, for example
`--rule POST:/v1/messages`. Then see exactly what the agent will be allowed to do, and launch it:

```sh
agentgate launch --name repo-fixer --target local --mode session --lifetime 2h \
  --profile python-dev --image agentgate-coding@sha256:<digest> \
  --mount /srv/repos/app:repo:ro --secret anthropic:ANTHROPIC_BASE_URL \
  --dry-run -- claude --print "fix the failing tests"
```

`--dry-run` posts the spec to `/launch-plans` and prints the resolved plan: target, profile version and digest, mode,
lifetime and expiry, image, command, working directory, spec and policy digests, network, web, DNS, read, write,
execute and denied trees, devices, signals, anonymous execute, each mount with its in-agent path, each brokered secret
by name with its environment variable, upstreams and header (never a value), the approval decision with every reason,
and the notices. `--json` prints the service's answer unchanged. Remove `--dry-run` and add `--wait` to launch it and
follow it until it runs. The same launch from a file: `agentgate launch -f spec.json` (`agentgate schema launch-spec`
prints the JSON Schema).

### 6. Approve

A launch that needs approval waits in `approval_pending`; `launch` exits with code 8 and says who must decide. A
different human with the `approver` role reviews and decides it:

```sh
agentgate show <launch id>
agentgate approve <launch id> --reason "Reviewed the plan"      # shows the plan and asks to confirm on a terminal
agentgate reject <launch id> --reason "Too broad"
```

Nobody can decide a launch they requested, with any credential; the CLI reports the service's `self_approval` refusal
with exit code 4.

### 7. Watch

```sh
agentgate ps --active --mine
agentgate events <launch id> -f        # Server-Sent Events, resumes after a disconnect without loss or repeats
agentgate logs <launch id> -f          # Server-Sent Events of the output, until the launch ends
agentgate show <launch id>             # state, plan, effective permissions, host jobs, evidence receipt
```

### 8. Stop

```sh
agentgate stop <launch id> --reason "Done" --wait
```

Stop is idempotent. Stopping a running session asks for confirmation (or `--yes`). `--wait` follows the launch until
the host confirms an empty domain and released enforcement (`stopped`) or the launch ends otherwise.

### 9. Audit

```sh
agentgate audit --launch <launch id>
agentgate audit --since 24h --action launch.approved
agentgate audit catalog
```

## Configuration and credentials

| File | Mode | Holds |
| --- | --- | --- |
| `~/.config/agentgate/config.json` | 0600 | contexts: service URL, API token and its id, name, subject, roles and expiry, CA file, certificate pin |
| `~/.config/agentgate/known-targets.json` | 0600 | host key pins: service, target id and name, the approved `host_key_id`, and the `SHA256:` host key fingerprint once a signed seal key was verified |
| `~/.config/agentgate/ca-CONTEXT.pem` | 0600 | the local TLS front's CA, written by `agentgate up` |

The directory is `$AGENTGATE_CONFIG_DIR`, else `$XDG_CONFIG_HOME/agentgate`, else `~/.config/agentgate`. It must be a
real directory of mode 0700 owned by you, and each file a regular file of mode 0600 owned by you; otherwise every
command refuses (exit 13) and says how to fix it. Files are replaced atomically under a lock.

`AGENTGATE_URL`, `AGENTGATE_TOKEN`, `AGENTGATE_CONTEXT` and `AGENTGATE_CA_FILE` override the saved context. A saved
token is sent only to the server it was saved for: with a different `--server` or `AGENTGATE_URL`, a token must come
from `AGENTGATE_TOKEN`.

TLS uses the system roots, or only the CA in `--ca-file`. `--pin-cert sha256:HEX` (saved with `login`) additionally
requires that exact server certificate. Plain `http` is refused, except to a loopback address with `--insecure`, which
prints a warning every time; `--insecure` never disables certificate verification. Redirects are never followed.

Tokens are never printed after creation: `login` and `token create --save` store them without showing them;
`token create` without `--save` prints the new token once. `--verbose` logs each request to standard error with
`Authorization`, `Cookie` and CSRF values redacted and never logs bodies. Error messages never contain a token or a
secret. Passwords are read from a hidden prompt, `--password-stdin` or `--password-file` (mode 0600), never from
arguments or the environment, and are zeroed after use.

## Output

Human output is tables and labelled fields on standard output; notes, progress and warnings go to standard error.
`--json` prints exactly one JSON value on standard output with the API's field names (usually the service's answer
unchanged; streams with `-f` print one JSON object per line). Errors with `--json` also print
`{"error":{"code","message","hint","exit_code","status","request_id"}}`. `--quiet` prints only what scripts need (an id,
a name). Colors appear only on a terminal, and never with `--no-color`, `NO_COLOR` or `TERM=dumb`. Text from the
service is stripped of control characters before it is printed.

Every error shows the service's error code and message (with the HTTP status and request id) and one `next:` line.

## Requests, retries and interruption

Each request has a time limit (`--timeout`, default 30 seconds). Reads, and writes that carry an `Idempotency-Key`
(the CLI adds one to every write the service replays safely), are retried up to 3 times on network failures, 429,
502, 503 and 504, with jittered exponential backoff capped at 5 seconds, honouring `Retry-After` up to 30 seconds. A
write that returns a one-time secret (target creation, enrollment, token creation) or a ciphertext (`secret set`) is
never retried. Responses are bounded (8 MiB, 64 KiB for errors, 1 MiB per event-stream line).

Ctrl-C (or SIGTERM) ends the command with exit code 130. An interrupted `launch --wait`, `stop --wait`, `events -f` or
`logs -f` stops only the waiting: the launch keeps going, and the CLI prints its id and how to follow or stop it.

The event and output streams resume after a disconnect with `Last-Event-ID` and drop what they already printed. A stream that
fails or goes quiet for 45 seconds is reopened with backoff; after 3 consecutive failures the CLI also polls the events
endpoint, and after 9 it gives up with the error.

## Exit codes

| Code | Name | Meaning |
| --- | --- | --- |
| 0 | `ok` | The command did what it said. |
| 1 | `failure` | An unexpected local failure (a file could not be written, an internal error). |
| 2 | `usage` | The command line is wrong, or a confirmation was needed and none was possible. |
| 3 | `auth` | Not signed in, or the API token is unknown, expired, revoked or for another service (HTTP 401). |
| 4 | `forbidden` | The service refused the operation for this identity, including deciding your own launch (HTTP 403), or a step of agentgate up needs root. |
| 5 | `not_found` | The named target, profile, launch, secret or token does not exist (HTTP 404). |
| 6 | `conflict` | The resource changed or is in the wrong state; read it again and retry (HTTP 409, 412). |
| 7 | `rejected` | The service rejected the request as invalid; its message names the field (HTTP 400, 413, 415, 422, 428). |
| 8 | `approval_pending` | The launch or host key waits for a decision by a different human. |
| 9 | `timeout` | A request or a --wait did not finish within its time limit. |
| 10 | `server` | The service failed or is overloaded (HTTP 429, 5xx) after the allowed retries. |
| 11 | `network` | The service could not be reached. |
| 12 | `launch_ended` | A followed launch ended (failed, rejected, cancelled, expired) without reaching the awaited state. |
| 13 | `trust` | A trust check failed: TLS verification, a certificate pin, a host key pin, or the custody of the configuration; nothing was sent. |
| 130 | `interrupted` | Interrupted (Ctrl-C or SIGTERM). Work already accepted by the service continues. |

`launch` without `--wait` exits 0 when the launch was queued and 8 when it waits for approval. `launch --wait` exits 0
when the launch is running (`--until running`, the default) or stopped (`--until done`), 8 if it still waits for
approval at `--wait-timeout`, 9 if it is in another state then, and 12 if it ended first.

## Command reference

Global flags work before or after the command: `--context NAME`, `--server URL`, `--ca-file FILE`,
`--pin-cert SHA256`, `--insecure`, `--json`, `-q/--quiet`, `--no-color`, `-v/--verbose`, `-y/--yes`,
`--timeout DUR`, `-h/--help`. `agentgate COMMAND --help` lists a command's own flags. Mutations take `--reason`
(3 to 512 characters); the CLI fills in a descriptive default where the API requires one, except for decisions.

| Command | API | Notes |
| --- | --- | --- |
| `up` | many | see [Quickstart 1](#1-first-time-setup-bring-this-machine-online) |
| `login URL [--token-stdin] [--username U] [--role R] [--expires 30d] [--save-as NAME]` | `/auth/local/*`, `POST /api-tokens` | password sign-in mints a token; `--token-stdin` saves an existing one |
| `logout [--revoke]` | `DELETE /api-tokens/{id}` with `--revoke` | removes the saved token; `--revoke` signs in and revokes it |
| `whoami` | `GET /launch-spec-schema` | shows what the context recorded and checks the token is accepted |
| `context ls \| use NAME \| rm NAME` | none | local contexts |
| `target ls` | `GET /targets` | with the local pin state |
| `target add NAME [--token-file F]` | `POST /targets` | prints the one-time enrollment token once, or writes it to a new 0600 file |
| `target enroll NAME [--token-file F]` | `POST /targets/{id}/enrollment` | a new one-time token (reinstall, job key rotation) |
| `target status NAME` | `GET /targets/{id}` | state, host key, pin and the next step |
| `target approve-key NAME [--host-key-id ID]` | `POST /targets/{id}/approve-key` | type the fingerprint the host printed; pins it on success |
| `target pin NAME --host-key-id ID [--replace]` | `GET /targets/{id}` | pins an already approved key after you compared it |
| `target rename NAME NEW` | `PATCH /targets/{id}` | |
| `target retire NAME [--yes]` | `DELETE /targets/{id}` | confirms; revokes the host key and deletes the target's secrets |
| `profile ls`, `profile show NAME [--version N]`, `profile versions NAME` | `GET /profiles...` | |
| `profile new NAME [--preset P \| --file F] [--description D] [--no-approval]` | `POST /profiles` | `--no-approval` is for administrators |
| `profile approval NAME required\|auto` | `PATCH /profiles/{id}` | administrators |
| `preset ls` | `GET /access-presets` | presets, grant actions and revoke kinds |
| `grant PROFILE ACTION [VALUE...] [--mode M] [--upgrade] [--dry-run]` | `POST /profiles/{id}/versions/{n}/grants` | actions below |
| `launch (-f SPEC \| FLAGS) [--dry-run] [--wait] [--until running\|done] [--wait-timeout D] [-- CMD...]` | `POST /launch-plans`, `POST /launches`, events | flags below |
| `ps [--state S\|--active] [--target T] [--name N] [--mine\|--requester S] [--limit N] [--cursor C\|--all]` | `GET /launches` | the service filters and pages (newest first); a full page prints the next `--cursor`; `--all` follows every page (at most 10000) |
| `show ID` | `GET /launches/{id}` | |
| `logs ID [-f] [--after N] [--stream stdout\|stderr]` | `GET /launches/{id}/logs` | `-f` follows the output as Server-Sent Events (resuming with `Last-Event-ID`) until the service's end event; it polls when the service does not stream |
| `events ID [-f] [--after N]` | `GET /launches/{id}/events` | `-f` streams with resume |
| `stop ID [--wait] [--yes]` | `POST /launches/{id}/stop` | confirms for a running session |
| `approve ID --reason R [--yes]`, `reject ID --reason R` | `POST /launches/{id}/approve`, `/reject` | approver; never your own launch |
| `audit [--launch ID] [--since T] [--until T] [--actor A] [--action A] [--resource R] [--limit N]`, `audit catalog` | `GET /audit`, `GET /audit-catalog` | |
| `secret set NAME --upstream HOST --allow-profile P [...]` | `GET /openapi.json`, `GET /targets/{id}`, `GET /targets/{id}/seal-key`, `POST /secrets`, `GET /secrets/{id}/receipt` | see below |
| `secret ls [--target T] [--profile P] [--for-launch]` | `GET /secrets` (administrators), `GET /targets/{id}/secrets` (launchers) | administrators see all metadata; everyone else (or `--for-launch`, `--profile`) sees the names a launch may use and why not; `-q` prints the usable names |
| `secret rm NAME\|ID [--target T] [--yes]` | `DELETE /secrets/{id}` | administrators |
| `token create [--role R] [--expires D] [--name N] [--save]`, `token ls`, `token revoke ID` | `/api-tokens` | password sign-in each time: a token cannot mint, list or revoke tokens |
| `schema launch-spec` | `GET /launch-spec-schema` | |
| `completion bash\|zsh\|fish` | none | `source <(agentgate completion bash)` |
| `version` | none | |

### grant actions

| Command line | Edit sent |
| --- | --- |
| `grant P read\|write\|exec\|deny PATH` | `{"action":"read","values":[PATH]}` and so on |
| `grant P web [allow] [PROTO...]` | `allow-web` with `http`, `https`, `quic` or `all` (empty: all) |
| `grant P web deny [PROTO...]` | `deny-web` |
| `grant P dns IP [IP [IP]]` | `dns` (replaces the resolvers) |
| `grant P signal SIG...` | `signal` |
| `grant P anon-exec` | `anon-exec` |
| `grant P mount NAME [--mode read-only\|read-write]` | `mount` (access for a spec mount at `/var/lib/agentgate/mounts/NAME`) |
| `grant P unmount NAME` | `unmount` |
| `grant P preset NAME` | `preset` |
| `grant P revoke KIND [VALUE...]` | `revoke` with `kind` |

`--upgrade` allows an edit to turn a version one profile into version two. `--dry-run` sends the same edit with
`"dry_run": true`: the service runs every check and the same typed engine, stores nothing (it audits
`profile.grant.previewed`), and answers with the resulting document, the parent and result digests and its change list;
the CLI prints the diff, messages and notices and labels the result a preview. The CLI never applies an edit itself
(it does not link `internal/access`). Without `--dry-run` the diff is between the parent version and the version the
service returned.

### launch flags

`--name` (default: from the image name), `--target` (default `local`), `--mode oneshot|session` (default `oneshot`,
which needs a command after `--`), `--lifetime` (default 10m for oneshot, 1h for session; `90s`, `30m`, `2h`, `1d` or
seconds), `--profile NAME[@VERSION]` (default: the latest version, which the CLI looks up and prints),
`--image NAME@sha256:DIGEST`, `--mount SRC:NAME[:ro|snapshot|rw]` (default `ro`, a live read-only bind), `--secret
REF[:ENV]` (default `ENV` is `REF_BASE_URL` in upper case; the CLI checks each REF against
`GET /targets/{id}/secrets` for the target, you and the profile before it plans, and the shell completion offers the
usable names), `--env K=V`, `--workdir DIR` (default
`/var/lib/agentgate/workspace`), `--approval auto|required`, then `-- COMMAND...`. The service validates the spec and
rejects, for example, environment names that look like credentials; its message is shown verbatim. `-f FILE` (or `-`)
sends a complete `agentgate.launch.v1` document as it is and cannot be combined with these flags.

### secret set

```sh
agentgate secret set NAME --upstream HOST [--upstream HOST] [--header x-api-key|Authorization] \
  [--scheme Bearer|Basic [--basic-user U]] [--rule METHODS:PATH[:exact|prefix]]... [--allow-any-path] \
  [--extra-header NAME=VALUE]... [--target local] --allow-profile PROFILE [--allow-launcher SUBJECT] \
  [--wait [--wait-timeout 2m]] [--reason R]
```

The value is read from a hidden prompt (entered twice) on a terminal, or from standard input otherwise; never from
arguments or the environment. `--allow-launcher` defaults to your own subject.

How the broker uses the credential follows what the service accepts, which the CLI reads from the service's OpenAPI
document (`GET /openapi.json`, the `SecretInput` schema) and never guesses:

- A service with broker rules forwards nothing by default, so `secret set` needs at least one `--rule`, for example
  `--rule POST:/v1/messages` or `--rule GET,HEAD:/v1/models:prefix`, or the explicit wildcard `--allow-any-path` (every
  method and path of the upstreams; every plan that uses it says so and needs approval). `--scheme` (`Bearer` or
  `Basic` with `--basic-user`) and `--extra-header` are sent as fields.
- A service without them forwards every path of the upstreams; the CLI then refuses `--rule`, `--allow-any-path`,
  `--extra-header` and `--scheme Basic`, and implements `--scheme Bearer` by sealing the value with a `Bearer `
  prefix, because that API carries no scheme field.
- `--wait` (only where the service relays receipts, `GET /secrets/{id}/receipt`) polls for the host's
  `secretseal.Receipt` and verifies its tag with the sealing secret this run holds (`Sealed.VerifyReceipt`): only the
  host that opened exactly this envelope can produce it, so a relay that swapped the ciphertext is detected (exit 13).
  It then prints the host's keyed value fingerprint (`sfp1_...`). The sealing secret never leaves the process, so a
  later run cannot verify the receipt.

Before it reads the value, the CLI checks the target, and every failure is exit 13 with nothing read or sent:

1. The target is active and this machine holds a pin for it (`known-targets.json`), created when you approved its
   host key with `agentgate target approve-key` or `agentgate up`, or with `agentgate target pin` after comparing the
   fingerprint on the host console. No pin, or a service that now reports another `host_key_id`, is refused with
   what to compare.
2. It fetches the target's signed seal key, `GET /targets/{id}/seal-key` returning
   `{host_public_key, host_key_fingerprint, record}` (`record` is the `secretseal.SignedKeyRecord` the host
   publishes; the endpoint is the control plane request in [BROKER.md](BROKER.md#integration-requests)). It requires
   that `hostproto.KeyID(host_public_key)` equals the pinned `host_key_id`, that the SHA-256 fingerprint matches the
   one pinned earlier (recorded on first successful use), and that the record is signed by that key, names this
   target and is in date (`secretseal.VerifyKeyRecord`). A substituted host key, a seal key signed by anything else,
   a record for another target and an expired record are all refused.
3. A service that does not serve the seal key (it answers 404) gives the CLI nothing to verify, and `secret set`
   refuses. There is no option to seal to an unsigned key: the earlier `hostproto.SealSecret` format is retired.

The value is sealed with `internal/secretseal` (RFC 9180 HPKE; the associated data binds the target, the name, a
version and a nonce), and only the envelope (`Envelope.Encode()`) is submitted, in the `ciphertext` field. The buffers
holding the value are zeroed after sealing, the submission is never retried, and the CLI prints the pinned host key
and its fingerprint, the seal method, the seal key id and the ciphertext SHA-256. If the service records a different
ciphertext SHA-256 than the one sent, the CLI reports it with exit 13.

## What the CLI does not do

- It does not verify kernel enforcement; `kernel_verified` stays false.
- It does not touch Docker, cgroups, BPF or the appliance scripts itself: `up` delegates to `docker compose` and
  `agentgate-hostd` with argument vectors (never a shell string) and a minimal environment.
- It does not manage users; the UI and `community first-admin` do.
- It verifies the host's secret receipt only with `secret set --wait`, and only where the service relays it.
