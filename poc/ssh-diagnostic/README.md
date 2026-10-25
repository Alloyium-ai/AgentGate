# Experimental guarded SSH coding POC

This fixed diagnostic accepts an authenticated, noninteractive SSH command.
Each request creates a new Docker target and attaches six BPF network hooks before the command starts.
The command uses UID/GID 65534, a read-only root, a persistent private workspace, and a 25-second cutoff.
The gateway returns stdout, stderr, and the command exit code.
It fsyncs command and output hashes to a root-owned audit.
Disconnect, guard loss, or expiry stops the command and kills the command domain.
The launcher removes the target and releases guard pins only after the domain is empty.
One request runs at a time. TTY, agent forwarding, and port forwarding stay disabled for the POC key.

This is an **experimental network guard and container POC**.
Normal product admission remains closed. Syscall filtering and UI approval controls remain incomplete; filesystem and process controls are opt-in and unverified on a kernel (see Host controls below).
The trusted bridge makes an authenticated live `GET /api/tasks/ID` for one task.
The target receives a Unix socket and four task fields. It receives no upstream bearer token.
The bridge exposes `/task` and `/auth-probe`; other paths and methods return 403.
This is a one-task read bridge. General taskboard API scope and identity remain incomplete.
An allowed IP can serve several hostnames. The guard enforces endpoints, not HTTP host or TLS names on a shared IP.

To change what the agent may reach, use the `grant` command instead of editing JSON: see [Granting access](#granting-access).

## Quickstart: provision, grant, launch (control plane)

One end-to-end walkthrough of the control plane (service, UI, `agentgate` CLI, `agentgate-hostd`) on one disposable
BPF-LSM VM that is both the service host and the first target. **It has never been run as a whole.** The service,
CLI and UI were tested in process, with fake host agents speaking the real host protocol; the launch runtime and
`install.sh` were tested with Docker and systemd stand-ins. Docker, Docker Compose, systemd, a real
`agentgate-hostd`, the broker container and a BPF LSM kernel were never exercised, so every launch reports
`kernel_verified: false`.

Before you start, prepare the VM exactly as in [Prerequisites](#prerequisites),
[Build the portable artifacts](#build-the-portable-artifacts) and [Configure the VM](#configure-the-vm) (instance
`demo`): the docker-host runtime runs every launch through `/var/lib/agentgate-poc-demo`. Run the rest from the
repository root as a user in the `docker` group, with `sudo` where shown. Replace `registry.example` with a registry
you push to (local images get no `name@sha256:` reference otherwise), and keep the same `revision` as the artifacts.

```sh
# 1. Build and install the binaries (verified against build/SHA256SUMS).
revision=$(git rev-parse HEAD)
make agentgate
sudo deploy/install.sh --from build

# 2. Start the control service and create the first administrator (prompts for ada's new password).
export AGENTGATE_IMAGE=agentgate-local:dev
docker compose -f compose.yaml -f deploy/compose.build.yaml build control
agentgate up --compose-file compose.yaml --admin-user ada --skip-host
CA=~/.config/agentgate/ca-default.pem          # the TLS front's CA, saved by agentgate up; the UI is https://localhost:9443

# 3. Images by digest: the agent image (built from this revision) and the credential broker.
docker tag agentgate-poc-target registry.example/agentgate-poc-target:"$revision"
docker push registry.example/agentgate-poc-target:"$revision"
IMAGE=$(docker image inspect --format '{{index .RepoDigests 0}}' registry.example/agentgate-poc-target:"$revision")
docker build -f cmd/agentgate-broker/Dockerfile --build-arg SOURCE_REVISION="$revision" \
  -t registry.example/agentgate-broker:"$revision" .
docker push registry.example/agentgate-broker:"$revision"
BROKER=$(docker image inspect --format '{{index .RepoDigests 0}}' registry.example/agentgate-broker:"$revision")
docker network create agentgate-egress

# 4. Add the target and enroll this machine's host agent with the one-time token.
agentgate target add local --token-file ./enroll.token
sudo agentgate-hostd install --service-url https://localhost:9443 --token-file ./enroll.token --ca-file "$CA" \
  --runtime docker-host --instance demo --broker-image "$BROKER" --broker-uid 10002 --broker-gid 10002
rm ./enroll.token
sudo agentgate-hostd status                    # prints host_key_id and the key fingerprint to compare

# 5. Approve the host key: type the host_key_id agentgate-hostd printed, never the one the service shows.
agentgate target approve-key local --host-key-id 'ed25519:<the id agentgate-hostd printed>' --reason "Matches the host console"
agentgate doctor --target local                # every check ok, or the exact fix

# 6. An access profile from a preset, then typed grants (each stores a new version).
agentgate profile new python-dev --preset python-dev --description "Python work"
agentgate grant python-dev mount repo          # a launch may mount a host folder as repo, read-only
agentgate grant python-dev web deny quic --dry-run
agentgate grant python-dev web deny quic --reason "No HTTP/3"
agentgate profile show python-dev

# 7. A second human approves launches: in the UI, Local users, add bob with the approver role. Then:
agentgate login https://localhost:9443 --ca-file "$CA" --username bob --role approver --save-as bob
agentgate context use default

# 8. Store a secret, sealed here to the host's verified seal key; the broker forwards only POST /v1/messages.
agentgate secret set anthropic --target local --upstream api.anthropic.com --header x-api-key \
  --rule POST:/v1/messages --extra-header anthropic-version=2023-06-01 \
  --allow-profile python-dev --wait < ~/anthropic.key

# 9. A one-shot command on a read-only repository mount (exit 8: it waits for bob).
sudo mkdir -p /srv/repos/app            # the host folder (readable by uid 65534)
ID=$(agentgate launch -q --name tests --profile python-dev --image "$IMAGE" --mode oneshot --lifetime 10m \
  --mount /srv/repos/app:repo:ro --workdir /var/lib/agentgate/mounts/repo -- python3 -c 'print(6+6)')
agentgate --context bob approve "$ID" --reason "Reviewed the plan"
agentgate logs "$ID" -f                        # prints 12, then ends with the launch

# 10. A long-running agent with the secret and the read-only repository.
agentgate launch --dry-run --name repo-agent --profile python-dev --image "$IMAGE" --mode session --lifetime 2h \
  --mount /srv/repos/app:repo:ro --secret anthropic:ANTHROPIC_BASE_URL -- sh -c 'echo "$ANTHROPIC_BASE_URL"; exec sleep 7200'
ID=$(agentgate launch -q --name repo-agent --profile python-dev --image "$IMAGE" --mode session --lifetime 2h \
  --mount /srv/repos/app:repo:ro --secret anthropic:ANTHROPIC_BASE_URL -- sh -c 'echo "$ANTHROPIC_BASE_URL"; exec sleep 7200')
agentgate --context bob approve "$ID" --reason "Reviewed the broker rules and the mount"
agentgate logs "$ID" -f                        # the broker URL, never the key; Ctrl-C stops following, not the agent

# 11. Stop it, and read the audit trail.
agentgate stop "$ID" --reason "Done" --wait --yes
agentgate show "$ID"                           # state, plan, evidence receipt (kernel_verified: false)
agentgate audit --launch "$ID"
```

The dry run in step 10 prints what the agent may do: the profile version, mounts, the broker endpoint and the
`base_url` it receives, the forwarded requests, and why approval is needed. The UI shows the same pages (Targets,
Access profiles, Launch, Launches, Secrets) at `https://localhost:9443`. [docs/CLI.md](../../docs/CLI.md) and
[docs/PROVISIONING.md](../../docs/PROVISIONING.md) describe every command and endpoint.

## One-command Docker appliance

Use a Linux x86_64 host with Docker Engine, Docker Buildx, `/dev/kvm`, Python3, and OpenSSH client tools.
The launcher fails clearly on unsupported hosts. It does not install a host kernel or change host SSH.
The outer Docker container runs a disposable QEMU VM from a SHA256-verified public Ubuntu cloud image.
The VM enables BPF LSM and installs Docker automatically. The existing kernel preflight remains mandatory.
The first start needs network access for pinned images, the cloud image, and package installation.

Copy `policy.example.json` to your protected `policy.json` and edit the taskboard fields.
Supply the real taskboard token in a separate caller-owned file. Keep both files at mode0600.
Run this command from a source checkout:

```sh
python3 poc/ssh-diagnostic/appliance.py start --policy ./policy.json --token-file ./taskboard.token
```

The command builds the separate guard, bridge, workload, and appliance images.
It generates separate management, workload, and guest host keys before boot.
It pins the guest host identity, validates the workload contract, and runs a real guarded readiness command.
It prints `ready=true` and a complete SSH command that prints12.
A bounded TCP relay preserves SSH bytes and half-close behavior while avoiding outer/guest Docker subnet overlap.
The host listener binds only127.0.0.1 on port22365. Use `--port` for another loopback port.

The default state directory is `~/.local/share/agentgate/poc`, mode0700.
It retains the VM disk, keys, policy, audit, and Docker workspace. Use `--state DIR` for another instance.
Matching `start` calls reuse the state and pinned keys.
Use `--builder NAME` only to reuse an owned idle Buildx builder. The launcher retains the4 CPU/6 GiB limits. A changed source, base, port, token, or policy binding refuses overwrite.
Interrupted image builds reuse matching initialization state. A partial guest installation refuses clearly and retains its evidence.

```sh
python3 poc/ssh-diagnostic/appliance.py status
python3 poc/ssh-diagnostic/appliance.py audit
python3 poc/ssh-diagnostic/appliance.py policy --policy ./policy.json
python3 poc/ssh-diagnostic/appliance.py stop
python3 poc/ssh-diagnostic/appliance.py start
```

The `policy` command validates and atomically applies rule edits for the next SSH command. It needs no image rebuild.
It uses the same engine as `grant` below, so the change is locked, recorded in the grant history, and can be rolled back.
Taskboard fields stay bound to the authenticated bridge. Create a new state directory to change those fields.
Stop refuses an active command. It preserves the disk, workspace, audit, and keys.
Start after stop and Docker restart reuse the same pinned identities.
Inspect startup failures with `docker logs NAME` and the protected `build.log` in the state directory.
The printed instance name also appears in `binding.json`.

### Choose the workload base

The default workload base uses the pinned Ubuntu image in `ssh/Dockerfile`.
Only the coding stage uses `CODING_BASE_IMAGE`; the enforcer, bridge, and appliance keep their separate pins.
For a Debian-compatible alternative, use a new state directory:

```sh
python3 poc/ssh-diagnostic/appliance.py start --state ~/.local/share/agentgate/debian-poc \
  --policy ./policy.json --token-file ./taskboard.token --port 22366 --coding-base debian:bookworm-slim
```

The launcher resolves a supplied tag to a digest and records that digest in `binding.json`.
Choose only trusted operator-selected Linux images. The contract checks prerequisites, not image trust.
The coding Dockerfile needs Debian/Ubuntu-compatible `apt-get`. It installs Python3, curl, certificates, dash, and util-linux.
The target requires `/bin/sh`, `/usr/bin/setpriv`, runtime directories, and UID/GID65534 execution.
The launcher rejects declared image volumes, disables inherited health checks, and validates the image before key installation.
It enforces UID/GID65534, read-only root, no capabilities, no-new-privileges, and the BPF guard regardless of base.
The cleared command environment exposes `/usr/local/bin:/usr/bin:/bin`, including standard development tools.
Alpine and arbitrary incompatible images are not supported by this Dockerfile.
You can also build the coding stage directly with `--build-arg CODING_BASE_IMAGE=IMAGE` for the manual setup below.

## Granting access

`grant` edits the operator policy for you: one locked, validated, atomic, recorded change per command.
Every result passes through the same native validator the runtime uses (`pilot-network-diagnostic network-info`).
A policy the validator rejects is never written, and its message is shown verbatim. Each change applies to the **next SSH command**.

### Quickstart

```sh
G="python3 poc/ssh-diagnostic/appliance.py grant"

$G show                                    # what the agent can reach now, with the effective policy digest
$G presets                                 # list the presets
$G preset python-dev --upgrade-to-v2       # start from a preset (see "Version two" below)
$G deny-web all                            # no public web
$G allow-web https                         # HTTPS (TCP443) only
$G dns 1.1.1.1 9.9.9.9                     # choose the DNS resolvers
$G mount ~/src/myrepo --as myrepo          # share a project folder, read-only
$G exec /var/lib/agentgate/mounts/myrepo   # let the agent run programs from it
$G deny /var/lib/agentgate/workspace/keys  # hide a subtree, overriding any allowance
$G --dry-run read /opt/reference           # preview: unified diff and validation, nothing written
$G history                                 # recorded changes
$G rollback                                # undo the most recent change
$G wizard                                  # answer a few questions; prints and runs the commands
```

With the appliance, `grant` acts on the default state directory; pass `--state DIR` for another instance.
To edit a policy file directly (for example on a manually configured VM), pass `--policy FILE`:

```sh
sudo python3 poc/ssh-diagnostic/grants.py --policy /var/lib/agentgate-poc-demo/policy.json allow-web https
```

In `--policy` mode the validator is `--validator PATH`, `$AGENTGATE_VALIDATOR`, or `pilot-network-diagnostic` in the policy's
directory (true for an installed VM). Build one with `go build -o ./pilot-network-diagnostic ./cmd/pilot-network-diagnostic`.
With the appliance, the instance's own validator runs in the same bounded container the `start` command uses.

### Command reference

| Command | Effect |
| --- | --- |
| `show [--json]` | Summary of network, filesystem, process, and host folder access, and the effective digest. |
| `presets` | The presets and what each allows. |
| `allow-web [http\|https\|quic\|all]...` / `deny-web ...` | Add or remove TCP80, TCP443, or UDP443 to public IPv4. Default `all`. |
| `dns IP...` | Set one to three public IPv4 resolvers. |
| `read PATH` | Readable tree (`filesystem.read_only`). |
| `write PATH` | Writable, never executable tree (`filesystem.scratch`). The container root stays read-only, so this matters only below the workspace, `/tmp`, or a read-write host folder; `grant` says so. |
| `exec PATH` | Readable and runnable tree (`filesystem.execute`). Refused if it overlaps any writable tree or read-write mount. |
| `deny PATH` | Tree where every operation is refused, overriding broader allowances. |
| `signal NAME...` | Allowed signals within the command's own tree (`TERM` or `SIGTERM`). |
| `anon-exec` | Executable anonymous memory (JIT, libffi closures). Weakens write-xor-execute. |
| `mount HOST_PATH [--as NAME] [--read-only\|--read-write]` | Share a host folder at `/var/lib/agentgate/mounts/NAME`; see [Host folders](#host-folders). |
| `unmount NAME` | Remove the folder and its access entry. |
| `device DEVICE` | Allow one character device: `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, or `/dev/tty` (`filesystem.devices`); refused inside a `deny` tree. |
| `revoke KIND VALUE...` | Undo a grant. `KIND` is `web`, `dns`, `read`, `write`, `exec`, `deny`, `signal`, `anon-exec`, `mount`, or `device`. |
| `preset NAME` | Replace the web, filesystem, and process sections with a preset. |
| `history [--json]` / `rollback [N]` | List changes; restore the policy as it was before the last `N` changes (default 1). |
| `sync` | Appliance only: apply the local policy to the running appliance (after a stopped-time change or a failed transfer). |
| `wizard` | Plain prompts for the common cases; prints the exact commands, then runs them on confirmation. |
| `allow-domain NAME` | Not implemented; exits 9. See [Domain allowlist](#domain-allowlist-design-and-open-work). |

Options for every command: `--state DIR` or `--policy FILE`, `--mounts FILE` (with `--policy`), `--validator PATH`,
`--dry-run`, `--upgrade-to-v2`, `--wait SECONDS` (lock wait, default 30), and `--json` (for `show` and `history`).

Grants are idempotent: granting what is already granted, including through a broader entry, prints `unchanged=true` and writes nothing.
`revoke` of a path that stays allowed through a broader entry fails with exit 12 and names that entry.
Paths are absolute and canonical; `..`, `.`, `//`, and `/` are refused. A path inside a `deny` tree must be revoked from `deny` first.

### Version two

A version one policy (`agentgate.network-poc.v1`) controls only the network. File, folder, signal, and preset grants need version two
(`agentgate.poc.v2`). The first such grant refuses with exit 6 unless you pass `--upgrade-to-v2` or confirm at an interactive prompt.
The upgrade keeps every network field unchanged and adds the conservative `filesystem` and `process` sections of
[policy.full.example.json](policy.full.example.json). Version two attaches the BPF LSM filesystem and process components, which are
**not yet exercised on a BPF LSM kernel** (see [Host controls](#host-controls-filesystem-executables-and-processes-experimental)).
Network grants on a version one policy keep it version one, exactly as before.

### Presets

Presets live in [presets.json](presets.json). Each one keeps the DNS resolvers, the taskboard, and existing host folder access entries.

| Preset | Web | Writable (never executable) | Read-only | Executable |
| --- | --- | --- | --- | --- |
| `locked-down` | none | workspace only | `/etc`, `/proc`, taskboard | `/usr`, `/bin`, `/lib`, `/lib64` |
| `python-dev` | HTTP, HTTPS | workspace, `/tmp` | `/etc`, `/proc`, taskboard | `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64` |
| `web-readonly` | HTTP, HTTPS, QUIC | workspace only (required by the schema) | `/etc`, `/proc`, taskboard | `/usr`, `/bin`, `/lib`, `/lib64` |
| `full-example` | as the example | as the example | as the example | as the example |

All presets deny `/etc/shadow` and the sensitive `/proc` entries. `full-example` is exactly the web, filesystem, and process sections
of `policy.full.example.json`. A test validates every preset with the real validator.

### Safety properties

- **Locking:** one lock per state directory (the same `control.lock` that `start`, `stop`, and `policy` use) or per policy directory.
  A second command waits up to `--wait` seconds, then exits 7.
- **Atomic, durable writes:** a temporary file in the same directory, `fsync`, rename, and directory `fsync`. A crash leaves the old or
  the new policy, never a partial one. The file keeps its mode (0600 or 0400).
- **Recovery:** before each change, `grant` records an intent. If a crash interrupts a change, the next `grant` (or `start`) finishes
  it when the new policy is in place, or discards it when the old policy is still in place, and says which. A policy changed by hand
  after an interruption stops with exit 10.
- **Custody:** the policy file must be a regular file owned by you with no group or other access, in a directory that is not group- or
  world-writable, reached without a symlink. The history directory (`policy.json.grants/`, or `grants/` in a state directory) is mode
  0700. Anything else exits 3 with the fix.
- **History:** every change appends to `log.jsonl` and keeps a timestamped backup of the previous policy. The last 20 backups are kept.
  `rollback N` verifies the backup's SHA-256 before it restores it, and a rollback is itself a recorded change.
- **Appliance:** with the appliance running, the change is copied into the guest and swapped in only between commands
  (`flock -n` on the guest's job lock); a running command makes `grant` exit 7 with nothing changed. With the appliance stopped, the
  change is recorded as pending and applied by the next `start`. `status` reports a pending change.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success, including an unchanged no-op and a dry run that would apply. |
| 1 | Unexpected error. |
| 2 | Invalid command line or argument value. |
| 3 | Unsafe policy, state, history, or host folder path (symlink, owner, mode, or protected tree). |
| 4 | The validator rejected the result; its message is shown verbatim. Nothing was written. |
| 5 | No validator is available, or it failed to run (for example, Docker is unavailable). |
| 6 | The change needs a version two policy; rerun with `--upgrade-to-v2`. |
| 7 | Busy: another grant or appliance command, or a guarded command in the appliance, holds the lock. |
| 8 | The appliance could not apply the change; the local policy is unchanged. |
| 9 | Not implemented (domain allowlists; read-write folders with the appliance). |
| 10 | The policy changed outside `grant`, or an interrupted change needs manual attention. |
| 11 | The requested history entry or backup is unavailable (pruned or damaged). |
| 12 | The request conflicts with the current policy; the message names the entry. |

### Host folders

A mount alone grants nothing. The version two `filesystem` policy decides what the agent may do below
`/var/lib/agentgate/mounts/NAME`, and `grant mount` adds the matching entry: `read_only` for a read-only folder, `scratch` (writable,
never executable) for a read-write one. A read-write folder can never also be executable: `grant` refuses `exec` over it, and the target
start refuses a policy that executes over a read-write mount. Mounts are refused for a version one policy, which controls no file access.

**Manually configured VM (`--policy FILE`).** The folder is a live bind mount of a directory on the Docker host that runs the targets.
`grant` writes the protected, root-owned `mounts.json` next to the policy. Before each command, `mounts.py` validates every entry again and
derives each Docker argument from validated fields only; `start-target.sh` and `restart-target.sh` never interpret free-form text.
Read-only is the default; `--read-write` is explicit. The agent runs as UID 65534, so the folder needs matching permissions.

**Appliance.** The agent runs inside a QEMU VM that cannot see this machine's files, so the appliance supports a **read-only snapshot**:
`grant mount` copies a normalized archive of the folder into the VM (directories and regular files only; symlinks, devices, sockets,
FIFOs, and other file systems are skipped and counted; owners become root; modes 0755/0644; at most 256 MiB and 20000 entries).
Run the same command again to refresh it. Changes inside the VM never reach this machine. `--read-write` exits 9: exchange files
through the workspace instead.

Rules for every folder: at most eight; canonical paths with no symlink; not `/`, `/etc`, `/root`, `/proc`, `/sys`, `/dev`, `/run`,
`/var/run`, `/boot`, `/usr`, `/bin`, `/sbin`, `/lib*`, `/var/lib/docker`, `/var/lib/containerd`, or any tree that contains one;
not your home directory (`$HOME`) or a directory containing it; not overlapping `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config`,
`~/.docker`, `~/.kube`, or the other credential stores `mounts.py` lists; not overlapping the state directory, the policy directory, or
any `/var/lib/agentgate-poc-*` instance; no further mount below a live folder; sources of two folders never overlap. Share a project
folder, not a whole home or system tree: everything inside the folder, including `.git` and any `.env` file, becomes visible. Live bind paths may use only letters, digits, and `. _ @ + - /`.
The target binding (`target.json`) lists each approved mount; the guard (`dockerplacement`) and the gateway both refuse a target whose
Docker mounts differ in any way, a read-only folder that the kernel mount table does not show read-only, a further mount below a folder,
or a folder whose device and inode differ from its source. The image contract refuses a symlinked `/var/lib/agentgate/mounts`.

`rollback` restores the policy only. A rollback that removes a folder's access entry leaves the folder mounted but inaccessible, and
`show` marks it so; `unmount` removes it.

## Domain allowlist: design and open work

`grant allow-domain` is **not implemented** and exits 9. The network guard enforces IPv4 addresses, protocols, and ports; it never sees
hostnames. Shipping an allowlist that only rewrote DNS answers or `/etc/hosts` would look like hostname enforcement while any process
could still connect to any allowed address, so this POC does not pretend.

A sound design within this architecture:

1. **Trusted resolver.** A resolver outside the command domain, owned by the guard, answers only allowlisted names (and their CNAME
   chains) through a pinned upstream with TLS (`internal/dnslease` already validates replies and builds leases for one job binding).
   Every other question gets `REFUSED`. The target's resolver file points only at it.
2. **Leases.** Each answer becomes a lease: rule ID, hostname, address, chain, and an expiry at the minimum TTL, capped by the command
   deadline. `internal/nodedns` coordinates publishing; `internal/netrules` compiles leases into the existing policy map, and the
   BPF map's lease revision field (`Policy.Reserved`) records each publication.
3. **Kernel admission.** The guard denies every destination without a live lease. The resolver address needs its own narrow
   exception, because the independent boundary in `bpf/network_policy.bpf.c` denies private and bridge addresses today.
4. **Evidence.** Receipts record each lease and each decision's lease revision.

Threat model and limits that remain even when built:

- **Shared addresses.** Enforcement is by resolved address, not by TLS server name. An allowed CDN address can serve other hostnames,
  and a command can send any SNI or `Host` header to it. Closing that needs a TLS-terminating or SNI-checking proxy.
- **Races.** A lease must be published before the answer reaches the command, and revoked at TTL expiry; connections opened under a
  lease outlive it.
- **Out-of-band resolution.** DNS over HTTPS to an allowed address, or hard-coded addresses, bypass the resolver; only addresses with
  live leases connect, so this stays address-bounded but not name-bounded.

Open work: run the resolver inside the guard process with a bounded cache, add the resolver exception to the BPF boundary, publish
leases with live map updates during the command (today the map is written once before attach), add receipts for leases, and test it all
end to end. It is left as design because a sound version needs those new guard and kernel components and an end-to-end test on the
appliance (Docker, the guest kernel, and real DNS), none of which this change could run.

## The editable network policy

Copy [policy.example.json](policy.example.json) to `policy.json`.
Edit its taskboard address, port, and task ID before setup. The example contains no credentials.
The JSON policy controls the real BPF network guard for this SSH POC. Version two documents also control the host components below.
The browser UI does not edit this POC policy.

The default policy denies all endpoints, then allows:

- DNS: UDP53 and TCP53, only to the exact IPv4 addresses in `dns.resolvers`.
- HTTP: TCP80 to public IPv4 destinations.
- HTTPS: TCP443 to public IPv4 destinations.
- HTTP/3 or QUIC: UDP443 to public IPv4 destinations, when that rule exists.
- Taskboard: TCP to the exact private address and port in `taskboard`.

IPv6 stays denied. The independent kernel boundary denies other LAN, host, bridge, loopback, and link-local destinations.
A private DNS answer does not bypass that boundary. Documentation address ranges also stay denied.
The taskboard exception grants one TCP endpoint. It does not grant other LAN addresses or UDP.
The authenticated task bridge exposes only the configured task through its Unix socket.
The SSH command target always gets the bridge volume, read-only. A launch target (`restart-target.sh --launch`) gets it
only when the launch asks: its signed policy keeps the `taskboard` endpoint and grants reading `/run/agentgate/taskboard`
(`launch_job.taskboard_bridge`). A launch with brokered secrets has no taskboard and never gets the volume; the guard
binding records the choice and the gateway refuses a target whose mounts differ from it.

This preset allows any public IPv4 web destination. It enforces protocol, address, and port, not domain or TLS names.
An allowed public IP can serve several hostnames. A domain allowlist is outside this simple preset.
Conventional HTTP uses TCP80. UDP443 permits HTTP/3; it does not supply an HTTP/3 client.

To change the installed policy, prefer `grant --policy /var/lib/agentgate-poc-demo/policy.json ...` on the VM (see
[Granting access](#granting-access)). The equivalent manual procedure, through the separate management connection:

```sh
sudo cp /var/lib/agentgate-poc-demo/policy.json ./policy.json
sudo chmod 0600 ./policy.json
sudo editor ./policy.json
sudo /var/lib/agentgate-poc-demo/pilot-network-diagnostic network-info ./policy.json
sudo install -o root -g root -m 0600 ./policy.json /var/lib/agentgate-poc-demo/policy.next.json
sudo mv /var/lib/agentgate-poc-demo/policy.next.json /var/lib/agentgate-poc-demo/policy.json
```

Edits apply to the **next SSH command**. Each command validates and snapshots the current JSON before target creation.
An active command retains its snapshot. Invalid JSON, unknown fields, duplicate keys, and invalid rules refuse execution.
The launcher derives the effective SHA256 digest from that snapshot. No digest in `settings.json` needs an edit.
The audit and guard receipt record that digest. Whitespace changes do not change the canonical effective digest.

Remove a web rule to deny that protocol and port. Use `"rules": []` to deny all public web access.
Edit `dns.resolvers` to choose one to three approved public IPv4 resolvers.
DNS always uses UDP53 and TCP53. The network router can intercept those requests normally.
The launcher replaces only its fresh target's generated resolver file, so ordinary `getent` and `curl` use these resolvers.
It uses no per-host address mapping, DNS over TLS, or `curl --resolve`.
The POC requires `duration_seconds: 25`; the command cutoff stays fixed at 25 seconds.
The taskboard fields bind the authenticated bridge. Create a new instance to change those fields.

## Host controls: filesystem, executables, and processes (experimental)

A version two policy (`agentgate.poc.v2`, see [policy.full.example.json](policy.full.example.json)) adds explicit `filesystem` and `process`
sections. The guard then also attaches the BPF LSM filesystem component (`bpf/fs_access.bpf.c`) and the process component
(`bpf/process_guard.bpf.c`) to the same per-command cgroup, before the command starts. A version one policy behaves exactly as before.

- **Filesystem:** every path is denied unless a list names it. `workspace` and `scratch` trees are writable (read, write, create, mkdir,
  delete, rename, symlink, chmod/chown) and never executable. `read_only` trees can be read and mapped. `execute` trees can also run
  programs and map code. `devices` is a subset of `/dev/{null,zero,full,random,urandom,tty}`. `deny` trees refuse everything and
  override a broader allowance (`/etc/shadow` under a readable `/etc`). The validator refuses any `workspace`, `scratch`, `read_only`,
  `execute`, or `devices` entry equal to or below a `deny` entry, because the kernel walker would let that more specific allowance
  win; so `grant deny` over an allowed tree is rejected (exit 4) until that entry is revoked. Hard links are never allowed, and
  `ioctl` is limited to five descriptor queries. A new regular file can be made only by `open(O_CREAT)`; its `create` right is checked
  when the new file is opened (see the limits below). FIFOs (`mkfifo`), socket nodes (`bind()` of an AF_UNIX socket to a pathname),
  device nodes, and regular files made by `mknod` are never allowed, in any tree: they fail with EPERM. Abstract AF_UNIX sockets,
  `socketpair`, and pipes make no node and are not affected. Ancestor directories of allowed trees get an exact-path read so `stat`
  works.
- **Executables:** `execute` entries are the program allowlist. A writable tree may not also be executable; the policy refuses that
  overlap. A binary a command writes cannot be run.
- **Memory:** anonymous mappings may be read, written, and re-protected. Executable anonymous memory (a JIT or libffi closure)
  needs `"anonymous_execute": true`.
- **Processes:** a command may signal only its own tree, and only the listed signals. Tracing (`ptrace` attach, `PTRACE_TRACEME`) is always
  denied. Signal 0 existence probes are denied.
- **Sockets:** no socket LSM guard is attached. The filesystem component lets `read`/`write` on socket descriptors through (it never sees
  `send`, `recv`, or other socket calls), and the only kernel control over sockets is the network guard's six cgroup hooks, which bound
  IPv4 and IPv6 connect, UDP sendmsg, and IP packet egress and ingress by address. Nothing decides socket family or type, `bind`,
  `listen`, `accept`, AF_UNIX connect (only file permissions on the socket node apply) and traffic, or AF_NETLINK traffic. The plan records this as the
  socket mode `cgroup-network-guard-only`, and the receipt's `host` block reports `"sockets": "cgroup-network-guard-only"` and
  `"socket_lsm_guard": false`. The guard selects that mode only after the kernel reports all six network hooks attached to the command's
  cgroup, and checks again before it installs the plan; otherwise it refuses to start.
- **Standard streams:** the command's stdout and stderr are pipes the gateway makes outside the domain; its stdin is `/dev/null`
  for a launch and sshd's stream for an SSH command. Before it starts the runner, the gateway records the inode of each of those
  pipes (stdin only when it is an anonymous pipe) in the guard's pinned file component (`pilot-network-diagnostic stdio-grant`):
  stdin for reading, stdout and stderr for writing. The guard refuses the grant once the domain is populated or after a first
  grant, and the gateway refuses to run the command when the grant fails. The file component then lets the job use a pipe made
  outside its domain only by a recorded inode, in its recorded direction; with no recorded inode, no inherited pipe is usable.
  Pipes the job makes itself (a shell pipeline) are unaffected, and a pipe from another job or received over a socket stays
  denied. What remains: a grant lasts until the policy expires, not until the pipe closes, and pipefs inode numbers come from the
  kernel's 32-bit `get_next_ino()` counter, so a different pipe made outside every domain could reuse a recorded number after
  about 2^32 inode allocations on the host during one launch; it would be usable in the recorded direction only.

To make this possible the runner joins the cgroup last. It opens `cgroup.procs` as root, enters the target namespaces, and the
unprivileged shell writes its own PID, closes the descriptor, verifies its cgroup, and only then runs the command. A failed join exits 125
without running the command. The receipt gains a `host` block: per-operation counts, a SHA-256 over the whole raw event stream, the first
2000 denials with their paths, and loss counters. Any lost or malformed event marks the receipt incomplete. The gateway also refuses to run
unless all 23 host links are pinned, and it stops the command if one disappears.

**Verification status.** The Go planning, the shell join logic, and the evidence accounting have unit tests. The BPF objects compile
cleanly, and their kernel-named structs and fields match a current kernel's BTF. **No BPF LSM kernel was available when this was
written, so the verifier, the hooks, and the end-to-end behavior are not yet exercised.** Expect first-boot fixes. The kernel read of
the six network hooks (`fsrules.ObserveCgroupNetworkGuard`) has run against real cgroup links on a 6.18 kernel; no LSM program has.
The `grant` engine, presets, mount validation, snapshot archives, and the gateway's cleanup paths have unit tests that run the real
validator; the Docker-host mount path and the appliance's snapshot transfer have not run against Docker or the VM here. Known limits:

- `bpf_d_path` is called only from hooks in the 6.8 kernel's sleepable LSM hook set, the only hooks where it is allowed (`file_open`,
  `file_receive`, `bprm_check_security`, `inode_getattr`, `mmap_file`, `path_mkdir`, `path_unlink`, `path_rmdir`, `path_rename`,
  `path_symlink`, `path_chmod`, `path_chown`, `path_truncate`). A Go test in `internal/fsrules` fails if a call becomes reachable from
  any other hook. `path_mknod` is not in that set, so it never resolves a path. If a kernel still refuses a program, the whole object
  fails to load and the guard fails closed.
- A denied `create` through `open(O_CREAT)` fails the open with EPERM, but the kernel has already made the empty file wherever file
  permissions allow it (for example `/dev/shm`). The denial is recorded with its path. Every other node type is refused before it exists.
- **`path_mknod` relies on kernel internals.** The hook cannot resolve a path, so it tells `open(O_CREAT)` from `mknod(2)` by
  evidence the kernel does not promise to keep: it lets a creation through only when the mode is a regular file with device 0,
  `current->nameidata` is published (6.8 publishes the open's walk during `may_o_create()` and has restored it before
  `do_mknodat()` and `unix_bind_bsd()` call the hook), that walk carries `LOOKUP_OPEN|LOOKUP_CREATE` (`0x100|0x200`), the hook's
  directory is that walk's own `nameidata->path`, and the syscall in progress (`orig_ax` of the task's user registers) is x86-64
  `open`, `creat`, `openat` or `openat2`. The last condition is the syscall ABI, so `mknod(2)` and `mknodat(2)` can never pass
  even if a kernel left `nameidata` published. Each condition fails closed: if a kernel changes one, creating a new file with
  `open(O_CREAT)` fails with EPERM instead of `mknod(2)` succeeding. 32-bit and x32 tasks, io_uring opens and kernel-made files
  such as core dumps never pass. Re-verify the checklist in [docs/QUALIFICATION.md](../../docs/QUALIFICATION.md) on every new
  kernel; the verification kit's `allow-create` and `deny-mknod-regular` probes exercise both sides.
- Open work: attaching the socket LSM guard. `bpf/network_sockets.bpf.c` and `bpf/network_custody.bpf.c` exist, but only the unused
  full-product path (`internal/enforcement`, through `fsrules.EnableSocketDelegation`) loads them. In this POC they would add policy
  decisions on `socket_create` and `socket_post_create` (family, type, protocol), `socket_bind`, `socket_listen`, `socket_accept`,
  `socket_sendmsg`, `socket_recvmsg`, `socket_getsockname`, `socket_getpeername`, `socket_shutdown`, `socket_setsockopt`,
  `socket_getsockopt`, socket `file_permission`, their own cgroup ingress and egress hooks, and descriptor custody on `socket_sendmsg`
  and `socket_recvmsg`. That is a separate change that needs its own kernel verification.
- There is no syscall filter. The container keeps Docker's default seccomp profile. `setxattr`/`utimes` are not path-checked.
- Every command loads and attaches the 23 hooks again; expect added start-up latency.
- Policy covers a command's tree only from the moment it joins. The trusted helpers before that run unrestricted.
- If the guard's cleanup bound expires, it still writes its receipt, marked incomplete with `"stop": "cleanup_bound_exceeded"`.
- An orphaned network or host pin directory (a killed guard) is released by the next command or cleanup once the domain is empty,
  the guard has exited, and the target is gone.

## Prerequisites

Use a fresh, operator-owned **QEMU x86-64 VM** with rootful Docker and kernel **6.8.0-142-generic**.
The existing guard preflight deliberately rejects another kernel or a missing disposable marker.
Enable BPF LSM in the VM boot settings. Verify the actual kernel features before setup:

```sh
uname -r
grep -w bpf /sys/kernel/security/lsm
test -r /sys/kernel/btf/vmlinux
test -r /sys/fs/cgroup/cgroup.controllers
test -e /sys/fs/cgroup/cgroup.kill
mountpoint /sys/fs/bpf
cat /sys/class/dmi/id/sys_vendor
```

The VM needs securityfs, bpffs, cgroup v2, BTF, BPF cgroup links, and access to the host PID and mount namespaces.
Provision the marker `/etc/alloyium-disposable-vm` with content that starts with `kernel-poc-` only on this disposable VM.
Install Docker, Python 3, Bash, util-linux (`nsenter`, `setpriv`, `flock`), OpenSSH server, and CA certificates.
The target image installs full Python 3 and util-linux explicitly.
Keep the VM SSH listener private or loopback-bound. Use its existing management SSH connection and verified host key.
Root runs the trusted launcher through a forced SSH key. The target never receives Docker or root configuration.
No VM image, private key, token, known-hosts file, or live policy comes with this source.

## Build the portable artifacts

Run these commands from a public repository clone. Docker builds do not need BPF privileges.
Use the same public source revision for all three builds:

```sh
revision=$(git rev-parse HEAD)
docker build -f ssh/Dockerfile --target coding-target --build-arg SOURCE_REVISION="$revision" -t agentgate-poc-target .
docker build -f ssh/Dockerfile --target taskboard-bridge --build-arg SOURCE_REVISION="$revision" -t agentgate-poc-bridge .
docker build -f poc/ssh-diagnostic/Dockerfile --build-arg SOURCE_REVISION="$revision" -t agentgate-poc-artifacts .
mkdir -p artifacts
copy=$(docker create agentgate-poc-artifacts true)
docker cp "$copy:/pilot-network-diagnostic" artifacts/
docker cp "$copy:/network_policy.bpf.o" artifacts/
docker cp "$copy:/licenses" artifacts/
docker cp "$copy:/build-modules.txt" artifacts/
docker rm "$copy"
```

Transfer the source, artifacts, and two target images to the disposable VM when you build elsewhere.
Use `docker save` and `docker load`, or a private registry with immutable digests.
The installation resolves the local image IDs and checks their source labels.
A durable release still needs independent review, protected CI, registry publication, and immutable image references.

## Configure the VM

Create a dedicated Ed25519 client key with `ssh-keygen -t ed25519 -f ./poc-key` on your client.
Copy only `poc-key.pub` to the VM. Preserve the VM's existing management key.
On the VM, set these variables to your real inputs:

- `TASKBOARD_IP`, `TASKBOARD_PORT`, `TASK_ID`: one reachable private taskboard endpoint and one readable task.
- `TOKEN_FILE`: an absolute root-owned regular file, mode 0600, containing its bearer token.
- `PUBLIC_KEY`: the copied public key path.
- `IPV6_SUBNET`: an unused private IPv6 /64 owned by this VM for negative verification.

The taskboard must return 401 or 403 without authentication, and 200 with the supplied token.
The bridge rejects an upstream that accepts unauthenticated reads.
Run the setup as root from the source clone:

```sh
cp poc/ssh-diagnostic/policy.example.json policy.json
chmod 0600 policy.json
editor policy.json
artifacts/pilot-network-diagnostic network-info policy.json
python3 poc/ssh-diagnostic/configure.py --instance demo --source-revision "$revision" \
  --artifacts ./artifacts --policy ./policy.json \
  --target-image agentgate-poc-target --bridge-image agentgate-poc-bridge \
  --token-file "$TOKEN_FILE" --public-key "$PUBLIC_KEY" --ipv6-subnet "$IPV6_SUBNET"
```

The setup copies protected inputs to `/var/lib/agentgate-poc-demo`, creates the bridge and workspace, and adds one restricted key.
The setup refuses an existing installation. It does not change an active endpoint.
A failed kernel attach returns a precise preflight or BPF error before any command executes.

## Run, audit, and stop

From your client, use the VM's verified address, port, and dedicated key:

```sh
ssh -T -i ./poc-key -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes root@VM_HOST \
  'python3 -c "from pathlib import Path; Path(\"hello.py\").write_text(\"print(6+6)\\n\")"; python3 hello.py'
ssh -T -i ./poc-key -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes root@VM_HOST \
  'curl --fail --silent --show-error --unix-socket /run/agentgate/taskboard/taskboard.sock http://localhost/task'
ssh -T -i ./poc-key -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes root@VM_HOST 'exit 7'
```

The first command prints `12`. The third command returns SSH exit code 7.
Each command uses a fresh target and guard. The workspace persists between commands.
Ordinary DNS, HTTP, and HTTPS work without address overrides:

```sh
ssh -T -i ./poc-key root@VM_HOST 'getent ahostsv4 example.org; curl -fsS http://example.org >/dev/null; curl -fsS https://example.com >/dev/null'
```

Use strict host checking and the verified host key as shown above.
Other LAN peers and the wrong taskboard port receive kernel denials.
Inspect the audit through the separate management connection:

```sh
sudo cat /var/lib/agentgate-poc-demo/audit.jsonl
sudo cat /var/lib/agentgate-poc-demo/operator-events.jsonl
sudo python3 /var/lib/agentgate-poc-demo/stop.py
```

The stop command requires an idle, empty domain with no guard pins.
It revokes the POC key and removes its containers and networks. It retains the workspace, inputs, and audit.
Store audits privately; receipts include host and task details.
Run Python tests in a container with `python3 -m unittest discover -s poc/ssh-diagnostic -p 'test_*.py'`.
The `grant` tests build the native validator with `go build`; without Go they skip and say so.
Build `ssh/Dockerfile --target test` for the existing transport and bridge tests.

## Launching agents and verifying the kernel

A long-running or one-shot agent is launched by the host agent
(`agentgate-hostd`, `cmd/agentgate-hostd`), which verifies a signed job from
the service and hands it to the launch runtime (`launch.py`). The runtime runs
the agent in exactly the guarded-target path the SSH command uses: a fresh
Docker target, the BPF guard attached before anything runs, and the late-join
runner. The policy document names `"mode": "oneshot"` (1..3600 s) or
`"session"` (60..86400 s); `duration_seconds` is then the launch lifetime, the
hard cap in the kernel policy expiry and in the host (which kills the domain at
the deadline). A document without a mode is the SSH command policy and still
requires `duration_seconds: 25`.

### Launching with secrets

A launch may use credentials (a model API key, a git token) that the sandbox
never holds. The operator seals the value once on a client (`agentgate secret
set`) to the seal key the host agent publishes; the host stores it in
`/var/lib/agentgate/secrets/<target>/` (root, 0700, outside every launch mount)
and starts one `agentgate-broker` container per launch. Enable it with
`agentgate-hostd install ... --broker-image NAME@sha256:HEX` (optionally
`--broker-egress-network`, `--broker-uid`, `--broker-gid`, `--broker-pool`,
`--secret-root`); the host then advertises `brokered-secrets`.

For such a launch the service assigns a `/29` inside `172.30.0.0/16` and puts the
broker's exact endpoint in the signed policy instead of the taskboard (a
top-level field next to `dns` and `web`):

```json
"broker": {"address": "172.30.7.2", "protocol": "tcp", "port": 8443}
```

`broker` and `taskboard` are mutually exclusive (the guard allows one exact
private endpoint, compiled as the rule `broker-exact`);
`pilot-network-diagnostic network-info FILE` prints the digest, the document and
that `endpoint`. The launcher job carries a `broker` block
(`network`, `subnet`, `address`, `port`, `target_address`, `env`) that
`launch_job.py` checks against that endpoint. `launch.py` starts the target,
attaches the guard, and only then joins the target to
`agentgate-LAUNCH-broker` as `.3`; it refuses to run the agent unless the target
is on exactly its own network and the broker network. The agent receives only
base URLs such as `ANTHROPIC_BASE_URL=http://172.30.7.2:8443/anthropic`; no
secret file, store or broker configuration is mounted into the target. The
host agent starts the broker before this and stops it after the agent ends;
its counts reach the receipt as `broker_counts` and `broker_evidence`, and the
receipt's `broker` block records how the target joined. None of this has run
with a Docker daemon or on a BPF LSM kernel; see `docs/BROKER.md`.

`verify-kernel.sh --instance NAME` runs the staged kernel verification on a
disposable BPF-LSM VM: preflight, per-program BPF object load (each verifier
result reported verbatim), a validation-time check that a more-specific allow
beneath a deny is rejected, and behaviour probes through one real guarded
launch (`verify-probe.sh`). It refuses to run without the disposable-VM marker,
cleans up, and writes a JSON report the service attaches to a target to decide
`kernel_verified`. The kit never sets that flag itself.

**What the behaviour probe proves.** The probe launch mounts a writable host
folder read-write and places the guard's `read_only`, `deny`, `execute` and
`workspace` trees over subpaths of it, so the folder is physically writable and
agent-owned throughout and only the guard can deny a write, read, exec, mknod,
hard link or FIFO there. Each guard denial is a true A/B against a positive
control that the SAME mechanism allows, and every negative must fail with
EPERM/EACCES, not a generic error:

- read a world-readable file inside a `deny` tree is denied, while a sibling in
  a `read_only` tree is read;
- a write into a `read_only` tree on the writable folder is denied, while a
  write into the workspace succeeds (not EROFS from the read-only rootfs);
- exec of a real ELF (`/bin/true`) copied into a non-execute tree is denied,
  while exec of the same ELF from an `execute` tree succeeds (not ENOEXEC);
- `mknod(2)` of a plain regular file in a writable tree is denied, while
  `open(O_CREAT)` of the same file succeeds — the create A/B that exercises the
  `path_mknod` open-vs-mknod decision, needing no capability so only the guard
  denies it;
- `mkfifo`, an `AF_UNIX` pathname bind and a hard link within one filesystem are
  each denied in a writable tree (so EROFS/EXDEV cannot be the cause);
- `PTRACE_ATTACH` of a sibling is denied, observed by the attaching process;
- the broker's exact endpoint connects, while its other ports, the reachable
  network gateway `.1`, a neighbour `.4` and a non-listed DNS resolver are all
  refused with EPERM from the hooks (reachable addresses, not timeouts);
- the broker's secret path and the host's secret store never open, and a random
  canary written to that store never appears in the agent's output.

The driver then cross-checks the launch receipt's host block: every operation
the guard was meant to deny (read, write, execute, create, hardlink, ptrace)
must have recorded at least one denial, and each rendered denial path must be
container-absolute. A probe that reports EACCES while the host evidence shows no
denial for that operation — the guard silently off, the error from elsewhere —
fails the stage, as does a host-side overlay path.

**What it cannot prove.** The probe exercises the main allow/deny selectors
once each; it is not exhaustive over paths or operations. It does not cover the
socket LSM guard (none is attached), syscall filtering (none), descriptor
passing beyond the recorded stdio, or the window before the command joins the
domain. It needs the `live-mounts` capability, so it runs only on a docker-host
VM, not the appliance guest. It cannot run in the build sandbox; its logic is
unit-tested with fakes (`test_verify_kernel.py`), including a regression that
the suite reports FAIL when deny-tree enforcement is off (a fake that records no
denial) and when only `path_mknod` denies. `verify-probe.sh` is unexercised on a
kernel, and a PASS of the previous kit proved little: its negative probes all
failed for reasons unrelated to the guard (a read-only rootfs, a dropped
capability, a non-ELF file, an unroutable address), and `deny-ptrace` could
never satisfy its own expectation, so a kernel with filesystem enforcement
silently off passed.
