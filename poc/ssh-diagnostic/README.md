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

This preset allows any public IPv4 web destination. It enforces protocol, address, and port, not domain or TLS names.
An allowed public IP can serve several hostnames. A domain allowlist is outside this simple preset.
Conventional HTTP uses TCP80. UDP443 permits HTTP/3; it does not supply an HTTP/3 client.

To change the installed policy, use the separate management connection:

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
  override a broader allowance. Hard links are never allowed, device nodes cannot be created, and `ioctl` is limited to five
  descriptor queries. Ancestor directories of allowed trees get an exact-path read so `stat` works.
- **Executables:** `execute` entries are the program allowlist. A writable tree may not also be executable; the policy refuses that
  overlap. A binary a command writes cannot be run.
- **Memory:** anonymous mappings may be read, written, and re-protected. Executable anonymous memory (a JIT or libffi closure)
  needs `"anonymous_execute": true`.
- **Processes:** a command may signal only its own tree, and only the listed signals. Tracing (`ptrace` attach, `PTRACE_TRACEME`) is always
  denied. Signal 0 existence probes are denied.
- **Sockets:** the filesystem component delegates socket I/O to the network guard, which is attached first. The command's stdin, stdout,
  and stderr are pipes the gateway made outside the domain; the plan allows those and no pipe from another job.

To make this possible the runner joins the cgroup last. It opens `cgroup.procs` as root, enters the target namespaces, and the
unprivileged shell writes its own PID, closes the descriptor, verifies its cgroup, and only then runs the command. A failed join exits 125
without running the command. The receipt gains a `host` block: per-operation counts, a SHA-256 over the whole raw event stream, the first
2000 denials with their paths, and loss counters. Any lost or malformed event marks the receipt incomplete. The gateway also refuses to run
unless all 23 host links are pinned, and it stops the command if one disappears.

**Verification status.** The Go planning, the shell join logic, and the evidence accounting have unit tests. The BPF objects compile
cleanly, and their kernel-named structs and fields match a current kernel's BTF. **No BPF LSM kernel was available when this was
written, so the verifier, the hooks, and the end-to-end behavior are not yet exercised.** Expect first-boot fixes. Known limits:

- The path-building hooks (`path_mknod`, `path_mkdir`, `path_unlink`, `path_rmdir`, `path_rename`, `path_symlink`) rely on `bpf_d_path`
  being allowed for those hooks. If a kernel refuses one, the object fails to load and the guard fails closed.
- There is no syscall filter. The container keeps Docker's default seccomp profile. `setxattr`/`utimes` are not path-checked.
- Every command loads and attaches the 23 hooks again; expect added start-up latency.
- Policy covers a command's tree only from the moment it joins. The trusted helpers before that run unrestricted.

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
Build `ssh/Dockerfile --target test` for the existing transport and bridge tests.
