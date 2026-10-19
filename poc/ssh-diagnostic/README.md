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
Normal product admission remains closed. Full filesystem, process, syscall, and UI approval controls remain incomplete.
The trusted bridge makes an authenticated live `GET /api/tasks/ID` for one task.
The target receives a Unix socket and four task fields. It receives no upstream bearer token.
The bridge exposes `/task` and `/auth-probe`; other paths and methods return 403.
This is a one-task read bridge. General taskboard API scope and identity remain incomplete.
An allowed IP can serve several hostnames. The guard enforces endpoints, not HTTP host or TLS names on a shared IP.

## The editable network policy

Copy [policy.example.json](policy.example.json) to `policy.json`.
Edit its taskboard address, port, and task ID before setup. The example contains no credentials.
The JSON policy controls the real BPF network guard for this SSH POC.
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
