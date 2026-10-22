# AgentGate

A kernel-level firewall for AI agents.

Start with the [guarded SSH POC](poc/ssh-diagnostic/README.md) and its [editable JSON policy](poc/ssh-diagnostic/policy.example.json).
On a supported Linux Docker/KVM host, one command provisions the guarded VM and coding container:

```sh
python3 poc/ssh-diagnostic/appliance.py start --policy ./policy.json --token-file ./taskboard.token
```

The guide explains the two protected input files, ready-to-copy SSH command, persistent state, and workload base override.

It runs authenticated coding commands in a fresh Docker target with a real BPF network guard.
The default policy allows IPv4 DNS through configured resolvers, public HTTP and HTTPS, and explicit UDP443 for QUIC.
It denies other endpoints and IPv6. An independent kernel boundary blocks LAN access except the exact taskboard TCP endpoint.
The one-task bridge keeps its upstream token outside the target.

Edit the installed `policy.json` through the management connection. The next SSH command validates and applies the edit.
The audit records the effective policy digest. The POC uses JSON directly; its browser UI is separate.
The guide includes the owned VM prerequisites, Docker builds, setup, command examples, and audit instructions.

This is experimental software. The SSH POC supports a focused network flow with a 25-second command cutoff.
Filesystem, executable, and process controls are implemented for the SSH POC as an opt-in policy version, but they are not yet exercised on a BPF LSM kernel. Syscall filtering and UI approval controls remain incomplete.
Normal full-policy product admission remains closed. This does not prevent the explicitly isolated SSH POC.

The source includes a local policy API and browser UI, versioned policies, approval requests, basic roles, audit export and verification.
The `ssh/` directory includes a standalone forced-command ingress and a read-only taskboard bridge. The [guarded SSH POC](poc/ssh-diagnostic/README.md) includes portable Docker targets and per-command setup. Full product qualification remains open.
The local control service uses signed SQLite configuration. Its local authentication path needs no fleet service or vendor account.
External OIDC is optional. First-party user-space code uses Apache-2.0, BPF uses GPL-2.0-only, and documentation uses CC-BY-4.0.
Third-party dependencies retain their supplier terms. The component map records the exact license scope.

## Build and test

Use a Linux Docker environment with BuildKit. A cloud development workspace can build and test the source without kernel privileges.
The build downloads dependencies from the pinned lock files and container digests.

```sh
docker build --target web-tests -t agentgate-preview-web-tests .
docker build --target go -t agentgate-preview-go-tests .
docker build --target bpf -t agentgate-preview-bpf .
docker build -t agentgate-source-preview .
```

The web target runs the schema unit tests and the isolated browser workspace test.
The Go target runs the race suite and builds the local service and the limited node entrypoint.
The BPF target compiles the selected inspection program. Compilation does not load a kernel program or qualify its behavior.
Read [development instructions](docs/DEVELOPMENT.md) for source verification, dependency records and test prerequisites.

This preview supplies source and build recipes. It supplies no public registry artifact or production deployment.
After independent review, protected release CI builds the Community product, standalone SSH ingress, coding target and taskboard bridge images and publishes them to the private registry. Deployments must use their immutable manifest digests. An image build alone does not qualify a policy or authorize workload admission.

## Architecture

The React UI calls the local Go policy service. The service stores immutable policy versions, decisions and audit records in SQLite.
Separate trust storage pins its configuration and authority. Workload signing, kernel enforcement and evidence verification have distinct responsibilities.
Read the [architecture and trust boundaries](docs/ARCHITECTURE.md) before testing these components.

## Wider product and legacy inspection limits

The older inspection path contains a limited existing-file write and new IPv4 TCP check. It is separate from the SSH network POC.
That older path does not provide read, executable, complete filesystem mutation, IPv6 or UDP confinement.
Existing descriptors and established connections lack immediate revocation in that path.
The full-policy components do not yet satisfy every required behavior contract for general agent workloads.
This preview makes no real-agent or model-turn qualification claim.

Kernel experiments require a fresh disposable x86-64 Linux VM with BPF LSM, BTF, cgroup v2 and an explicit disposable marker.
A container or cloud editor alone does not supply those host kernel features.
The source preview build does not require privileged Docker access, a live model endpoint or provider credentials.

Historical engineering checks covered selected local UI and narrow kernel behavior on Linux6.8.
They do not qualify this source snapshot. [Qualification status](docs/QUALIFICATION.md) records that distinction.

## Source, licenses and contributions

`SOURCE-MANIFEST.json` records the public source identifier, selected file sizes and SHA256 hashes.
It contains no private repository URL, private source path or private commit history.
The detailed committed-source mapping stays in private release custody.
A generated `SBOM.cdx.json` records the locked npm and Go build/test dependency set; the build also retains dependency notices.

Read [notices](docs/NOTICE.md), [component licensing](docs/LICENSING.md), `LICENSE`, `LICENSE-DOCS` and `licenses/`.
`COMPONENT-LICENSES.json` maps every selected source file. `DEPENDENCY-LICENSES.json` binds the inspected supplier terms and notice hashes.
Report defects through this repository. Read [contribution terms](CONTRIBUTING.md) before submitting changes.
