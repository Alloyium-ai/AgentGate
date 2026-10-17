# AgentGate

A kernel-level firewall for AI agents.

Experimental software under active development. This source preview supports inspection, builds and isolated development.
It does not provide complete workload confinement or a qualified production installation.
Normal full-policy admission remains unavailable until the required behavior contracts pass for the exact target and policy.

The source includes a local policy API and browser UI, versioned policies, approval requests, basic roles, audit export and verification.
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

The web target runs the schema unit tests and the browser workspace test against owned mock responses.
The Go target runs the race suite and builds the local service and the limited node entrypoint.
The BPF target compiles the selected inspection program. Compilation does not load a kernel program or qualify its behavior.
Read [development instructions](docs/DEVELOPMENT.md) for source verification, dependency records and test prerequisites.

This preview supplies source and build recipes. It supplies no prebuilt image, public registry artifact or production deployment.
An eventual distributed image must come from reviewed CI and use an immutable registry digest.

## Architecture

The React UI calls the local Go policy service. The service stores immutable policy versions, decisions and audit records in SQLite.
Separate trust storage pins its configuration and authority. Workload signing, kernel enforcement and evidence verification have distinct responsibilities.
Read the [architecture and trust boundaries](docs/ARCHITECTURE.md) before testing these components.

## Known limits

The source contains a limited existing-file write and new IPv4 TCP inspection path, plus incomplete full-policy components.
The limited path does not provide read, executable, complete filesystem mutation, IPv6 or UDP confinement.
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
