# Development in Docker and cloud workspaces

Use a Linux x86-64 Docker host with BuildKit and enough storage for the pinned builders and browser dependencies.
A cloud workspace needs only the exported source, Docker access and network access for dependency download.
The build uses pinned container digests, `go.sum` and `web/package-lock.json`.
No fleet account, Redis service, model endpoint or provider credential is required for these build checks.

## Verify the source

Use the pinned Node image declared by the Dockerfile. Run the verifier in a container with the source mounted read-only:

```sh
docker run --rm --network none --read-only --user "$(id -u):$(id -g)" --cap-drop ALL   --security-opt no-new-privileges -v "$PWD:/source:ro" -w /source   node@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392   node tools/verify-source.mjs .
```

Run `node tools/licenses.mjs .` in the same pinned container to verify the exact component map, owned source headers and preserved BPF bytes.
The verifier checks the public content identifier, listed file sizes and hashes, and generated artifact hashes.
It rejects linked files and paths outside the source directory. Compare the printed identifier with the independently reviewed release identifier.
Pass that identifier as the final verifier argument to require an exact match.

## Build targets

`docker build --target web-tests .` runs both declared web QA commands after the web build and TypeScript check.
The browser test uses a local mock server inside the build step. It performs no workload or provider request.
`docker build --target go .` runs the Go race suite with bounded package parallelism and builds both public commands.
`docker build --target bpf .` compiles the selected BPF object without loading it.
A source-only export uses `docker build --target runtime .` before inventory generation.
The published preview already includes its inventory; `docker build .` packages that inventory and retains dependency notices.

## Dependency records

Export the build notices to a fresh local directory, then generate the source dependency inventory:

```sh
docker build --target source-notices --output type=local,dest=build-notices .
docker run --rm --network none --read-only --user "$(id -u):$(id -g)" --cap-drop ALL   --security-opt no-new-privileges -v "$PWD:/source" -w /source   node@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392   node tools/sbom.mjs . build-notices/notices/go/downloads.json
```

`SBOM.cdx.json` lists the Go modules used by the default build and test set and all packages in the npm lock file, including optional platform packages.
It is a source dependency inventory, not a claim about the packages linked into every binary.
The npm license fields come from the lock file. Go license expressions come from the pinned supplier evidence in DEPENDENCY-LICENSES.json.
The build verifies each reviewed module version, checksum and notice hash. It rejects an unreviewed dependency or changed supplier text.
The exact binary metadata identifies fifteen linked modules. The default source checks also compile x/net; neither packaged binary includes it.
Module-root declarations do not replace embedded component terms; inspect the retained supplier notices.
The Go record retains the verified module directory checksum. The npm record retains its declared download integrity.
The build keeps Go, npm and runtime package inventories and supplier notice files under `/opt/agentgate/notices`.
`DEPENDENCY-NOTICES/` preserves the collected supplier texts byte for byte and records their generated artifact hashes.
Keep those notices with any distributed image. A source inventory does not grant relicensing rights.

## Isolated application work

The preview image contains the local control command, browser assets and deployment examples.
The examples require durable state, trust, backup and TLS storage. The TLS example binds only to loopback.
Before any application deployment, use an independently reviewed CI image pinned by digest and protect its bootstrap input.
This source preview supplies no prebuilt image or production deployment approval.
Read the local configuration and authentication code before using the examples with real data.
