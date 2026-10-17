# Experimental source-preview status

This document describes a source preview. It does not attest a production workload, kernel target or complete confinement policy.
The public identity and exact file hashes appear in `SOURCE-MANIFEST.json`.

## Current build checks

The exported context builds without the private monorepo or fleet adapter.
Its Docker targets run Go race tests, schema unit tests, a browser workspace test with owned mock responses, TypeScript checks and npm audit.
The BPF target compiles the selected inspection object. Build results and kernel behavior evidence have separate meanings.
Some kernel tests require a marked disposable VM or explicit protected fixtures. Read the actual test output for skips and prerequisites.

Normal full-policy admission remains unavailable when any required capability lacks complete, fresh behavior evidence.
A successful build, available hook or signed report alone does not establish that evidence.
This preview provides no real-agent or model-turn qualification.

## Historical scope

Engineering notes dated14October2026 reported local login, role, policy, restart and restore checks.
They also reported a selected existing-file write and a new IPv4 TCP connection on a dedicated Linux6.8.0-142 VM.
Those notes do not provide a current public source-to-artifact attestation. They do not qualify this snapshot.
The private raw evidence and infrastructure details are excluded from this distribution.

## Remaining product work

Full filesystem, executable, descriptor, network, socket, process, memory and lifecycle contracts need exact target behavior evidence.
The full-policy report producer refuses incomplete coverage. The limited inspection path has the narrower limits stated in the README.
Existing descriptors and established connections lack immediate revocation in that limited path.
Host and node custody remain trusted. Audit signatures do not replace those trust assumptions.

Independent code, security and privacy review, exact dependency notices and provenance review precede a source release.
Production and image releases require separate supported-platform and workload acceptance.
The authorized first-party Community migration is complete: user-space source uses Apache-2.0.
BPF retains GPL-2.0-only, documentation retains CC-BY-4.0, and third-party components retain their supplier terms.
