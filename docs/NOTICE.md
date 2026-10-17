# AgentGate Community notices

Copyright (c) 2026 Dan Metcalf.

The selected first-party Community user-space code, tests, UI and build tools use Apache-2.0.
The owner authorized this Community license migration on 17 October 2026.
The BPF source and headers retain GPL-2.0-only. Documentation retains CC-BY-4.0.
This migration leaves the separate Alloyium repository license unchanged.

COMPONENT-LICENSES.json identifies the exact source-file license scope.
DEPENDENCY-LICENSES.json records inspected Go supplier terms and binary membership.
SBOM.cdx.json records the exact Go source-check modules and npm lock inventory.
DEPENDENCY-NOTICES/ preserves supplier notices byte for byte. Those notices retain their own terms and copyright owners.
Module-root license expressions do not override notices for embedded or transitive components.

The Docker build also retains Go and npm build records, supplier notices, and runtime package records under /opt/agentgate/notices.
Its Ubuntu runtime retains distribution notices under /usr/share/doc and /usr/share/common-licenses.
Keep the corresponding source, component license texts, source manifest, BOM and supplier notices with a distributed image.

This source preview supplies no prebuilt image or production deployment. It makes no full-policy or real-agent qualification claim.
