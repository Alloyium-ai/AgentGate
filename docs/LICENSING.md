# AgentGate Community component licenses

Copyright owner for the first-party Community source: Dan Metcalf.

The first-party Community user-space code, tests, UI and build tools use Apache-2.0.
The project-owned qualification denial worker also uses Apache-2.0.
The owner authorized this Community migration on 17 October 2026.
This changes the selected Community source. It does not change the license of the separate Alloyium repository.

| Component | License and scope |
| --- | --- |
| First-party user-space source and build metadata | Apache-2.0; exact files appear in COMPONENT-LICENSES.json |
| BPF source and headers | GPL-2.0-only; preserve their notices and license text |
| Documentation | CC-BY-4.0; preserve attribution and indicate changes |
| Third-party dependencies | Their supplier terms; preserve DEPENDENCY-NOTICES and DEPENDENCY-LICENSES.json |

The top-level LICENSE contains the Apache license. LICENSE-DOCS and licenses/ contain the other component texts.
The mixed source distribution is not Apache-2.0-only. Apache terms do not replace BPF, documentation or supplier terms.

The Go dependency record binds the exact module versions, checksums, supplier notices and packaged binary membership.
Its module-root declarations retain additional embedded and transitive notices separately.
A copied upstream notice is not proof that its entire upstream repository enters a product binary.
The source BOM includes default Go build/test modules and the complete npm lock, including optional platform packages.

Community permits commercial and non-commercial use under the applicable component terms.
Paid hosting, support and separate Business features do not restrict Community license rights.
No trademark rights arise from this source license. Preserve required attribution when you refer to the source.

Read CONTRIBUTING.md before submitting changes. Mark copied or generated external material and preserve its provenance and terms.
The experimental qualification limits in docs/QUALIFICATION.md remain unchanged by this license migration.
