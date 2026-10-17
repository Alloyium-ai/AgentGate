# Contributing to AgentGate Community

Discuss substantial changes in a repository issue. Submit a focused pull request with a clear problem, change and test result.

Contribute only work that you own or have permission to submit under the applicable file license.
First-party user-space contributions use Apache-2.0. BPF contributions use GPL-2.0-only. Documentation contributions use CC-BY-4.0.
Apache contributions follow section 5 of LICENSE unless you state otherwise and the maintainers accept that separate arrangement.
A contribution does not assign your copyright or change the license of upstream material.

Preserve copyright, patent, trademark and supplier notices. Identify external copied or generated source and its original license.
Update COMPONENT-LICENSES.json when you add a source file. Update the dependency evidence when you change a pinned dependency.
Keep dependency checksum and license changes reviewable. The build rejects missing evidence or changed supplier notice bytes.

Use the Docker build and source checks in docs/DEVELOPMENT.md. Include the exact checks and remaining limits in your pull request.
Run kernel experiments only in an owned disposable VM. Keep credentials, private configuration and real workload evidence out of commits.
No source change can claim production qualification without its required current-target behavior evidence.
