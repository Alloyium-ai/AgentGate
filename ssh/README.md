# SSH command source path

This directory contains the Community SSH ingress code. It imports only its own files and Node builtins.
Build the image from the exported Community source root with `docker build -f ssh/Dockerfile --target test .`.
The listener requires a protected managed gateway configuration, signed policy, enrolled node and authority.
It does not start a workload when admission or qualification is unavailable.

The forced command accepts noninteractive OpenSSH commands. An empty stdin, including `ssh -n`, is normal.
The authenticated sshd process and channel signals control the command lifetime. TTY and forwarding stay disabled.
The terminal returns bounded stdout and stderr with separate SHA-256 digests after the node confirms domain cleanup.
The SSH exit code follows the terminal result. The node retains the signed receipt in local audit history.

The Docker target placement, scoped taskboard identity, complete same-target qualification and admitted coding smoke remain required before MVP readiness.
The `coding-target` image includes POSIX dash, Python 3, curl, and CA certificates. It has a writable workspace for the unprivileged UID 65534. It has no C compiler or Docker socket.

For an allowed Internet hostname, provision every A or AAAA alias in the target from the node's pinned TLS resolver. The node checks the target hosts file against its live leases before release and before each map refresh. A missing or changed alias stops the job. An allowed shared IP can serve other hostnames; this pilot does not isolate HTTP or TLS hostnames on that IP.

The separate [fixed SSH coding POC](../poc/ssh-diagnostic/README.md) uses the disposable VM launcher. It does not use normal product admission.
