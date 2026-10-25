# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
ARG CODING_BASE_IMAGE=ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
FROM oven/bun@sha256:9dba1a1b43ce28c9d7931bfc4eb00feb63b0114720a0277a8f939ae4dfc9db6f AS runtime

USER root
ENV DEBIAN_FRONTEND=noninteractive AGENTGATE_SSH_CONFIG=/etc/agentgate/gateway.json
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 agentgate-ssh \
 && useradd -u 10001 -g 10001 -d /var/empty -s /bin/sh agentgate-ssh \
 && usermod -p NP agentgate-ssh \
 && mkdir -p /run/sshd /opt/agentgate /var/empty \
 && chmod 0755 /run/sshd /opt/agentgate /var/empty

COPY --chmod=0444 ssh/agentgate_gateway_policy.ts ssh/agentgate_gateway_bootstrap.ts ssh/agentgate_gateway_runtime.ts ssh/agentgate_node_trust.ts ssh/agentgate_ssh_command.mts ssh/taskboard_bridge.mts /opt/agentgate/
COPY --chmod=0444 ssh/sshd_config /etc/ssh/sshd_config
ARG SOURCE_REVISION
LABEL org.opencontainers.image.revision=$SOURCE_REVISION
EXPOSE 2222
ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config"]

FROM runtime AS test
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
COPY --chmod=0444 ssh/tests/transport.test.ts /opt/agentgate/tests/
COPY --chmod=0444 ssh/tests/taskboard_bridge.test.ts /opt/agentgate/tests/
RUN chmod 0755 /opt/agentgate/tests && bun test /opt/agentgate/tests/transport.test.ts /opt/agentgate/tests/taskboard_bridge.test.ts

FROM ${CODING_BASE_IMAGE} AS coding-target
USER root
HEALTHCHECK NONE
ARG SOURCE_REVISION
LABEL org.opencontainers.image.revision=$SOURCE_REVISION
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 dash ca-certificates curl util-linux \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/agentgate/workspace /run/agentgate/streams \
 && chmod 0711 /run/agentgate/streams \
 && chown 65534:65534 /var/lib/agentgate/workspace
USER 65534:65534
WORKDIR /var/lib/agentgate/workspace
CMD ["sleep", "infinity"]

FROM oven/bun@sha256:9dba1a1b43ce28c9d7931bfc4eb00feb63b0114720a0277a8f939ae4dfc9db6f AS taskboard-bridge
ARG SOURCE_REVISION
LABEL org.opencontainers.image.revision=$SOURCE_REVISION
USER root
WORKDIR /
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
RUN install -d -m 0755 /opt/agentgate
COPY --chmod=0444 ssh/taskboard_bridge.mts /opt/agentgate/taskboard_bridge.mts
ENTRYPOINT ["/usr/local/bin/bun", "/opt/agentgate/taskboard_bridge.mts"]
CMD []

FROM runtime AS release
