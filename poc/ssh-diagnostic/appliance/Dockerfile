# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
FROM ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils cloud-image-utils openssh-client python3 ca-certificates curl socat && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /opt/agentgate && curl -fL --retry 3 https://cloud-images.ubuntu.com/releases/noble/release-20260926/ubuntu-24.04-server-cloudimg-amd64.img -o /opt/agentgate/noble.img && printf '6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2  /opt/agentgate/noble.img\n' | sha256sum -c - && chmod 0644 /opt/agentgate/noble.img
COPY poc/ssh-diagnostic/appliance/boot.py /opt/agentgate/boot.py
ARG SOURCE_REVISION
LABEL org.opencontainers.image.revision=$SOURCE_REVISION
ENTRYPOINT ["python3", "/opt/agentgate/boot.py"]
