# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
# Build from the exported repository root. This image never loads a BPF program.
FROM golang@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS guard
ARG SOURCE_REVISION
WORKDIR /src
ENV GOMAXPROCS=2
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/pilot-network-diagnostic cmd/pilot-network-diagnostic
COPY internal internal
COPY poc/ssh-diagnostic/policy.example.json poc/ssh-diagnostic/policy.example.json
RUN printf '%s\n' "$SOURCE_REVISION" | grep -Eq '^[a-f0-9]{40}$' \
 && go test -p 2 ./cmd/pilot-network-diagnostic ./internal/dockerplacement ./internal/netrules ./internal/pocpolicy \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-X alloyium.local/kernel-poc/internal/buildinfo.SourceRevision=$SOURCE_REVISION" -o /out/pilot-network-diagnostic ./cmd/pilot-network-diagnostic
RUN mkdir -p /out/licenses && cp /usr/local/go/LICENSE /out/licenses/Go-LICENSE \
 && go version -m /out/pilot-network-diagnostic > /out/build-modules.txt \
 && go list -m -f '{{if not .Main}}{{.Path}} {{.Dir}}{{end}}' all | while read -r module directory; do \
      if [ -n "$directory" ]; then mkdir -p "/out/licenses/$module"; \
      find "$directory" -maxdepth 2 -type f \( -iname '*license*' -o -iname '*notice*' -o -iname 'copying*' \) -exec cp --parents '{}' "/out/licenses/$module/" \;; fi; done
RUN find /out/licenses -type d -exec chmod 0755 '{}' + && find /out/licenses -type f -exec chmod 0644 '{}' +
FROM ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55 AS bpf
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends clang libbpf-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY bpf bpf
RUN clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c bpf/network_policy.bpf.c -o /network_policy.bpf.o
FROM scratch AS artifacts
COPY --from=guard /out/ /
COPY --from=bpf /network_policy.bpf.o /
COPY LICENSE LICENSE-DOCS /licenses/
COPY licenses/ /licenses/
ARG SOURCE_REVISION
LABEL org.opencontainers.image.revision=$SOURCE_REVISION
