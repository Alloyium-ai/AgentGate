# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
# Build from the repository root. The image holds only the static broker and
# the CA bundle it verifies upstreams against:
#   docker build -f cmd/agentgate-broker/Dockerfile \
#     --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" -t agentgate-broker .
# Run it with the hardened recipe in docs/BROKER.md.
FROM golang@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS build
ARG SOURCE_REVISION
WORKDIR /src
ENV GOMAXPROCS=2 CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/agentgate-broker cmd/agentgate-broker
COPY internal internal
RUN printf '%s\n' "$SOURCE_REVISION" | grep -Eq '^[a-f0-9]{40}$' \
 && go test -p 2 ./cmd/agentgate-broker ./internal/broker ./internal/secretseal \
 && go build -trimpath -ldflags "-X alloyium.local/kernel-poc/internal/buildinfo.SourceRevision=$SOURCE_REVISION" \
      -o /out/agentgate-broker ./cmd/agentgate-broker \
 && mkdir -p /out/etc/ssl/certs /out/licenses \
 && cp /etc/ssl/certs/ca-certificates.crt /out/etc/ssl/certs/ca-certificates.crt \
 && cp /usr/local/go/LICENSE /out/licenses/Go-LICENSE \
 && go version -m /out/agentgate-broker > /out/licenses/build-modules.txt \
 && chmod 0555 /out/agentgate-broker && chmod 0444 /out/etc/ssl/certs/ca-certificates.crt

FROM scratch AS broker
COPY --from=build /out/agentgate-broker /agentgate-broker
COPY --from=build /out/etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/licenses /licenses
COPY LICENSE /licenses/LICENSE
ARG SOURCE_REVISION
LABEL org.opencontainers.image.revision=$SOURCE_REVISION
# The broker starts as root only to read its root-owned config and secret
# files and bind its endpoint; it then drops to the config's run_as identity,
# with no capabilities, before it serves a request.
USER 0:0
ENTRYPOINT ["/agentgate-broker"]
CMD ["run", "/etc/agentgate/broker.json"]
