FROM node@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS web
WORKDIR /web
ENV TMPDIR=/web/build-tmp
RUN mkdir -p "$TMPDIR"
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/src src
COPY web/qa qa
COPY internal/policy/schema.v2.json /internal/policy/schema.v2.json
COPY web/index.html web/tsconfig.json ./
RUN npm run test:policy && npm run build && npx tsc --noEmit && npm audit
RUN mkdir -p /notices/web && npm ls --all --json > /notices/web/dependencies.json && find node_modules -type f \( -iname '*license*' -o -iname '*notice*' -o -iname 'copying*' \) -exec cp --parents '{}' /notices/web/ \;
RUN find /notices -type d -exec chmod 755 '{}' + && find /notices -type f -exec chmod 644 '{}' +

FROM web AS web-tests
RUN npx playwright install --with-deps chromium
RUN --network=none mkdir -p /qa-output && QA_OUTPUT=/qa-output npm run test:policy-browser

FROM golang@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS go
WORKDIR /src
ENV TMPDIR=/src/build-tmp
ENV GOMAXPROCS=2
RUN mkdir -p "$TMPDIR"
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
RUN --mount=type=cache,id=agentgate-community-go,target=/root/.cache/go-build,sharing=locked go test -race -p 2 ./... && CGO_ENABLED=0 go build -trimpath -o /agentgate ./cmd/community && CGO_ENABLED=0 go build -trimpath -o /agentgate-node ./cmd/poc
RUN mkdir -p /notices/go && go list -deps -test -f '{{with .Module}}{{if not .Main}}{{.Path}}@{{.Version}}{{end}}{{end}}' ./... | sed '/^$/d' | sort -u > /notices/go/module-ids.txt && xargs go mod download -json < /notices/go/module-ids.txt > /notices/go/downloads.json
RUN while read -r identifier; do go list -m -f '{{.Path}} {{.Version}} {{.Dir}}' "${identifier%@*}"; done < /notices/go/module-ids.txt > /notices/go/modules.txt && go version -m /agentgate /agentgate-node > /notices/go/build.txt && while read -r module version directory; do if [ -n "$directory" ]; then target="/notices/go/$module/$version"; mkdir -p "$target"; find "$directory" -type f \( -iname '*license*' -o -iname '*notice*' -o -iname 'copying*' \) -exec cp --parents '{}' "$target/" \;; fi; done < /notices/go/modules.txt
RUN cp "$(go env GOROOT)/LICENSE" /notices/go/toolchain-LICENSE
RUN find /notices -type d -exec chmod 755 '{}' + && find /notices -type f -exec chmod 644 '{}' +

FROM scratch AS source-notices
COPY --from=go /notices /notices/
COPY --from=web-tests /notices /notices/

FROM ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55 AS bpf
ENV TMPDIR=/var/cache/agentgate-build
RUN mkdir -p "$TMPDIR" && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends clang libbpf-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY bpf bpf
RUN clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c bpf/enforce.bpf.c -o /enforce.bpf.o

FROM ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55 AS runtime
ENV TMPDIR=/var/cache/agentgate-build
RUN mkdir -p "$TMPDIR" && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/* && groupadd -g 10001 agentgate && useradd -u 10001 -g 10001 -d /var/lib/agentgate -s /usr/sbin/nologin agentgate && mkdir -p /var/lib/agentgate /var/lib/agentgate-trust /var/backups/agentgate && chmod 700 /var/lib/agentgate /var/lib/agentgate-trust /var/backups/agentgate && chown 10001:10001 /var/lib/agentgate /var/lib/agentgate-trust /var/backups/agentgate
COPY --from=go /agentgate /agentgate-node /opt/agentgate/
COPY --from=web-tests /web/dist /opt/agentgate/web/
COPY --from=bpf /enforce.bpf.o /opt/agentgate/enforce.bpf.o
COPY --from=go /notices /opt/agentgate/notices/
COPY --from=web-tests /notices /opt/agentgate/notices/
COPY LICENSE LICENSE-DOCS /opt/agentgate/licenses/
COPY COMPONENT-LICENSES.json DEPENDENCY-LICENSES.json /opt/agentgate/licenses/source/
COPY licenses /opt/agentgate/licenses/
COPY docs /opt/agentgate/docs/
COPY README.md /opt/agentgate/docs/README.md
COPY compose.yaml settings.json Caddyfile /opt/agentgate/deployment/
COPY --chmod=644 SOURCE-MANIFEST.json /opt/agentgate/SOURCE-MANIFEST.json
ENV PATH=/opt/agentgate:$PATH TMPDIR=/var/lib/agentgate/data/spool
ARG SOURCE_REVISION
LABEL org.opencontainers.image.title="AgentGate experimental source preview" org.opencontainers.image.version="0.2.6-community-candidate" org.opencontainers.image.revision=$SOURCE_REVISION org.opencontainers.image.licenses="Apache-2.0 AND GPL-2.0-only AND CC-BY-4.0"
RUN mkdir -p /opt/agentgate/notices/runtime && dpkg-query -W > /opt/agentgate/notices/runtime/packages.txt && chmod -R a+rX /opt/agentgate
USER 10001:10001
EXPOSE 8930
ENTRYPOINT ["/opt/agentgate/agentgate"]
CMD ["serve"]

FROM runtime AS release
COPY SBOM.cdx.json /opt/agentgate/notices/SBOM.cdx.json
COPY --chmod=644 SOURCE-MANIFEST.json /opt/agentgate/SOURCE-MANIFEST.json
