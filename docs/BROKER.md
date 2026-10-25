# Credential broker

An agent in the guarded sandbox can use a credential (a model API key, a git token) without the sandbox, the agent or
any code it runs ever holding the secret. A host-side broker holds the value, accepts plain HTTP requests from the
sandbox on one exact endpoint, forwards only allowed requests to an exact HTTPS upstream allowlist, adds the
credential on the way out, and records bounded evidence. The value reaches the host through a sealed relay that the
service cannot read and whose injection policy (upstreams, header, rules) it cannot change (`internal/secretseal`).

| Part | Path |
| --- | --- |
| Broker library | `internal/broker` |
| Command | `cmd/agentgate-broker` (`validate`, `run`, `version`) |
| Container image | `cmd/agentgate-broker/Dockerfile` (static binary and CA bundle on `scratch`) |
| systemd sample | `cmd/agentgate-broker/agentgate-broker@.service` |
| Sealed relay | `internal/secretseal` (host store, client pinning helper, known-answer vector) |

**Status.** The broker, the sealed relay, the policy endpoint, the host agent, the service and the launch runtime are
connected (see [Integration status](#integration-status)). The whole path, from a sealed `POST /secrets` to a launch
receipt with broker counts, runs in one in-process test with the real service, the real host agent and protocol and the
real broker against a local TLS fake upstream (test CA, fake resolver). Docker, systemd, the BPF LSM guard, real DNS and
real upstreams were **not** exercised: the host's Docker steps ran against a command recorder, the guard not at all.

## Design

```
 sandbox (target container, guarded cgroup)            broker container (per launch)             internet
 ------------------------------------------            -----------------------------             --------
 SDK: ANTHROPIC_BASE_URL=http://172.30.7.2:8443/anthropic
   POST /anthropic/v1/messages  --- plain HTTP/1.1 --->  172.30.7.2:8443 (exact bind)
   (no credential)                 per-launch            strip credentials and hop-by-hop
                                   internal network      check route, method, path, limits
                                                         resolve api.example.com itself,
                                                         refuse non-public answers,
                                                         TLS to the validated IP, SNI = name  --->  upstream
                                                         add x-api-key from a 0600 file
                                                         mask credential echoes  <------------
```

- **Per launch.** The host agent starts one broker per launch with a configuration naming that launch, its secrets,
  its endpoint and its deadline. Nothing is shared between launches: a compromised agent in one launch can reach only
  its own broker, its counters are its own, and the broker exits at the launch deadline. A per-target broker would
  need per-request launch identification, which the sandbox could forge.
- **One endpoint, several routes.** The SSH POC guard allows exactly one private TCP endpoint, so one broker serves all
  of a launch's secrets on one `address:port`. The first path segment selects the route. Each route binds exactly one
  secret to exactly one origin (`https://host:port`) and a set of method and path rules. A route's credential is only
  ever placed on that route's transport, whose dialer refuses every other host, so a request for route A never
  carries secret B and never reaches upstream B. The routing decision uses the request path only; a client-supplied
  `Host` or authority never selects a destination (it must equal the broker's own address, see below).
- **Plain HTTP inside, HTTPS outside.** The agent leg carries only the agent's own request data and travels on a
  per-launch network that holds only the target and the broker. Standard SDKs accept an `http://` base URL; none
  needs a custom CA. The credential exists only on the broker's verified TLS leg.
- **HTTP/1.1 only, one request per connection.** Inbound keep-alive is disabled, so there is no pipelining and no
  framing carried between requests. Upstream uses HTTP/1.1 with connection reuse. HTTP/2, h2c, WebSocket and other
  protocol upgrades are refused; there is no switch to enable WebSocket in v1, because frames would bypass response
  masking and size limits.
- **Vetted parser, strict pre-check.** Go `net/http` parses every request. Before it acts, a raw check of the first
  header block refuses shapes `net/http` tolerates but an intermediary must not (see the request path). Request bodies
  are read in full, bounded, before anything is sent upstream, so the upstream request always has an exact
  `Content-Length` chosen by the broker; a truncated or malformed chunked body never reaches the upstream.
- **TCP or Unix socket.** `listen.network` is `tcp` (one exact private IPv4 address and port; the SDK route) or `unix`
  (a socket on a per-launch volume, like the taskboard bridge). Unix mode needs no private-address exception in the
  SSH POC guard, whose network hooks do not see `AF_UNIX`, but SDK base URLs cannot name a socket, so it suits only
  clients such as `curl --unix-socket`. The guard denies loopback, so an in-sandbox TCP-to-socket relay is not an
  option.

## Threat model

Assets: the secret value; the upstream account it unlocks; the host and its private networks; the evidence.

| Adversary | Can | Broker answer |
| --- | --- | --- |
| Compromised agent or any code in the sandbox | send any bytes to the broker endpoint | it never receives the value; requests outside the route rules, to other hosts, with other framing or upgrades are refused and counted |
| Same, aiming at SSRF | ask for other hosts, absolute-form URLs, `CONNECT`, a crafted `Host`, encoded paths, redirects to metadata services | destinations come only from configuration; names are resolved by the broker and every address is classified; redirects are returned, never followed |
| Same, aiming at the credential | ask the upstream to echo it, read error bodies, read stats | response headers that carry a credential form are dropped, bodies are masked; broker errors and stats hold only fixed codes and counts |
| DNS attacker or rebinding upstream name | answer with private or loopback addresses, or change answers between lookups | a whole answer is refused if any address is not public; every new connection re-resolves after a bounded cache; the dial and a socket-level hook both re-check the address |
| Malicious upstream response | huge or endless bodies, slow streams, `Content-Encoding` that defeats masking, protocol switches, cookies | size, idle and total limits; encoded bodies and `101` are refused; `Set-Cookie`, `Alt-Svc` and hop-by-hop headers are dropped |
| Malicious or compromised service (relay), or anyone who can write its database or sign its jobs | substitute the host's seal key, replace or replay ciphertext, or change a secret's upstreams, header, scheme, rules or headers at creation or later, to send the credential elsewhere or use it more widely | the seal key is signed by the host's pinned Ed25519 key; the envelope binds target, name, version, nonce and the digest of the injection policy the operator chose; the host stores that policy with the value, refuses a secret-put whose settings differ from it and a launch whose settings differ from it, and builds every broker from its stored policy; replays and rollbacks are refused; a substituted ciphertext or policy cannot produce a receipt the client accepts. It can still decide which approved launches to queue, deny service, and show a plan that a client does not check against the sealed digest (the CLI and the web UI check it and refuse to approve on a mismatch) |
| Another launch on the same host | reach this broker | it is on a different per-launch network and its guard allows only its own broker endpoint |
| Local user on the host | read process memory or a core dump | the broker is non-dumpable, `RLIMIT_CORE=0`, runs as its own uid, and keeps the value in a locked, `MADV_DONTDUMP` mapping outside the Go heap |

Out of scope: a compromised host kernel, root on the host, or the upstream itself misusing a credential.

## Request path

Every step refuses with a fixed reason code (JSON body `{"error":"agentgate_broker","reason":...}`) and counts it.

1. **Connection limit.** Connections beyond `max_connections` are closed at once (`rejected_over_limit`).
2. **Raw header check** (first header block, byte by byte, any read split): request line `METHOD SP target SP
   HTTP/1.1` only; CRLF line endings only (bare LF or CR refused); no obs-fold continuation; header names are tokens;
   values are visible ASCII or tab (no NUL, DEL or non-ASCII); exactly one `Host`; at most one `Content-Length`,
   digits only; `Transfer-Encoding` at most once and exactly `chunked`; never both; `max_header_count` and
   `max_header_bytes`. `net/http` then parses the same bytes with `MaxHeaderBytes` and `ReadHeaderTimeout`.
3. **Rate limit**: a token bucket of `requests_per_minute` and `burst` for the whole launch.
4. **Shape**: HTTP/1.1; not `CONNECT`; origin form only (no absolute form, no `*`); `Host` exactly the broker's
   authority (`172.30.7.2:8443`, or `listen.authority` in unix mode); no `Upgrade`, `Connection: upgrade` or
   `HTTP2-Settings`; no request trailers.
5. **Path**: at most 2048 bytes of ASCII RFC 3986 path characters. Refused, so that no upstream normalization can turn
   an allowed path into another one: path parameters (`;` anywhere, literal or `%3B`: Tomcat, Jetty and several proxies
   strip `;...` and read `..;` as `..`); any byte outside ASCII, literal or percent-encoded (`%80`..`%FF`, so fullwidth
   and other look-alike dots that an NFKC-normalizing upstream folds into `.`, and overlong UTF-8 forms of `.` and `/`,
   never pass); percent-encoding that produces `/`, `\`, `.`, `%`, `?`, `#` or a control byte; dot-only segments (`.`,
   `..`, `...`); segments that end in `.` or start or end with a space (servers that trim them turn `.. ` into `..`);
   empty segments except one trailing slash. The rules match the decoded path, and the broker forwards exactly that path
   in one canonical encoding (path characters literally, every other byte as an upper-case `%XX`), never the agent's own
   spelling. The query is forwarded verbatim if it is visible ASCII without `#`.
6. **Route and rules**: the first segment names a route; the rest must match a rule (`exact`, or `prefix` on a segment
   boundary) whose methods include the request method. Methods are `GET HEAD POST PUT PATCH DELETE OPTIONS`; `CONNECT`
   and `TRACE` cannot be configured.
7. **Concurrency**: at most `max_concurrent_requests` in flight (`503`).
8. **Body**: read in full within `body_timeout_seconds`, at most `max_request_bytes` (`413`). Invalid chunking or a
   truncated body is `400`; the upstream sees nothing.
9. **Forward**: only allowlisted request headers are copied (below); the credential and extra headers are injected;
   `Accept-Encoding: identity` is set; `Content-Length` is the length of the buffered body; the URL is
   `https://host[:port]` + `base_path` + the canonical route-relative path.

Request headers are forwarded by allowlist (`internal/broker/headers.go`); every other header is dropped, so the next
override-style header an upstream invents is safe by default:

- **Route default** (every route): `Accept`, `Content-Type`, `User-Agent`, `Idempotency-Key`, and the families
  `anthropic-*` (`anthropic-version`, `anthropic-beta`), `openai-*` (`openai-organization`, `openai-project`) and
  `x-stainless-*` (the client metadata of the model-API SDKs). This is the header set of the Anthropic and OpenAI SDKs;
  `TestModelSDKHeadersPassTheRouteDefault` sends it through a route.
- **`forward_headers`** (per route, default empty): up to 16 further exact names, for example `git-protocol` or
  `x-github-api-version`.
- **Never forwarded**, even when a route lists it (the configuration is refused): hop-by-hop (`Connection` and every
  header it lists, `Keep-Alive`, `Proxy-Connection`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`,
  `HTTP2-Settings`); credentials (`Authorization`, `Proxy-Authorization`, `X-Api-Key`, `Api-Key`, `X-Goog-Api-Key`,
  `Private-Token`, `X-Auth-Token`, `Authentication`, `Cookie`, `Cookie2`, and any name containing `Authorization`,
  `Token`, `Secret`, `Password`, `Cookie`, `Session`, `Credential`, `Api-Key`, `Apikey`, `Access-Key` or
  `Signature`); method and URL overrides (`X-HTTP-Method-Override`, `X-HTTP-Method*`, `X-Method-Override`,
  `X-Original-*` such as `X-Original-URL`, `X-Rewrite-*` such as `X-Rewrite-URL`, `X-Override-*`,
  `X-Forwarded-Method`, `X-Forwarded-Uri`, `X-Forwarded-Path`): an upstream that honours one would act on a method or
  path the rules never matched; client identity and forwarding (`Forwarded`, `Via`, `X-Forwarded-*`, `X-Real-Ip`,
  `X-Client-Ip`, `True-Client-Ip`, `Cf-Connecting-Ip`, `Fastly-Client-Ip`, `X-Cluster-Client-Ip`,
  `X-Original-Forwarded-For`, every `Proxy-*`); `Range` and `If-Range` (a partial response could show part of a
  response the masking never sees whole); `Sec-*`; and framing owned by the broker (`Host`, `Content-Length`,
  `Expect`, `Accept-Encoding`, `Content-Encoding`). The route's credential header and its extra header names are
  always the broker's own values. Without a client `User-Agent`, none is sent.

## Upstream connections and SSRF

The broker resolves the configured name itself (`net.Resolver`, the container's resolver), never trusts a cached
answer longer than `dns_cache_seconds` (default 30, `0` resolves for every connection), and refuses the **whole**
answer if any address is not acceptable. It then dials the validated address (IPv4 first) with TLS `ServerName` and
`Host` set to the configured name. The socket's `Control` hook re-checks the exact address handed to `connect(2)`.
Each new connection repeats all of this; a reused connection stays on its validated address. The transport ignores
`HTTP(S)_PROXY`, never follows redirects, and only ever dials its own route's `host:port`.

Refused addresses (`ClassifyAddress`):

| Family | Ranges |
| --- | --- |
| IPv4 | `0/8`, `10/8`, `100.64/10` (CGNAT), `127/8`, `169.254/16` (link-local and `169.254.169.254` metadata), `172.16/12`, `192.0.0/24`, `192.0.2/24`, `192.31.196/24`, `192.52.193/24`, `192.88.99/24`, `192.168/16`, `192.175.48/24`, `198.18/15`, `198.51.100/24`, `203.0.113/24`, `224/4`, `240/4` |
| IPv6 | everything outside `2000::/3` except NAT64 below (so `::`, `::1`, `::/96` IPv4-compatible, `100::/64`, `fc00::/7` ULA, `fe80::/10`, `fec0::/10`, `ff00::/8`, `5f00::/16`, `64:ff9b:1::/48`); `2001::/23` (Teredo, benchmarking, ORCHID, AMT, AS112); `2001:db8::/32`; `2002::/16` (6to4, every form); `3fff::/20`; `2620:4f:8000::/48` |
| Embedded IPv4 | `::ffff:a.b.c.d` is judged and dialed as `a.b.c.d`; `64:ff9b::/96` is allowed only if the embedded address is public |
| Local | the broker network (`listen.subnet`) and every address on the broker's own interfaces; zoned addresses |

**Private by design.** An upstream that is meant to be private (an internal git server) sets
`upstream.private_addresses` to at most four exact canonical RFC 1918 or ULA addresses. Every resolved address must
then be one of them and nothing else is accepted; loopback, link-local, metadata, the broker network and the host's
own addresses stay refused. It still needs a certificate trusted by the system roots (see limits).

**TLS.** Verification is mandatory against the system roots (the image ships the build stage's CA bundle), TLS 1.2 or
later, ALPN `http/1.1`. `pin_spki_sha256` optionally lists base64 SHA-256 digests of a `SubjectPublicKeyInfo`; a
verified chain must contain one (pin an intermediate or root key to survive leaf rotation).

## Responses

- Status `101` and any `Content-Encoding` other than identity are refused (`502`), because masking needs the plain
  body. A declared `Content-Length` over `max_response_bytes` is refused before any byte is sent.
- Dropped headers: hop-by-hop (and those `Connection` lists), `Set-Cookie`, `Set-Cookie2`, `Alt-Svc`, `Trailer`, and
  any header whose value contains a credential form. Trailers are never forwarded.
- `Location` is returned verbatim and never followed. An absolute `https` redirect to the route's own origin inside
  `base_path` is rewritten to the broker route so the client follows it through the broker.
- The body is streamed and flushed after every write, so Server-Sent Events arrive at once. The credential's raw value
  and its unpadded standard and URL base64 forms (and of `username:value` for Basic) are masked with a same-length
  run of `*`, even across reads. Only the tail that could still begin a match is held back, so event boundaries are
  not delayed.
- Limits during the stream: `max_response_bytes`, `stream_idle_timeout_seconds` between upstream reads,
  `write_timeout_seconds` per client write, `request_timeout_seconds` in total, and the launch deadline. A failure
  after the status line aborts the connection, so a truncated body is never presented as complete.

## Configuration reference (`agentgate.broker.v2`)

One JSON object, at most 64 KiB, root-owned (or owned by the broker user), regular, not a symlink, not group or world
writable. Unknown fields, duplicate keys, keys that are not lowercase, `null`, trailing data and nesting beyond 16
levels are refused. Errors name the field and never echo a value. The file never contains a secret.

```json
{
  "version": "agentgate.broker.v2",
  "launch_id": "lch-0001",
  "target_id": "local",
  "deadline": "2026-10-24T21:00:00Z",
  "listen": {"network": "tcp", "address": "172.30.7.2", "port": 8443, "subnet": "172.30.7.0/29"},
  "stats_path": "/var/lib/agentgate/broker/stats.json",
  "run_as": {"uid": 10002, "gid": 10002},
  "limits": {"max_request_bytes": 33554432, "max_concurrent_requests": 8},
  "routes": [
    {
      "name": "anthropic",
      "upstream": {"host": "api.anthropic.com", "port": 443},
      "credential": {"secret_file": "/run/agentgate/secrets/anthropic", "header": "x-api-key"},
      "rules": [
        {"methods": ["POST"], "path": "/v1/messages", "match": "prefix"},
        {"methods": ["GET"], "path": "/v1/models", "match": "prefix"}
      ]
    },
    {
      "name": "github",
      "upstream": {"host": "github.com"},
      "credential": {"secret_file": "/run/agentgate/secrets/github", "header": "authorization",
                     "scheme": "Basic", "username": "x-access-token"},
      "rules": [{"methods": ["GET", "POST"], "path": "/example-org/app.git", "match": "prefix"}]
    }
  ]
}
```

| Field | Rule |
| --- | --- |
| `version` | `agentgate.broker.v2` (version 2 forwards request headers by allowlist and refuses path parameters and non-ASCII paths; a version 1 configuration is refused) |
| `launch_id`, `target_id` | `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` |
| `deadline` | RFC 3339; more than 1 s and at most 24 h 10 min in the future; the broker exits at it |
| `listen` (tcp) | `address`: canonical RFC 1918 IPv4, not the network or broadcast address; `port` 1024..65535; `subnet`: canonical `/16`..`/30` inside one RFC 1918 range containing `address`. At start, exactly one up, non-loopback interface must hold `address/prefix`; the broker binds that exact address and port, never a wildcard |
| `listen` (unix) | `path`: clean absolute, at most 100 bytes, must not exist, in a directory owned by the broker user and not group or world writable; `socket_gid`; `authority` (expected `Host`, default `agentgate-broker`). The socket is mode 0660 |
| `stats_path` | clean absolute path ending in `.json`; its directory must be writable by `run_as` |
| `run_as` | non-zero `uid` and `gid`. Started as root, the broker drops to them; started unprivileged, it must already run as them. It never serves as root |
| `routes` | 1..16, unique `name` `^[a-z0-9][a-z0-9-]{0,39}$` |
| `upstream.host` | lowercase DNS name with at least two labels, not an address literal, not numeric-final, not `localhost` or under `.localhost .local .internal .home.arpa .arpa .onion .invalid .lan .intranet .corp .private` |
| `upstream.port` | default 443 |
| `upstream.base_path` | empty or `/seg[/seg...]` without a trailing slash or dot segments; prefixed to every forwarded path |
| `upstream.pin_spki_sha256` | up to 8 base64 SHA-256 digests |
| `upstream.private_addresses` | up to 4 exact RFC 1918 or ULA addresses outside the broker network; see SSRF |
| `credential.secret_file` / `secret_fd` | exactly one. File: regular, one link, owner root or the broker user, no group or other access, opened without following any symlink (`openat2` `RESOLVE_NO_SYMLINKS`), unchanged between `fstat` calls. Descriptor 3..1023: a regular file or memfd with the same ownership rules (a memfd must be `fchmod` 0600), or a pipe whose writer closes within 5 seconds. The value is 8..8192 bytes of visible ASCII; one trailing newline is removed. A file may back several routes; a descriptor only one |
| `credential.header` | a token header name, never a framing, hop-by-hop, cookie, proxy or forwarding header |
| `credential.scheme` | `""` (the raw value), `Bearer` or `Basic` (both need `authorization`; Basic needs `username`, visible ASCII without `:`) |
| `credential.extra_headers` | up to 8 non-secret headers (for example an API version), 1..256 printable ASCII characters; they replace any client value |
| `rules` | 1..64 of `{methods, path, match}`; `path` canonical (no percent-encoding, no `;`, no dot-only segment or segment ending in `.`); `match` `exact` or `prefix` |
| `forward_headers` | optional, up to 16 unique token header names forwarded in addition to the route default; never a header from the never-forwarded set, nor the credential header or an extra header |

Limits (all optional; the default applies when absent):

| Limit | Default | Range |
| --- | --- | --- |
| `max_connections` | 32 | 1..1024 |
| `max_concurrent_requests` | 16 | 1..`max_connections` |
| `requests_per_minute`, `burst` | 600, 60 | 1..60000, 1..10000 |
| `max_request_bytes` | 16 MiB | 1 KiB..256 MiB; times `max_concurrent_requests` at most 1 GiB (bodies are buffered) |
| `max_response_bytes` | 256 MiB | 1 KiB..4 GiB |
| `max_header_bytes`, `max_header_count` | 32 KiB, 64 | 4..256 KiB, 8..256 |
| `header_timeout_seconds` | 10 | 1..60 (also the idle bound of a silent connection) |
| `body_timeout_seconds` | 60 | 1..3600 |
| `upstream_header_timeout_seconds` | 300 | 1..3600 |
| `stream_idle_timeout_seconds` | 120 | 1..3600 |
| `request_timeout_seconds` | 900 | 1..86400 |
| `write_timeout_seconds` | 30 | 1..600 |
| `connect_timeout_seconds` | 10 | 1..60 |
| `max_upstream_connections` | 16 | 1..256 per route |
| `dns_cache_seconds` | 30 | 0..300 |
| `shutdown_grace_seconds` | 5 | 0..60 (signal only; never past the deadline) |
| `stats_interval_seconds` | 5 | 1..300 |
| `max_denial_records` | 64 | 0..256 |

Agent base URLs: `http://ADDRESS:PORT/ROUTE` (`broker.BaseURL`). SDKs append their own paths, so
`ANTHROPIC_BASE_URL=http://172.30.7.2:8443/anthropic` reaches `/v1/messages`, an OpenAI-style client takes
`.../openai/v1`, and git uses `git clone http://172.30.7.2:8443/github/example-org/app.git`.

## Commands

```
agentgate-broker validate [--skip-secrets] CONFIG   print a JSON summary with each route's base_url
agentgate-broker run [--config-sha256 HEX] CONFIG   serve until the deadline or SIGTERM/SIGINT
agentgate-broker version
```

`validate` checks custody, the schema and (unless `--skip-secrets`) every secret file, then wipes the values. It
prints `{ok, config_sha256, launch_id, target_id, listen, deadline, routes: [{name, base_url, upstream, rules}],
secrets_checked}` or `{ok: false, error}`. `run` order: harden the process (refuse if core dumps cannot be disabled);
read the config (and compare `--config-sha256`); load every secret; prove and bind the endpoint; drop to `run_as`;
harden again (a uid change resets the dumpable flag); write stats `state: running`; serve.

| Exit | Meaning |
| --- | --- |
| 0 | stopped at the deadline or on a signal, final stats written |
| 1 | stopped with an error (including a stats write failure) |
| 2 | configuration refused (custody, schema, digest, deadline) |
| 3 | secret custody or value refused |
| 4 | listen endpoint refused (not the launch's broker address, or cannot bind exactly) |
| 5 | identity or hardening refused |
| 64 | usage |

The broker writes only fixed lines to stderr (`agentgate-broker: running routes=N`, `stopped reason=...`, and refusal
messages that name a field or route). It never logs a header, query, body, address of a client or the secret.

## Evidence: the stats document

The broker atomically replaces `stats_path` (mode 0600) every `stats_interval_seconds` and on exit. The host agent
parses it with `broker.ParseStats` (strict, at most 1 MiB), checks `launch_id`, `target_id`, `config_sha256` and
`listen` against the configuration it wrote, fills `hostproto.Receipt.BrokerCounts` with `broker.BrokerCounts`, and
folds the document into `Receipt.BrokerEvidence` (counts and fixed codes only). The stats file, with its denial records, is removed with the container; the host
keeps the summary in `STATE/brokers/<launch>/evidence.json`.

```json
{
  "version": "agentgate.broker-stats.v1",
  "launch_id": "lch-0001",
  "target_id": "local",
  "config_sha256": "<sha256 of the exact config bytes>",
  "listen": "tcp:172.30.7.2:8443",
  "started_at": "2026-10-24T20:00:00.104Z",
  "updated_at": "2026-10-24T21:00:00.002Z",
  "deadline": "2026-10-24T21:00:00Z",
  "state": "stopped",
  "stop_reason": "deadline",
  "complete": true,
  "hardening": {"uid": 10002, "gid": 10002, "not_dumpable": true, "core_limit_zero": true, "no_new_privs": true,
                "no_effective_capabilities": true, "secret_memory_locked": true},
  "connections": {"accepted": 42, "rejected_over_limit": 0},
  "requests": {"total": 42, "denied": 2, "forwarded": 40},
  "denied": {"path_not_allowed": 1, "host_mismatch": 1},
  "routes": {
    "anthropic": {"upstream": "api.anthropic.com:443", "requests": 41, "forwarded": 40,
                  "status": {"2xx": 39, "4xx": 1}, "errors": {}, "bytes_in": 81234, "bytes_out": 912345, "redactions": 0}
  },
  "denials": [{"at": "2026-10-24T20:10:00.5Z", "reason": "path_not_allowed", "method": "POST",
               "host": "172.30.7.2:8443", "path": "/anthropic/v1"}],
  "denials_truncated": false
}
```

- `state` is `starting`, `running` or `stopped`; `stop_reason` is `deadline`, `signal` or `error`; `complete` is true
  only when every handler returned and the server stopped cleanly.
- `denied` keys are fixed reason codes (the raw header reasons, `absolute_form`, `connect_method`,
  `method_not_allowed`, `host_mismatch`, `upgrade`, `path_invalid`, `query_invalid`, `route_unknown`,
  `path_not_allowed`, `rate_limited`, `concurrency_limit`, `request_too_large`, `body_invalid`, `body_timeout`,
  `shutting_down`, `request_trailer`, `internal_error`).
- Route `errors` keys: `resolve`, `address_denied`, `connect`, `tls`, `timeout`, `response_too_large`,
  `response_encoded`, `response_protocol_switch`, `stream_idle_timeout`, `client_write`, `aborted`, `other`.
- `bytes_in` counts request body bytes sent upstream; `bytes_out` counts response body bytes returned.
- `denials` holds the first `max_denial_records`: time, reason, a method from the fixed list (else `OTHER`), the
  sanitized `Host` (else `invalid`), and at most the first two path segments with unsafe characters replaced. Never a
  query, header or body.
- Requests that `net/http` itself rejects before the handler (for example a request line it cannot parse) are not
  counted.

## Process hardening

- `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` before any file is read, again after the identity change; `no_new_privs` on
  every thread (`AllThreadsSyscall`, release builds are `CGO_ENABLED=0`).
- Root only to read root-owned files and bind; then the capability bounding set is dropped where `CAP_SETPCAP`
  allows, supplementary groups are cleared, `setresgid`/`setresuid` apply to every thread, and the broker verifies it
  cannot regain uid 0 and holds no effective or permitted capability.
- Each secret is read straight into an anonymous private mapping (locked with `mlock` where `RLIMIT_MEMLOCK` allows,
  `MADV_DONTDUMP`, `MADV_WIPEONFORK`) outside the Go heap. The injected header value and the masking forms are built
  in a second exactly sized mapping; the scratch mapping is zeroed and unmapped. Arenas are zeroed when the broker
  stops. The value never enters argv, the environment, an error, a log line, the stats or a panic message.

Hardened container: the commands `agentgate-hostd` runs (`internal/hostd.DockerBroker`; `IMAGE` is the
digest-pinned image from `--broker-image`, `STATE` the host agent's state directory, default
`/var/lib/agentgate-hostd`, `SECRETS` the secret root, default `/var/lib/agentgate/secrets`):

```sh
L=<launch id>; NET=agentgate-$L-broker; D=$STATE/brokers/$L
# refused first if 172.30.7.0/29 overlaps any Docker network or any host address
docker network create --internal --driver bridge --subnet 172.30.7.0/29 --gateway 172.30.7.1 \
  --label agentgate.launch=$L --label agentgate.role=broker-network "$NET"
docker create --name "$NET" --network "$NET" --ip 172.30.7.2 \
  --read-only --cap-drop ALL --cap-add SETUID --cap-add SETGID --security-opt no-new-privileges \
  --ulimit core=0 --memory 256m --pids-limit 64 --cpus 1 --restart no --pull never \
  --label agentgate.launch=$L --label agentgate.role=broker \
  --mount type=bind,source=$D/broker.json,target=/etc/agentgate/broker.json,readonly \
  --mount type=bind,source=$SECRETS/<target>/anthropic,target=/run/agentgate/secrets/anthropic,readonly \
  --mount type=bind,source=$D/stats,target=/var/lib/agentgate/broker \
  "$IMAGE" run --config-sha256 <sha256 of broker.json> /etc/agentgate/broker.json
docker network connect agentgate-egress "$NET"   # the broker's own route to the internet (--broker-egress-network)
docker start "$NET"
# launch.py, after the guard is attached: the target joins the broker network as .3
docker network connect --ip 172.30.7.3 "$NET" <target container>
# stop: docker stop --time 5; rm --force --volumes; network rm; then inspect proves both are gone
```

`$D` is 0700 and root-owned, `broker.json` is created exclusively with mode 0600, and `$D/stats` (0700) is owned by
the broker's uid and gid (`--broker-uid`, `--broker-gid`, default 10002). The broker container never mounts the Docker
socket, the whole secret store or anything of the target; it mounts exactly the store files of the launch's secrets.
The target never mounts a secret file, the store, the configuration or the stats. Docker user-namespace remapping changes file ownership inside the container; the custody checks
then refuse root-owned files, so a remapped host must own the config and secret files by the remapped root uid. For a host without Docker, see the systemd sample (not exercised here).

## Sealed relay for `secret-put` (`internal/secretseal`)

1. **Host seal key.** The host builds an X25519 key (`GenerateHostKey`, or `HostKeyFromECDH` from the encryption key
   `agentgate-hostd` already holds) and a `SignedKeyRecord`: `{format, target_id, key_id, suite, public_key,
   not_before, not_after, host_key}` signed with the host's enrolled Ed25519 key over a length-prefixed encoding.
   `host_key` is `HostKeyFingerprint(ed25519 public key)` (`SHA256:` and unpadded base64). Lifetime at most 90 days.
2. **Client check.** `VerifyKeyRecord(record, hostPub, pinnedFingerprint, targetID, now)` requires the fingerprint the
   operator pinned out of band (`KnownTargets`, a 0600 file; trust on first use only when the caller asks, never
   replacing a different pin), a valid signature, the right target, suite and validity window. A service that
   substitutes its own key fails here.
3. **Injection policy.** Before it seals, the client computes the secret's injection policy
   (`hostproto.SecretPolicy`, format `agentgate.secret-policy.v1`) from what the operator chose: the upstreams (each
   with an explicit port, 443 by default), the header (lower case), the scheme (Bearer for an Authorization header
   without one) and Basic user name, the extra headers (lower-case names, sorted), the forwarded request headers
   (lower case, sorted), the rules (methods in `GET HEAD POST PUT PATCH DELETE OPTIONS` order) and the wildcard flag.
   Its canonical encoding is nested length-prefixed fields (big-endian uint32 lengths):
   `lp(format, lp(lp(host, port, base_path, lp(private_address...))...), header, scheme, username,
   lp(lp(name, value)...), lp(forward...), lp(lp(lp(method...), path, match)...), "true"|"false")`, and
   `policy_digest` is its hex SHA-256. Two spellings of one policy (`host` and `host:443`, `Authorization` and
   `authorization`) give one digest; anything ambiguous (a duplicate after normalizing) is refused.
   `internal/hostproto/testdata/secret-policy-vectors.json` (copied to `web/qa/fixtures`) pins the encoding for every
   implementation, including the refusals.
4. **Seal.** `Seal(pub, targetID, name, policyDigest, value)`: RFC 9180 HPKE base mode, DHKEM(X25519, HKDF-SHA256),
   HKDF-SHA256, ChaCha20-Poly1305 (`crypto/hpke` in the Go standard library; no new dependency). The HPKE info binds
   the format, suite, key id and target. The associated data binds format (`agentgate.secretseal.v2`), suite, target
   id, secret name, version (sealing time in Unix milliseconds), a fresh 128-bit nonce and the policy digest. The
   envelope `{format, target_id, name, version, key_id, nonce, policy_digest, sealed}` holds only ciphertext and public
   context; `Envelope.Encode()` is its string wire form.
5. **Host.** The secret-put job carries the policy's settings. The host computes their digest and refuses the job
   (`invalid_job`, or `policy_mismatch` from `agentgate-hostd`) unless it equals both the job's `policy_digest` and the
   envelope's; the AEAD then opens only with the digest the client sealed (`envelope_unauthenticated` otherwise).
   `Store.Accept(key, envelope, now)` (directory owned by the host agent, mode 0700, under a lock) refuses a
   different target or key id, a version not newer than the stored one (replay and rollback), an envelope sealed more
   than 24 hours ago or more than 5 minutes in the future, and a value that `Store.Validate` rejects (set it to
   `broker.ValidSecret`). It writes the value to `DIR/NAME` (0600, temporary file, fsync, rename, directory fsync) and
   `DIR/NAME.meta.json` (version, nonce, fingerprint, policy digest; no value). The host agent keeps the policy itself
   with the secret's binding (`secret-bindings.json`) and, at launch, refuses a secret whose stored policy does not
   reproduce the digest both the binding and the store record hold.
6. **Receipt.** `{format, target_id, name, version, key_id, nonce, policy_digest, fingerprint, tag}`. The fingerprint is
   `sfp1_` + the first 128 bits of HMAC-SHA256 under a random 32-byte key kept only in the host store, over the target,
   name and value: without that key a fingerprint reveals nothing, so a short or guessable secret cannot be brute
   forced from it, and the same value on the same host always shows the same fingerprint, so a change is visible. The
   tag is HMAC-SHA256 keyed by the HPKE exporter secret, which only the sealing client and the host share. The client
   runs `Sealed.VerifyReceipt`; a relay that swapped the ciphertext for one of its own (even with the same public
   context) cannot produce a tag the client accepts, and a receipt that names another policy fails too.
7. **Launch.** The service plans a launch only for a secret whose stored settings make its sealed digest and whose
   receipt names it (`secret_policy_mismatch` otherwise), shows the digest in the plan, and queues the launch only if
   the secret still holds the planned digest. The launch job carries the settings and the digest; the host refuses the
   launch (`secret_unavailable`, "the launch's broker settings differ from the policy sealed with the stored value")
   unless both equal its stored policy, and builds the broker configuration from its stored policy, never from the
   job's copy. Changing a secret's policy means sealing the value again: delete the secret and store it with a new
   envelope; the old envelope is refused under new settings (`policy_mismatch`) and, under its own, as a replay.

`testdata/vector-v2.json` is a known-answer vector (fixed keys, policy, envelope, fingerprint and receipt;
`AGENTGATE_SECRETSEAL_WRITE_VECTOR=1` rewrites it). Envelopes and receipts of format v1, which bound no policy, are
refused everywhere, and a secret stored with one must be stored again. Comparisons of
tags use `hmac.Equal`. Plaintext and exporter secrets are cleared after use; Go cannot guarantee that no transient
copy remains.

## Integration status

<a id="integration-requests"></a>Each earlier integration request is listed with what now implements it. "Connected"
means implemented and exercised by tests in the build sandbox; nothing below ran on Docker or a BPF LSM kernel.

### Connected

**Policy (`internal/pocpolicy`; no BPF change).** `pocpolicy.Document` has `broker: {address, protocol: "tcp", port}`,
validated like `taskboard` (canonical RFC 1918 IPv4, not loopback, link-local or `169.254.169.254`, TCP, port
1024..65535) and mutually exclusive with it: a document with both is refused (`... not both`), because the pilot guard
holds one exact private endpoint. `Compile` fills `pilot_mode 1`, `pilot_family`, `pilot_port` and `pilot_address` from
whichever is present and adds the exact allow rule `broker-exact` (or `taskboard-exact`): `/32`, TCP, that port. The
policy digest covers the endpoint. Documents without `broker` encode and digest exactly as before (pinned in
`broker_test.go`). `ForLaunch` keeps a broker, `WithBroker(address, port)` replaces the taskboard with the broker, and
`Shorten` narrows a signed launch document's lifetime without changing anything else.

**Seal key publication.** `agentgate-hostd` derives its seal key with `secretseal.HostKeyFromECDH(target, enrollment
X25519 key, enrolled Ed25519 key, now, 30 days)` and re-signs it when less than 7 days remain (the key id depends only
on the public key, so re-signing never invalidates an envelope). Every poll heartbeat carries the record
(`heartbeat.seal_key`, at most 4 KiB). The service verifies it against the target's approved host key, stores it
verbatim (`target.seal_key.published`; a record that does not verify is kept out and audited as
`target.seal_key.rejected`), clears it on re-enrollment, and serves `GET /api/v1/targets/{id}/seal-key`:
`{target_id, host_key_id, host_public_key, host_key_fingerprint, seal_key_id, not_after, record}`. It never re-signs.

**Envelope format.** `SecretPutPayload.ciphertext` is `secretseal.Envelope.Encode()`; `hostproto.DecodeSealed`,
`ParseSealed` and `CheckSealed` accept only that envelope in its canonical encoding, and `ciphertext_sha256` is the
SHA-256 of the decoded envelope bytes. `hostproto.SealSecret`, `OpenSecret` and `SecretAAD` are removed, so no new
secret can use the old format. `CreateSecret` requires the envelope's target and name to equal the secret's, and its
key id to equal the seal key the target publishes (`seal_key_changed` otherwise).

**Injection rules.** Secret metadata, `LaunchSecret` and the plan carry `scheme` (`""`, `Bearer`, `Basic`; an empty
scheme for `authorization` is stored as `Bearer`), `username`, `rules` (`[{methods, path, match}]`) and
`extra_headers`. The service validates them with `hostproto.CheckInjection` and then with `broker.BuildLaunchConfig` on
a synthetic launch, so a secret the broker would refuse is refused when it is created. **Deny by default:** a secret
without rules may be stored (older clients), but every launch that references it is refused with
`secret_rules_missing`. The only wildcard is exactly `rules: [{"methods":["*"],"path":"/"}]`; it is stored expanded
with `wildcard_rules: true`, and every plan that uses it carries a `WARNING:` notice and an approval reason.
`BuildLaunchConfig` itself now refuses a secret without rules instead of defaulting to every path.

**`secret-put` and `secret-delete` on the host.** `DecodeEnvelope`, a target and name check, the policy check (the
relayed settings' digest must equal the job's and the envelope's `policy_digest`), then `Store.Accept` on
`SECRETS/<target>` (root, 0700; `Validate = broker.ValidSecret`). The host binds the name to the service's secret id,
version, fingerprint, policy digest and the policy itself (`STATE/secret-bindings.json`), so a launch uses only the
value the service relayed for that exact secret id and only under its sealed policy, and answers with
`secret_receipt` in the job result. Refusals map to fixed codes (`policy_mismatch`, `replayed_or_rolled_back`,
`envelope_stale`, `envelope_wrong_context`, `envelope_unauthenticated`, `value_refused`, `envelope_malformed`). `secret-delete` is refused while a running launch uses the secret; otherwise
`Store.Delete` overwrites and removes the value and keeps a tombstone of its version (see the fix below).

**Receipt relay.** The service accepts a successful `secret-put` only with a receipt for exactly the relayed envelope
(target, name, version, key id, nonce, policy digest), stores it, shows its keyed fingerprint as `value_fingerprint`, and serves it
verbatim at `GET /api/v1/secrets/{id}/receipt` (and in the secret object as `receipt`). It cannot check the tag; the
sealing client does, with `Sealed.VerifyReceipt`.

**Broker endpoint in a launch.** For a launch with secrets the service allocates the launch's `/29` inside
`172.30.0.0/16` (8191 blocks per target, block 0 unused) when the launch is created: the block the launch id hashes
to, else the next free one in order, recorded in `broker_allocations` until the host confirms the teardown (its
receipt), the launch ends without reaching the host, or the target is retired; an exhausted pool is refused with `409
broker_pool_exhausted`. Broker `.2`, target `.3`, port 8443. It puts
the endpoint in the signed launch policy with `WithBroker` (so the policy digest and the approval cover it), names it in
the plan (`plan.broker`) and in each secret's `base_url`, and refuses an access document that names a broker itself.
A launch with secrets always needs approval and a target that advertises `brokered-secrets`. A dry run shows an
example endpoint; the created launch gets its own.

**Launch on the host.** `agentgate-hostd` refuses a broker endpoint that is not the `.2` of a `/29` inside its pool
(`--broker-pool`, default `172.30.0.0/16`), checks every secret's binding, version, fingerprint and sealed policy
(the job's settings and `policy_digest` must equal the stored policy), builds the configuration with
`BuildLaunchConfig` from the stored policies (deadline = the signed expiry), checks that its routes give the
launch's variables, writes the configuration, starts the broker (recipe
above), and waits at most 10 seconds for stats with `state: running` bound to this launch, target, configuration
digest and endpoint. Any failure tears down what was created and fails the launch closed (`broker_start_failed`,
`broker_not_running`, `broker_config_refused`, `secret_unavailable`) before the target starts. The launcher job gains
a `broker` block `{network, subnet, address, port, target_address, env}` (paths and values never appear in it);
`launch_job.py` checks it against the signed policy's single endpoint, and `launch.py` joins the target to the broker
network as `.3` only after the guard is attached, verifies that the target is on exactly its own network and the broker
network, and gives the agent only the base URLs. The Go and Python shapes are pinned by a drift test.

**Stop and evidence.** When the agent ends (exit, stop, expiry, lost service), the host runs `docker stop --time 5`,
reads the stats with `broker.ParseStats`, checks launch, target, configuration digest and endpoint, and folds them into
`Receipt.broker_counts` (forwarded requests per upstream) and `Receipt.broker_evidence`
(`agentgate.broker-evidence.v1`: state, stop reason, hardening, connection, request and per-route counts and fixed
codes; no denial records, paths or values). It then removes the container and the network and proves both are gone;
leftovers are reported as `broker_cleanup_errors` in the network evidence. Missing or invalid stats become
`broker_evidence.missing` (`broker_stats`, `broker_stats_invalid`, `broker_evidence_unreadable`). A durable
`STATE/brokers/<launch>/state.json` lets a restarted host agent stop and remove a broker a crash left behind and still
report its outcome. The service validates the evidence on ingest: none for a launch without secrets, counts and routes
only for the plan's upstreams, and `listen` equal to the plan's endpoint.

**Capability.** The host advertises `brokered-secrets` only with a broker configured (`--broker-image`), the image
present, the egress network present and the secret store usable.

**Verification kit.** `verify-probe.sh` runs its probe launch with a broker stand-in on `172.30.255.0/29` and a secret
canary in a store directory, and `verify_kernel.py` judges, among others: `open(O_CREAT)` allowed, `mkfifo` and an
`AF_UNIX` pathname bind denied, the broker endpoint reachable, the broker address on another port, the gateway and a
neighbour in the `/29` refused with `EPERM`/`EACCES`, the secret paths unreadable, and the canary absent from the agent's
output. The kit is unit-tested with fakes and has not run on a kernel.

**Fixes outside the integration code** (bugs found while connecting the parts):

- `internal/secretseal`: `Store.Delete` writes a tombstone with the deleted version, so the envelope that set a deleted
  secret cannot set it again (before, a deleted name accepted any older envelope).
- `internal/broker`: `BuildLaunchConfig` refused nothing for a secret without rules and defaulted to every method on
  every path; it now refuses (`deny by default`).
- `internal/pocpolicy`: the host could not run a signed launch document whose expiry was shorter than its lifetime
  (`ForLaunch` refused a document that already had a mode); `Shorten` narrows it.
- `poc/ssh-diagnostic`: `verify_kernel.py` was truncated and did not parse, and the probe policy in `verify-probe.sh`
  was invalid (memory controls in the wrong block, an unknown signal) with a hard-coded digest; both are rewritten.
- `internal/hostd`: a launch mount that overlaps the host agent's state directory or a configured secret root is refused
  (`invalid_mount`); the protocol already refused the default locations.

### Remaining

- **Kernel and Docker.** Nothing above ran with a Docker daemon (networks, `--ip`, `--internal`, bind mounts, the
  privilege drop inside a container, user namespaces) or on a BPF LSM kernel (the guard allowing exactly the broker
  endpoint). Run `verify-kernel.sh` on a disposable VM before relying on either.
- **Taskboard and broker together** needs the BPF change from the original request: up to four pilot endpoints in
  `struct net_policy` and an exact match in `pilot_endpoint()`. Until then a launch with secrets has no taskboard TCP
  endpoint. A launch target no longer gets the taskboard's `AF_UNIX` bridge volume unless its policy keeps the
  taskboard endpoint and grants reading the bridge path, which a launch with secrets never does
  (`restart-target.sh --launch ... [--taskboard-bridge]`, `launch_job.taskboard_bridge`); the SSH command target keeps it.
- **Pool overlap.** Docker's default address pools can hand out `172.30.0.0/16` subnets. The host refuses a broker
  network that overlaps an existing network or host address, which fails that launch closed; reserve the pool in
  `daemon.json` (`default-address-pools`) or set `--broker-pool` on hosts that run brokers.
- **Appliance runtime.** The one-command appliance does not run brokers and never advertises `brokered-secrets`.
- **`expose.placeholder_env`** (a fixed non-secret key variable for SDKs that insist on one) is not implemented.
- **Unix listen mode** is not used by the host agent; TCP is the only supported route.
- **systemd** (the sample unit) is not wired into the host agent.

## Limits

- **The broker narrows where a credential goes, not what it can do there.** Within an allowed route and its rules, a
  compromised agent can use the credential as fully as the upstream permits: spend model quota, read or push every
  repository the token reaches, and send any data it holds to that upstream (in prompts, commits or issues). Use
  least-privilege tokens with spending limits, and tight path and method rules; the explicit wildcard rule allows
  every path of the origin and is flagged in every plan that uses it.
- **Masking is best effort.** It catches the raw value and its base64 forms, also across reads, but not a value the
  upstream reverses, splits, escapes, hashes or encodes otherwise. Compressed responses are refused rather than passed
  unmasked. Allow only upstreams that do not reflect credentials.
- **Memory.** Go cannot zero every transient copy: the header value passes through HTTP write buffers and TLS record
  buffers. `mlock` is best effort and recorded in the stats. A local root user can still read the broker's memory.
- **Protocol scope.** HTTP/1.1 only, inbound plain HTTP; no WebSocket, HTTP/2, h2c, trailers or `CONNECT`. Paths
  with encoded `/`, `\`, `.` or `%` are refused (some APIs encode slashes in branch names). Request bodies are
  buffered, so large git pushes need a higher `max_request_bytes` and fewer concurrent requests.
- **TLS trust.** System roots only, optionally narrowed by pins. A private-by-design upstream with a private CA is not
  supported yet; it would need an explicit per-route CA file.
- **DNS.** The container resolver is trusted for names (not for addresses); there is no DNSSEC, and record TTLs are
  replaced by `dns_cache_seconds`.
- **Agent leg.** Anyone else on the per-launch broker network could read the agent's requests; the network must hold
  only the target and the broker.
- **Connection behaviour.** One request per connection. A client that half-closes its socket after sending a request
  is treated as gone and its request is cancelled. A connection that sends nothing holds a slot for
  `header_timeout_seconds`.
- **Counting.** Requests rejected by `net/http` before the handler are not in the stats. Rate and concurrency limits
  are per launch, not per route.
- **Not exercised here:** Docker (networks, `--ip`, `--read-only`, capabilities, user namespaces, the default seccomp
  profile's treatment of `openat2`), systemd, the BPF guard with a broker endpoint, real DNS, real upstream TLS, IPv6
  egress, `mlock` under container limits, and the privilege drop inside a container. The privilege drop was tested as
  root in a child process on the build host. The host agent's Docker commands were checked against a recorder only.

## Tests

`go test -race ./cmd/agentgate-broker/... ./internal/broker/... ./internal/secretseal/...` covers: the address table
for every class above and transition forms; DNS rebinding with a fake resolver (cached, uncached and through the
proxy); a redirect to `169.254.169.254` returned and not followed; the raw smuggling corpus at every read split and
over the wire (duplicate and list `Content-Length`, `Transfer-Encoding` with `Content-Length`, obs-fold, bare LF and
CR, NUL, non-ASCII, HTTP/1.0, the HTTP/2 preface, invalid and truncated chunking, chunk-extension floods, pipelining,
trailers, header floods); the request-header allowlist (method and URL override headers, `Range`, unlisted headers
dropped; the model-API SDK header set and a route's `forward_headers` forwarded; forbidden `forward_headers` refused);
path normalization tricks (`..;`, `.;`, `;jsessionid`, encoded `;`, fullwidth and other look-alike dots, overlong
UTF-8, mixed and double encodings, double slashes, trailing dots and spaces, encoded `?` and `#`) refused before
matching, and the canonical form forwarded; credential stripping and injection for raw, Bearer and Basic; route isolation with two
secrets; streaming SSE flushed before the upstream finishes; idle, header, body, upstream-header and total timeouts;
request and response size limits (declared and streamed); rate, concurrency and connection limits; hostname, CA and
pin failures; encoded and protocol-switching responses; header and body masking; config fuzzing and over 80 negative
cases; secret custody (modes, owners, symlinks in the path, hard links, FIFOs, descriptors); the arena being zeroed;
shutdown at the deadline and on a signal; 64 concurrent requests across two routes; and a check after every proxy
test that no form of the secret appears in logs, stats or errors. `secretseal` adds the known-answer vector, tamper of
every ciphertext byte and every context field, replay, rollback, stale and future envelopes, a wrong host, a
substituted seal key, a substituted ciphertext with the same public context, receipt tampering, pin handling and store
custody.

The integration tests: `go test -race ./internal/control/ -run Broker` runs the real service, the real host agent
(`internal/hostd`) on the real host protocol, and the real broker in process against a TLS fake upstream: a client
pins the host key, fetches and verifies the seal key, seals, the host stores the value and returns a receipt the
client verifies, a launch is planned, approved and run, the agent's request reaches the upstream with the credential,
and the receipt carries broker counts, broker evidence and `kernel_verified: false`. After every step it checks that no
form of the value appears in the database, the audit log, job payloads, events, logs, errors, the launcher job or the
receipt. Negatives: a substituted or tampered seal key, a replayed and a rolled-back `secret-put`, a launcher or profile
outside the secret's scope, the credential-redirect attacks of `e2e_policy_test.go` (a service that stores the
operator's envelope with another upstream, wider rules, another header or other headers is refused with
`policy_mismatch`; a compromised service that signs a secret-put or a launch job with the attacker's settings, under
the sealed digest or its own, is refused by the host and no broker starts; a database rewrite of a stored secret's
settings makes every plan and launch fail with `secret_policy_mismatch`; changing a policy needs a new envelope), a broker that fails to start (the launch aborts and nothing remains), and a host crash
mid-launch (the restarted host removes the broker and reports it). `prov_broker_test.go` covers the seal key record
checks, the envelope and injection refusals, a secret without rules (`secret_rules_missing`), the wildcard warning,
the endpoint derivation, receipt matching and the schema 6 migration; `prov_broker_pool_test.go` covers the
allocation order and wrap, concurrent launches on one target, an exhausted pool, release only after the host's
receipt (or for a launch that never reached the host), a silent host keeping its block until a late receipt, and the
schema 10 migration of existing launches. `internal/hostd` adds the Docker recipe against a recorder, overlap refusals, start and stop failures, recovery, and
the Go and Python launcher-job drift test.
