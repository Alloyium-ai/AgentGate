# Credential broker

An agent in the guarded sandbox can use a credential (a model API key, a git token) without the sandbox, the agent or
any code it runs ever holding the secret. A host-side broker holds the value, accepts plain HTTP requests from the
sandbox on one exact endpoint, forwards only allowed requests to an exact HTTPS upstream allowlist, adds the
credential on the way out, and records bounded evidence. The value reaches the host through a sealed relay that the
service cannot read (`internal/secretseal`).

| Part | Path |
| --- | --- |
| Broker library | `internal/broker` |
| Command | `cmd/agentgate-broker` (`validate`, `run`, `version`) |
| Container image | `cmd/agentgate-broker/Dockerfile` (static binary and CA bundle on `scratch`) |
| systemd sample | `cmd/agentgate-broker/agentgate-broker@.service` |
| Sealed relay | `internal/secretseal` (host store, client pinning helper, known-answer vector) |

**Status.** Implemented and tested in the build sandbox with a local TLS fake upstream, a test CA, a fake resolver
and a fake dialer. Docker, systemd, the BPF LSM guard, real DNS and real upstreams were **not** exercised. End-to-end
use needs the integration changes listed below; until they land, `agentgate-hostd` refuses launches with secrets.

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
| Malicious or compromised service (relay) | substitute the host's seal key, replace or replay ciphertext | the seal key is signed by the host's pinned Ed25519 key; the envelope binds target, name, version and nonce; replays and rollbacks are refused; a substituted ciphertext cannot produce a receipt the client accepts |
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
5. **Path**: at most 2048 bytes of RFC 3986 path characters; percent-encoding must not produce `/`, `\`, `.`, `%` or a
   control byte; no dot segments; no empty segment except one trailing slash. The query is forwarded verbatim if it is
   visible ASCII without `#`.
6. **Route and rules**: the first segment names a route; the rest must match a rule (`exact`, or `prefix` on a segment
   boundary) whose methods include the request method. Methods are `GET HEAD POST PUT PATCH DELETE OPTIONS`; `CONNECT`
   and `TRACE` cannot be configured.
7. **Concurrency**: at most `max_concurrent_requests` in flight (`503`).
8. **Body**: read in full within `body_timeout_seconds`, at most `max_request_bytes` (`413`). Invalid chunking or a
   truncated body is `400`; the upstream sees nothing.
9. **Forward**: headers are copied except the stripped set; the credential and extra headers are injected;
   `Accept-Encoding: identity` is set; the URL is `https://host[:port]` + `base_path` + the route-relative path.

Stripped inbound headers: hop-by-hop (`Connection` and every header it lists, `Keep-Alive`, `Proxy-Connection`, `TE`,
`Trailer`, `Transfer-Encoding`, `Upgrade`, `HTTP2-Settings`); credentials (`Authorization`, `Proxy-Authorization`,
`X-Api-Key`, `Api-Key`, `X-Goog-Api-Key`, `Private-Token`, `X-Auth-Token`, `Authentication`, `Cookie`, `Cookie2`, the
route's credential header and every extra header name); client identity and forwarding (`Forwarded`, `Via`,
`X-Forwarded-*`, `X-Real-Ip`, `X-Client-Ip`, `True-Client-Ip`, `Cf-Connecting-Ip`, `Fastly-Client-Ip`,
`X-Cluster-Client-Ip`, every `Proxy-*`); and framing owned by the broker (`Host`, `Content-Length`, `Expect`,
`Accept-Encoding`). Without a client `User-Agent`, none is sent.

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

## Configuration reference (`agentgate.broker.v1`)

One JSON object, at most 64 KiB, root-owned (or owned by the broker user), regular, not a symlink, not group or world
writable. Unknown fields, duplicate keys, keys that are not lowercase, `null`, trailing data and nesting beyond 16
levels are refused. Errors name the field and never echo a value. The file never contains a secret.

```json
{
  "version": "agentgate.broker.v1",
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
| `version` | `agentgate.broker.v1` |
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
| `credential.secret_file` / `secret_fd` | exactly one. File: regular, one link, owner root or the broker user, no group or other access, opened without following any symlink (`openat2` `RESOLVE_NO_SYMLINKS`), unchanged between `fstat` calls. Descriptor 3..1023: a regular file or memfd with the same ownership rules, or a pipe. The value is 8..8192 bytes of visible ASCII; one trailing newline is removed. A file may back several routes; a descriptor only one |
| `credential.header` | a token header name, never a framing, hop-by-hop, cookie, proxy or forwarding header |
| `credential.scheme` | `""` (the raw value), `Bearer` or `Basic` (both need `authorization`; Basic needs `username`, visible ASCII without `:`) |
| `credential.extra_headers` | up to 8 non-secret headers (for example an API version), 1..256 printable ASCII characters; they replace any client value |
| `rules` | 1..64 of `{methods, path, match}`; `path` canonical, no percent-encoding; `match` `exact` or `prefix` |

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
parses it with `broker.ParseStats` (strict, at most 1 MiB), checks `launch_id` and `config_sha256` against the
configuration it wrote, fills `hostproto.Receipt.BrokerCounts` with `broker.BrokerCounts`, and attaches the document.

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

Hardened container (the host agent's recipe; `IMAGE` is the digest-pinned image):

```sh
L=lch-0001; NET=agentgate-$L-broker; NAME=agentgate-$L-broker
docker network create --internal --driver bridge --subnet 172.30.7.0/29 "$NET"
install -d -o 10002 -g 10002 -m 0700 "/var/lib/agentgate/launches/$L/broker"
digest=$(sha256sum "/var/lib/agentgate/launches/$L/broker.json" | cut -d' ' -f1)
docker create --name "$NAME" --network "$NET" --ip 172.30.7.2 \
  --read-only --cap-drop ALL --cap-add SETUID --cap-add SETGID --security-opt no-new-privileges \
  --ulimit core=0 --memory 256m --pids-limit 64 --cpus 1 --restart no \
  -v "/var/lib/agentgate/launches/$L/broker.json:/etc/agentgate/broker.json:ro" \
  -v "/var/lib/agentgate/secrets/local/anthropic:/run/agentgate/secrets/anthropic:ro" \
  -v "/var/lib/agentgate/launches/$L/broker:/var/lib/agentgate/broker" \
  "$IMAGE" run --config-sha256 "$digest" /etc/agentgate/broker.json
docker network connect agentgate-egress "$NAME"      # the broker's own route to the internet
docker start "$NAME"
docker network connect --ip 172.30.7.3 "$NET" "$TARGET"   # the target joins only the broker network
```

The broker container never mounts the Docker socket, the secret store or anything of the target. The target never
mounts a secret file. Docker user-namespace remapping changes file ownership inside the container; the custody checks
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
3. **Seal.** `Seal(pub, targetID, name, value)`: RFC 9180 HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
   ChaCha20-Poly1305 (`crypto/hpke` in the Go standard library; no new dependency). The HPKE info binds the format,
   suite, key id and target. The associated data binds format, suite, target id, secret name, version (sealing time in
   Unix milliseconds) and a fresh 128-bit nonce. The envelope `{format, target_id, name, version, key_id, nonce,
   sealed}` holds only ciphertext and public context; `Envelope.Encode()` is its string wire form.
4. **Host.** `Store.Accept(key, envelope, now)` (directory owned by the host agent, mode 0700, under a lock) refuses a
   different target or key id, a version not newer than the stored one (replay and rollback), an envelope sealed more
   than 24 hours ago or more than 5 minutes in the future, and a value that `Store.Validate` rejects (set it to
   `broker.ValidSecret`). It writes the value to `DIR/NAME` (0600, temporary file, fsync, rename, directory fsync) and
   `DIR/NAME.meta.json` (version, nonce, fingerprint; no value).
5. **Receipt.** `{format, target_id, name, version, key_id, nonce, fingerprint, tag}`. The fingerprint is
   `sfp1_` + the first 128 bits of HMAC-SHA256 under a random 32-byte key kept only in the host store, over the target,
   name and value: without that key a fingerprint reveals nothing, so a short or guessable secret cannot be brute
   forced from it, and the same value on the same host always shows the same fingerprint, so a change is visible. The
   tag is HMAC-SHA256 keyed by the HPKE exporter secret, which only the sealing client and the host share. The client
   runs `Sealed.VerifyReceipt`; a relay that swapped the ciphertext for one of its own (even with the same public
   context) cannot produce a tag the client accepts.

`testdata/vector-v1.json` is a known-answer vector (fixed keys, envelope, fingerprint and receipt). Comparisons of
tags use `hmac.Equal`. Plaintext and exporter secrets are cleared after use; Go cannot guarantee that no transient
copy remains.

## Integration requests

These changes are outside the broker's files. Each is required for end-to-end use unless marked optional.

### Guard and policy (`internal/pocpolicy`, `bpf/`)

The pilot guard (`bpf/network_peer_match.h`) denies every private, loopback and link-local destination except one
exact TCP endpoint (`pilot_family`, `pilot_port`, `pilot_address`), which `pocpolicy.Document.Compile` fills from
`taskboard` together with the allow rule `taskboard-exact`.

1. **Broker endpoint in the policy (no BPF change).** Add `broker: {address, protocol: "tcp", port}` to
   `pocpolicy.Document`, validated exactly like `taskboard` (canonical private IPv4, TCP, port 1024..65535) and
   mutually exclusive with `taskboard` in v1. `Compile` sets `PilotMode 1`, `PilotFamily IPv4`, `PilotPort` and
   `PilotAddress` from it and adds the exact allow rule `broker-exact` (`/32`, TCP, that port). The digest covers it,
   so the receipt binds the endpoint.
2. **Taskboard and broker together (BPF change).** Extend `struct net_policy` with up to four pilot endpoints
   (`pilot_count`, `pilot_addresses[4][16]`, `pilot_ports[4]`) and make `pilot_endpoint()` allow a private destination
   only when family, TCP and port and all 16 address bytes equal one entry; keep everything else in the function as it
   is. `pocpolicy` then accepts `taskboard` and `broker` together and emits one exact allow rule for each.
3. Nothing else changes: the broker subnet must never be allowed as a prefix, and the guard keeps denying the
   target's own egress network and loopback.
4. **Unix mode (optional).** Today's pilot hooks do not see `AF_UNIX`, so a socket on a read-only per-launch volume is
   reachable; with a v2 policy the socket directory must be in `filesystem.read_only` (like
   `/run/agentgate/taskboard`). The full socket component (`internal/enforcement`) denies `AF_UNIX` creation, so this
   mode will not survive a move to it; TCP is the supported route.

### Host agent and launch runtime (`internal/hostd`, `poc/ssh-diagnostic`)

1. **Seal key.** At start, build `secretseal.HostKeyFromECDH(targetID, keys.Encryption, keys.Signing, now, 30 days)`,
   publish `Published()` through the service (see the control plane requests) and rotate it before `not_after`.
2. **`secret-put`.** Replace the fail-closed branch: `env, _ := secretseal.DecodeEnvelope(payload.Ciphertext)`; open
   `secretseal.OpenStore("/var/lib/agentgate/secrets/" + targetID)` (root, 0700, outside every mount and outside
   `/var/lib/agentgate/workspace`); set `store.Validate = broker.ValidSecret`; `receipt, err := store.Accept(hostKey,
   env, now)`; return the receipt in the job result. Map `ErrReplay`, `ErrStale`, `ErrContext`, `ErrOpen`, `ErrValue`
   to `rejected` results. `secret-delete` removes `DIR/NAME` and `DIR/NAME.meta.json` under the store lock.
3. **`launch` with secrets.** Allocate a per-launch `/29` from a host-reserved pool (for example `172.30.0.0/16`):
   broker `.2`, target `.3`, port 8443. Build the config with `broker.BuildLaunchConfig` (`secret_file` = the bind
   target of each store file, `stats_path` in a per-launch directory owned by the `run_as` uid, `deadline` = the
   launch `expires_at`); write it root-owned 0600; run `agentgate-broker validate`; start the container with the recipe
   above; wait up to 10 seconds for the stats file to show `state: running`, else fail the launch closed; put the
   endpoint in the launch policy (guard request 1); add the returned environment (`expose.env` to base URL) to the
   agent environment; connect the target to the broker network only after the policy is attached.
4. **Stop.** `docker stop --time 5` the broker (SIGTERM, graceful within the deadline), read the stats with
   `broker.ParseStats`, verify `launch_id` and `config_sha256`, set `Receipt.BrokerCounts = broker.BrokerCounts(doc)`,
   attach the document, then remove the container, the broker network and the per-launch config. A missing or
   incomplete stats file is reported as `evidence_missing: broker_stats`.
5. **Never** mount the secret store, a secret file or the broker's config into the target, and never put a value in
   `agent.env`, argv or job events.
6. **SDK placeholder (optional, contract amendment below).** Some SDKs refuse to start without a key variable. The
   host may set the name in `expose.placeholder_env` to the fixed non-secret value `agentgate-brokered`; the broker
   strips whatever the client sends.

### Control plane and host protocol (`internal/hostproto`, `internal/control`)

1. **Envelope format.** `SecretPutPayload.Ciphertext` carries `secretseal.Envelope.Encode()`; `DecodeSealed` and
   `CheckSealed` (or a new `envelope` field) accept it, `ciphertext_sha256` is the SHA-256 of the decoded envelope
   bytes, and `CreateSecret` checks `secretseal.DecodeEnvelope` with `TargetID` equal to the target and `Name` equal
   to the secret name. Retire `hostproto.SealSecret` for new secrets: its AAD binds no version or nonce, so a relayed
   old ciphertext can roll a rotated secret back, and its X25519 key reaches clients without a host signature the
   client can check against a pin.
2. **Seal key publication.** The host sends its `SignedKeyRecord` at enrollment (`EnrollRequest.seal_key_record`) and
   on rotation; `GET /api/v1/targets/{id}/seal-key` returns `{host_public_key, host_key_fingerprint, record}`. The
   service stores and relays the record and never re-signs it.
3. **Receipt relay.** The `secret-put` result carries the `secretseal.Receipt` (fingerprint and tag only); the service
   stores `fingerprint` as the displayed value fingerprint and returns the receipt to the creating client.
4. **Evidence.** `hostproto.Receipt` gains `broker_evidence` (raw JSON, at most 64 KiB, the stats document) next to
   `broker_counts`.
5. **Injection rules.** Secret metadata and `LaunchSecret` gain `scheme` (`""`, `Bearer`, `Basic`), `username`,
   `rules` (`[{methods, path, match}]`) and optional `extra_headers`. Until they exist, `BuildLaunchConfig` uses
   `Bearer` for an `authorization` header, the raw value otherwise, and `DefaultRules()` (every method on every path of
   the one origin), which is the widest setting. Prefer one upstream per secret; several upstreams become routes
   `REF`, `REF-2`, ... each bound to one origin, and `expose.env` receives the first.

### CLI (`cmd/agentgate`)

`agentgate secret set NAME --target T --upstream HOST [--header H]` reads the value from stdin, fetches the seal key,
loads `~/.config/agentgate/known-targets.json`, calls `secretseal.SealForTarget` (trust on first use only with an
explicit flag, after printing the host key fingerprint for comparison with the one `agentgate-hostd` printed at
enrollment), uploads `Envelope.Encode()`, keeps the `Sealed` value until the receipt arrives, verifies it with
`VerifyReceipt` and prints the fingerprint.

## Limits

- **The broker narrows where a credential goes, not what it can do there.** Within an allowed route and its rules, a
  compromised agent can use the credential as fully as the upstream permits: spend model quota, read or push every
  repository the token reaches, and send any data it holds to that upstream (in prompts, commits or issues). Use
  least-privilege tokens with spending limits, and tight path and method rules; the interim default rules allow every
  path of the origin.
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
  root in a child process on the build host.

## Tests

`go test -race ./cmd/agentgate-broker/... ./internal/broker/... ./internal/secretseal/...` covers: the address table
for every class above and transition forms; DNS rebinding with a fake resolver (cached, uncached and through the
proxy); a redirect to `169.254.169.254` returned and not followed; the raw smuggling corpus at every read split and
over the wire (duplicate and list `Content-Length`, `Transfer-Encoding` with `Content-Length`, obs-fold, bare LF and
CR, NUL, non-ASCII, HTTP/1.0, the HTTP/2 preface, invalid and truncated chunking, chunk-extension floods, pipelining,
trailers, header floods); credential stripping and injection for raw, Bearer and Basic; route isolation with two
secrets; streaming SSE flushed before the upstream finishes; idle, header, body, upstream-header and total timeouts;
request and response size limits (declared and streamed); rate, concurrency and connection limits; hostname, CA and
pin failures; encoded and protocol-switching responses; header and body masking; config fuzzing and over 80 negative
cases; secret custody (modes, owners, symlinks in the path, hard links, FIFOs, descriptors); the arena being zeroed;
shutdown at the deadline and on a signal; 64 concurrent requests across two routes; and a check after every proxy
test that no form of the secret appears in logs, stats or errors. `secretseal` adds the known-answer vector, tamper of
every ciphertext byte and every context field, replay, rollback, stale and future envelopes, a wrong host, a
substituted seal key, a substituted ciphertext with the same public context, receipt tampering, pin handling and store
custody.
