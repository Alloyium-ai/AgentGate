// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// agentgate up brings this machine online end to end. Every step first reads
// the current state (the service, the host agent, the saved context), says
// what it found, and acts only when something is missing, so the command is
// safe to run again after any failure. Host-side work is delegated to docker
// compose and agentgate-hostd through argument vectors; agentgate never
// reimplements it.

const (
	defaultLocalURL    = "https://localhost:9443"
	caddyRootPath      = "/data/caddy/pki/authorities/local/root.crt"
	defaultHostdState  = "/var/lib/agentgate-hostd"
	defaultUpTokenTTL  = "7d"
	healthWait         = 2 * time.Minute
	onlineWait         = 60 * time.Second
	minAdminPassword   = 16
	upPollInterval     = 3 * time.Second
	defaultApproveWait = 10 * time.Minute
)

var fingerprintText = regexp.MustCompile(`ed25519:[a-f0-9]{32}`)

type upOptions struct {
	target, serviceURL, composeFile   string
	adminUser, adminName              string
	cred                              credentialFlags
	runtime, instance, applianceState string
	source, stateDir, hostd, tokenTTL string
	approve, skipHost                 bool
	waitTimeout                       time.Duration
	broker                            brokerFlags
	mountRoots                        multiFlag
}

// brokerFlags are the credential broker settings up passes to
// agentgate-hostd install; zero values are not passed (the host agent's
// defaults apply).
type brokerFlags struct {
	image, egress, pool, secretRoot string
	uid, gid                        int
}

var dockerNetworkName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)

// check refuses settings agentgate-hostd would refuse, before anything runs.
func (b brokerFlags) check() error {
	if b.image == "" {
		for _, f := range []struct {
			name string
			set  bool
		}{{"--broker-uid", b.uid != 0}, {"--broker-gid", b.gid != 0}, {"--broker-egress-network", b.egress != ""}, {"--broker-pool", b.pool != ""}} {
			if f.set {
				return usageError("%s configures the credential broker; it needs --broker-image NAME@sha256:<digest>", f.name)
			}
		}
	} else if !hostproto.ImagePattern.MatchString(b.image) {
		return usageError("--broker-image must be a digest-pinned image reference (name@sha256:<64 hex>)")
	}
	if b.uid < 0 || b.uid > 1<<31-2 || b.gid < 0 || b.gid > 1<<31-2 {
		return usageError("--broker-uid and --broker-gid must be unprivileged ids (1 to 2147483646)")
	}
	if b.egress != "" && (!dockerNetworkName.MatchString(b.egress) || b.egress == "host" || b.egress == "none") {
		return usageError("--broker-egress-network must name a Docker bridge network")
	}
	if b.pool != "" {
		p, err := netip.ParsePrefix(b.pool)
		if err != nil || p.Masked() != p || !p.Addr().Is4() || !p.Addr().IsPrivate() || p.Bits() < 8 || p.Bits() > 24 || p.String() != b.pool {
			return usageError("--broker-pool must be a canonical private IPv4 prefix of /8 to /24")
		}
	}
	if b.secretRoot != "" && (!filepath.IsAbs(b.secretRoot) || filepath.Clean(b.secretRoot) != b.secretRoot || b.secretRoot == "/") {
		return usageError("--secret-root must be a canonical absolute path")
	}
	return nil
}

// args are the install flags for these settings.
func (b brokerFlags) args() []string {
	var out []string
	if b.image != "" {
		out = append(out, "--broker-image", b.image)
	}
	if b.uid != 0 {
		out = append(out, "--broker-uid", strconv.Itoa(b.uid))
	}
	if b.gid != 0 {
		out = append(out, "--broker-gid", strconv.Itoa(b.gid))
	}
	if b.egress != "" {
		out = append(out, "--broker-egress-network", b.egress)
	}
	if b.pool != "" {
		out = append(out, "--broker-pool", b.pool)
	}
	if b.secretRoot != "" {
		out = append(out, "--secret-root", b.secretRoot)
	}
	return out
}

// differs reports whether the installed host agent's settings lack what was
// asked for.
func (b brokerFlags) differs(s *hostdStatus) bool {
	if b.secretRoot != "" && b.secretRoot != s.SecretRoot {
		return true
	}
	if b.image == "" {
		return false
	}
	have := s.Broker
	return have == nil || have.Image != b.image || b.uid != 0 && have.UID != b.uid || b.gid != 0 && have.GID != b.gid ||
		b.egress != "" && have.EgressNetwork != b.egress || b.pool != "" && have.Pool != b.pool
}

func init() {
	register(&command{name: "up", summary: "Bring this machine online: service, first admin, enrollment, host agent, key approval, provisioning.",
		help: `Each step checks the current state first and only does what is missing; re-run after any failure.
  --target NAME          target name for this machine (default local)
  --service-url URL      use an existing service (default: the saved context, or https://localhost:9443)
  --compose-file FILE    deployment compose.yaml for a local service (default ./compose.yaml or
                         /opt/agentgate/deployment/compose.yaml); needs AGENTGATE_IMAGE=<image>@sha256:<digest>
  --admin-user NAME      first administrator to create, or the administrator to sign in as
  --admin-name TEXT      display name of a new first administrator
  --runtime KIND         docker-host or appliance (passed to agentgate-hostd install)
  --instance NAME        docker-host POC instance (default demo)
  --appliance-state DIR  appliance runtime state directory
  --source DIR           AgentGate source checkout (appliance runtime)
  --state-dir DIR        host agent state directory (default /var/lib/agentgate-hostd)
  --hostd PATH           agentgate-hostd binary (default: from PATH)
  --approve              approve the host key here: only if you are an administrator, on a terminal,
                         after comparing the fingerprint this machine's agent printed (never with --yes)
  --wait-timeout DUR     how long to wait for another administrator's approval (default 10m)
  --token-ttl DUR        lifetime of the admin API token up saves (default 7d)
  --skip-host            stop after the service, admin and target steps (no root needed)
  --broker-image REF     digest-pinned agentgate-broker image: enables brokered secrets on this host
  --broker-egress-network NET  Docker network the broker reaches upstreams on (default agentgate-egress)
  --broker-uid N, --broker-gid N  the broker's unprivileged identity (default 10002)
  --broker-pool CIDR     private range of per-launch broker networks (default 172.30.0.0/16)
  --secret-root DIR      the host's secret store (default /var/lib/agentgate/secrets)
  --mount-root PATH      a host folder launches on this host may mount (repeatable; this host's own list)
` + credentialHelp + `
Steps that need root (installing the host agent, appliance provisioning) refuse to run without it
and print the exact command to run instead.`,
		setup: func(fs *flag.FlagSet) runner {
			var o upOptions
			o.cred.register(fs)
			fs.StringVar(&o.target, "target", "local", "")
			fs.StringVar(&o.serviceURL, "service-url", "", "")
			fs.StringVar(&o.composeFile, "compose-file", "", "")
			fs.StringVar(&o.adminUser, "admin-user", "", "")
			fs.StringVar(&o.adminName, "admin-name", "", "")
			fs.StringVar(&o.runtime, "runtime", "docker-host", "")
			fs.StringVar(&o.instance, "instance", "", "")
			fs.StringVar(&o.applianceState, "appliance-state", "", "")
			fs.StringVar(&o.source, "source", "", "")
			fs.StringVar(&o.stateDir, "state-dir", defaultHostdState, "")
			fs.StringVar(&o.hostd, "hostd", "", "")
			fs.StringVar(&o.tokenTTL, "token-ttl", defaultUpTokenTTL, "")
			fs.BoolVar(&o.approve, "approve", false, "")
			fs.BoolVar(&o.skipHost, "skip-host", false, "")
			fs.DurationVar(&o.waitTimeout, "wait-timeout", defaultApproveWait, "")
			fs.StringVar(&o.broker.image, "broker-image", "", "")
			fs.StringVar(&o.broker.egress, "broker-egress-network", "", "")
			fs.IntVar(&o.broker.uid, "broker-uid", 0, "")
			fs.IntVar(&o.broker.gid, "broker-gid", 0, "")
			fs.StringVar(&o.broker.pool, "broker-pool", "", "")
			fs.StringVar(&o.broker.secretRoot, "secret-root", "", "")
			fs.Var(&o.mountRoots, "mount-root", "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 0 {
					return usageError("up takes flags only (agentgate up --help)")
				}
				if o.adminUser != "" && o.cred.username != "" && o.adminUser != o.cred.username {
					return usageError("--admin-user and --username name different accounts")
				}
				if o.adminUser == "" {
					o.adminUser = o.cred.username
				}
				if o.runtime != "docker-host" && o.runtime != "appliance" {
					return usageError("--runtime is docker-host or appliance")
				}
				if o.approve && e.g.yes {
					return usageError("--approve never takes --yes: approving a host key needs an interactive confirmation")
				}
				if err := o.broker.check(); err != nil {
					return err
				}
				if o.broker.image != "" && o.runtime == "appliance" {
					return usageError("the appliance runtime does not run credential brokers; --broker-image needs --runtime docker-host")
				}
				if len(o.mountRoots) > 0 {
					if err := hostproto.CheckMountRoots([]string(o.mountRoots)); err != nil {
						return usageError("--mount-root: %s", strings.TrimPrefix(err.Error(), "hostproto: "))
					}
				}
				if o.skipHost && (o.broker.image != "" || o.broker.secretRoot != "" || len(o.mountRoots) > 0) {
					return usageError("--skip-host installs no host agent, so the broker and mount root flags would do nothing")
				}
				return (&upRun{e: e, o: o}).run(ctx)
			}
		}})
}

type upRun struct {
	e        *env
	o        upOptions
	url      *url.URL
	opts     transportOptions
	compose  string
	docker   string
	password []byte
	admin    *Client
	ctxName  string
	saved    *Context
	target   Target
	token    string
	hostd    string
	// localKey and localTarget are what this machine's own agentgate-hostd
	// reports (agentgate-hostd status): the out-of-band anchor a pin needs.
	localKey    string
	localTarget string
	local       *hostdStatus
}

type upStep struct {
	name string
	fn   func(context.Context) error
}

func (u *upRun) say(format string, args ...any) {
	if !u.e.g.json {
		u.e.p.line("      "+format, args...)
	}
}

func (u *upRun) run(ctx context.Context) error {
	defer func() { zero(u.password) }()
	steps := []upStep{
		{"service", u.service},
		{"administrator credentials", u.credentials},
		{"target", u.targetStep},
		{"host agent", u.hostAgent},
		{"host key approval", u.keyApproval},
		{"provision", u.provision},
		{"ready", u.ready},
	}
	for i, s := range steps {
		if !u.e.g.json {
			u.e.p.line("[%d/%d] %s", i+1, len(steps), s.name)
		}
		if err := s.fn(ctx); err != nil {
			ce := asError(ctx, err)
			if ce.Exit != ExitInterrupted {
				ce.Message = "agentgate up stopped at step " + fmt.Sprint(i+1) + " (" + s.name + "): " + ce.Message
				retry := "fix that, then run agentgate up again; finished steps are detected and skipped."
				if ce.Hint == "" {
					ce.Hint = strings.ToUpper(retry[:1]) + retry[1:]
				} else {
					ce.Hint = strings.TrimSuffix(ce.Hint, ".") + "; then run agentgate up again (finished steps are skipped)."
				}
			}
			return ce
		}
	}
	return nil
}

func (u *upRun) rootError(step, what string, manual []string) error {
	return &Error{Exit: ExitForbidden, Code: "root_required", Message: "Step " + step + " needs root: it must " + what + ". Nothing was changed by this step.",
		Hint: "Run sudo agentgate up " + strings.Join(u.replayArgs(), " ") + ", or run it yourself as root: " + strings.Join(manual, " ")}
}

// replayArgs is the up command line to suggest.
func (u *upRun) replayArgs() []string {
	args := []string{"--target", u.o.target}
	if u.url != nil {
		args = append(args, "--service-url", u.url.String())
	}
	if u.o.runtime != "docker-host" {
		args = append(args, "--runtime", u.o.runtime)
	}
	return args
}

func (u *upRun) findCompose() string {
	if u.o.composeFile != "" {
		return u.o.composeFile
	}
	for _, p := range []string{"compose.yaml", "/opt/agentgate/deployment/compose.yaml"} {
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	return ""
}

func (u *upRun) runCmd(ctx context.Context, path string, args []string, stdin []byte, stream bool) (Result, error) {
	c := Cmd{Path: path, Args: args, Stdin: stdin}
	if stream && !u.e.g.json && !u.e.g.quiet {
		c.Stream = &prefixWriter{w: u.e.app.Stderr, prefix: "      | "}
	}
	res, err := u.e.app.Runner.Run(ctx, c)
	if err != nil {
		return res, failure("cannot run %s: %v", filepath.Base(path), err)
	}
	return res, nil
}

func (u *upRun) composeArgs(args ...string) []string {
	return append([]string{"compose", "-f", u.compose}, args...)
}

func tail(out []byte) string {
	s := strings.TrimSpace(redactText(string(out)))
	if len(s) > 600 {
		s = "..." + s[len(s)-600:]
	}
	return s
}

func (u *upRun) healthy(ctx context.Context) error {
	c, err := u.e.clientFor(u.url, "", u.opts)
	if err != nil {
		return err
	}
	c.timeout = 5 * time.Second
	_, err = c.call(ctx, request{method: "GET", path: "/healthz", noAuth: true}, nil)
	return err
}

// fetchCA copies the local TLS front's CA certificate into the config dir.
func (u *upRun) fetchCA(ctx context.Context) error {
	if u.compose == "" || u.docker == "" {
		return errors.New("no compose deployment")
	}
	res, err := u.runCmd(ctx, u.docker, u.composeArgs("exec", "-T", "tls", "cat", caddyRootPath), nil, false)
	if err != nil {
		return err
	}
	if res.Exit != 0 || !bytes.Contains(res.Stdout, []byte("BEGIN CERTIFICATE")) {
		return errors.New("the TLS front has no CA certificate yet")
	}
	st, err := u.e.store()
	if err != nil {
		return err
	}
	name := "ca-" + u.ctxName + ".pem"
	if err = st.writePrivate(name, res.Stdout); err != nil {
		return err
	}
	u.opts.caFile = filepath.Join(st.dir, name)
	u.say("trusting the local TLS front's CA, saved to %s", u.opts.caFile)
	return nil
}

func (u *upRun) service(ctx context.Context) error {
	cfg, err := u.e.config()
	if err != nil {
		return err
	}
	u.ctxName = u.e.contextName(cfg)
	if err = validContextName(u.ctxName); err != nil {
		return err
	}
	raw := u.o.serviceURL
	if raw == "" {
		raw = u.e.g.server
	}
	if saved := cfg.Contexts[u.ctxName]; raw == "" && saved != nil {
		raw = saved.Server
	}
	if raw == "" {
		raw = defaultLocalURL
	}
	if u.url, err = serverURL(raw); err != nil {
		return err
	}
	if saved := cfg.Contexts[u.ctxName]; saved != nil && saved.Server == u.url.String() {
		u.saved = saved
		u.opts = transportOptions{caFile: saved.CAFile, pin: saved.CertSHA256, allowLoopbackHTTP: saved.AllowLoopbackHTTP}
	}
	if u.e.g.caFile != "" {
		u.opts.caFile, _ = filepath.Abs(u.e.g.caFile)
	}
	if u.e.g.pinCert != "" {
		u.opts.pin = u.e.g.pinCert
	}
	u.opts.allowLoopbackHTTP = u.opts.allowLoopbackHTTP || u.e.g.insecure
	local := isLoopbackHost(u.url.Host)
	if local {
		u.compose = u.findCompose()
		if u.compose != "" {
			u.docker, _ = u.e.app.Runner.LookPath("docker")
		}
	}
	err = u.healthy(ctx)
	if err != nil && local && u.opts.caFile == "" && u.docker != "" {
		var ce *Error
		if errors.As(err, &ce) && ce.Exit == ExitTrust {
			if u.fetchCA(ctx) == nil {
				err = u.healthy(ctx)
			}
		}
	}
	if err == nil {
		u.say("running at %s", u.url)
		return nil
	}
	var ce *Error
	if errors.As(err, &ce) && (ce.Exit == ExitTrust || ce.Exit == ExitUsage) {
		return err
	}
	if !local {
		return &Error{Exit: ExitNetwork, Code: "service_unreachable", Message: "No AgentGate service answers at " + u.url.String() + ".", Hint: "Start the service there, or pass the right --service-url."}
	}
	if u.compose == "" {
		return &Error{Exit: ExitNetwork, Code: "service_unreachable", Message: "No AgentGate service answers at " + u.url.String() + " and no compose.yaml was found to start one.", Hint: "Pass --compose-file FILE (the deployment directory of the AgentGate image), or --service-url URL of a running service."}
	}
	if u.docker == "" {
		return &Error{Exit: ExitUsage, Code: "docker_missing", Message: "The docker command is not installed; the local service runs with docker compose.", Hint: "Install Docker with the compose plugin."}
	}
	if u.e.app.Getenv("AGENTGATE_IMAGE") == "" {
		return usageError("set AGENTGATE_IMAGE to the CI-built AgentGate image reference with its sha256 digest; %s requires it", u.compose)
	}
	u.say("no service answers; starting it with docker compose (%s)", u.compose)
	res, err := u.runCmd(ctx, u.docker, u.composeArgs("run", "--rm", "-T", "control", "job-key"), nil, false)
	if err != nil {
		return err
	}
	if res.Exit == 0 {
		u.say("service state: already initialized")
	} else {
		u.say("service state: initializing")
		res, err = u.runCmd(ctx, u.docker, u.composeArgs("run", "--rm", "-T", "control", "init", "/bootstrap/settings.json"), nil, true)
		if err != nil {
			return err
		}
		if res.Exit != 0 {
			return &Error{Exit: ExitFailure, Code: "init_failed", Message: "Initializing the service state failed: " + tail(append(res.Stdout, res.Stderr...)), Hint: "Check docker compose logs control and the settings file the compose file mounts."}
		}
	}
	if err = u.firstAdmin(ctx); err != nil {
		return err
	}
	res, err = u.runCmd(ctx, u.docker, u.composeArgs("up", "-d"), nil, true)
	if err != nil {
		return err
	}
	if res.Exit != 0 {
		return &Error{Exit: ExitFailure, Code: "compose_up_failed", Message: "docker compose up failed: " + tail(append(res.Stdout, res.Stderr...)), Hint: "Check docker compose logs."}
	}
	deadline := time.Now().Add(healthWait)
	for {
		if u.opts.caFile == "" {
			u.fetchCA(ctx)
		}
		if err = u.healthy(ctx); err == nil {
			u.say("running at %s", u.url)
			return nil
		}
		if time.Now().After(deadline) {
			return &Error{Exit: ExitTimeout, Code: "service_not_ready", Message: "The service did not become ready within " + healthWait.String() + ": " + asError(ctx, err).Message, Hint: "Check docker compose -f " + u.compose + " logs control."}
		}
		if err := u.e.app.Sleep(ctx, 2*time.Second); err != nil {
			return err
		}
	}
}

// adminJSON builds the first-admin request without copying the password
// into a Go string.
func adminJSON(username, name string, password []byte) []byte {
	b := []byte(`{"username":`)
	b = appendJSONString(b, []byte(username))
	b = append(b, `,"name":`...)
	b = appendJSONString(b, []byte(name))
	b = append(b, `,"password":`...)
	b = appendJSONString(b, password)
	return append(b, '}')
}

func (u *upRun) firstAdmin(ctx context.Context) error {
	user := u.o.adminUser
	if user == "" {
		if !u.e.app.Term.IsTerminal(0) {
			return usageError("a new service needs its first administrator: pass --admin-user NAME and --password-stdin or --password-file")
		}
		var err error
		if user, err = u.e.readLine(ctx, "      first administrator username: "); err != nil {
			return err
		}
		user = strings.TrimSpace(user)
	}
	if !usernamePattern.MatchString(user) {
		return usageError("a local username matches ^[a-z][a-z0-9_.-]{2,63}$")
	}
	name := u.o.adminName
	if name == "" {
		name = user
	}
	password, err := u.e.readPassword(ctx, u.o.cred, "      password for "+user+" (at least 16 characters)", true)
	if err != nil {
		return err
	}
	if len(password) < minAdminPassword || len(password) > 256 {
		zero(password)
		return usageError("the administrator password is 16 to 256 bytes")
	}
	body := adminJSON(user, name, password)
	res, err := u.runCmd(ctx, u.docker, u.composeArgs("run", "--rm", "-T", "control", "first-admin"), body, false)
	zero(body)
	if err != nil {
		zero(password)
		return err
	}
	out := append(append([]byte{}, res.Stdout...), res.Stderr...)
	switch {
	case res.Exit == 0 && bytes.Contains(out, []byte("FIRST_ADMIN_READY")):
		u.say("created the first administrator %s", user)
		u.o.adminUser, u.password = user, password
	case bytes.Contains(out, []byte("administrator_exists")) || bytes.Contains(out, []byte("first administrator already exists")):
		u.say("a first administrator already exists; nothing created (signing in as %s next)", user)
		u.o.adminUser, u.password = user, password
	default:
		zero(password)
		return &Error{Exit: ExitFailure, Code: "first_admin_failed", Message: "Creating the first administrator failed: " + tail(out), Hint: "Check the password length (16 to 256 bytes) and docker compose logs control."}
	}
	return nil
}

func (u *upRun) credentials(ctx context.Context) error {
	if s := u.saved; s != nil && s.Token != "" {
		c, err := u.e.clientFor(u.url, s.Token, u.opts)
		if err != nil {
			return err
		}
		if _, err = c.get(ctx, apiPrefix+"/launch-spec-schema", nil, nil); err == nil && containsString(s.Roles, "admin") {
			u.admin = c
			u.say("using the saved admin token of context %s (expires %s)", u.ctxName, s.ExpiresAt)
			return nil
		} else if err == nil {
			u.say("the saved token of context %s is not an admin token; signing in to mint one", u.ctxName)
		} else {
			u.say("the saved token of context %s is not accepted (%s); signing in again", u.ctxName, asError(ctx, err).Code)
		}
	}
	seconds, err := lifetimeSeconds(u.o.tokenTTL)
	if err != nil {
		return err
	}
	c, err := u.e.clientFor(u.url, "", u.opts)
	if err != nil {
		return err
	}
	username, password := u.o.adminUser, u.password
	if password == nil {
		cred := u.o.cred
		cred.username = username
		if username, password, err = u.e.credentials(ctx, cred, "agentgate up"); err != nil {
			return err
		}
		defer zero(password)
	}
	host, _ := u.e.app.Hostname()
	name := strings.TrimSpace(tokenNameClean.ReplaceAllString("agentgate up on "+host, ""))
	if len(name) > 64 {
		name = name[:64]
	}
	created, subject, err := mintToken(ctx, c, username, password, []string{"admin"}, seconds, name, "Bring this machine online with agentgate up")
	if err != nil {
		return err
	}
	saved := &Context{Server: u.url.String(), Token: created.Token, TokenID: created.ID, TokenName: created.Name, Subject: subject, Roles: created.Roles, ExpiresAt: created.ExpiresAt,
		CAFile: u.opts.caFile, CertSHA256: u.opts.pin, AllowLoopbackHTTP: u.opts.allowLoopbackHTTP}
	st, err := u.e.store()
	if err != nil {
		return err
	}
	if err = st.update(func(cfg *Config) error {
		cfg.Contexts[u.ctxName] = saved
		cfg.CurrentContext = u.ctxName
		return nil
	}); err != nil {
		return err
	}
	u.saved = saved
	if u.admin, err = u.e.clientFor(u.url, created.Token, u.opts); err != nil {
		return err
	}
	u.say("signed in as %s; saved an admin token (expires %s) to context %s", subject, created.ExpiresAt, u.ctxName)
	return nil
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func (u *upRun) needsRootForHost() error {
	if u.o.skipHost || u.e.app.Euid() == 0 {
		return nil
	}
	return u.rootError("host agent", "install agentgate-hostd as a system service and enroll this machine",
		[]string{"agentgate target enroll", u.o.target, "--token-file", "TOKEN-FILE;", "agentgate-hostd install --service-url", u.url.String(), "--token-file", "TOKEN-FILE"})
}

func (u *upRun) targetStep(ctx context.Context) error {
	var t Target
	_, err := u.admin.get(ctx, apiPrefix+"/targets/"+pathEscape(u.o.target), nil, &t)
	var ce *Error
	switch {
	case errors.As(err, &ce) && ce.Exit == ExitNotFound:
		if err := u.needsRootForHost(); err != nil {
			return err
		}
		if u.o.skipHost {
			u.say("target %s does not exist; --skip-host leaves it to you (agentgate target add %s)", u.o.target, u.o.target)
			return nil
		}
		var out TargetEnrollment
		if _, err := u.admin.mutate(ctx, "POST", apiPrefix+"/targets", map[string]string{"name": u.o.target, "reason": "Enroll this machine with agentgate up"}, false, &out); err != nil {
			return err
		}
		u.target, u.token = out.Target, out.Enrollment.Token
		u.say("created target %s (%s) with a one-time enrollment token (kept in memory)", out.Target.Name, out.Target.ID)
		return nil
	case err != nil:
		return err
	}
	u.target = t
	switch t.State {
	case "pending":
		if err := u.needsRootForHost(); err != nil {
			return err
		}
		if u.o.skipHost {
			u.say("target %s waits for its host agent; --skip-host leaves that to you", t.Name)
			return nil
		}
		var out TargetEnrollment
		if _, err := u.admin.mutate(ctx, "POST", apiPrefix+"/targets/"+pathEscape(t.ID)+"/enrollment", map[string]string{"reason": "Enroll this machine with agentgate up"}, false, &out); err != nil {
			return err
		}
		u.target, u.token = out.Target, out.Enrollment.Token
		u.say("target %s exists but no host enrolled; issued a new one-time token (kept in memory)", t.Name)
	case "awaiting_key_approval":
		u.say("target %s: a host presented key %s; it waits for approval", t.Name, t.HostKeyID)
	case "active":
		u.say("target %s is active (host key %s)", t.Name, t.HostKeyID)
	case "rekey_required":
		return &Error{Exit: ExitConflict, Code: "rekey_required", Message: "Target " + t.Name + " must enroll again after a job key rotation.", Hint: "On the host: remove the host agent's identity (see agentgate-hostd), then agentgate target enroll " + t.Name + " --token-file F and agentgate-hostd install --token-file F"}
	case "retired":
		return &Error{Exit: ExitConflict, Code: "target_retired", Message: "Target " + t.Name + " is retired.", Hint: "Choose another name with --target."}
	default:
		return &Error{Exit: ExitConflict, Code: "target_state", Message: "Target " + t.Name + " is in state " + t.State + "."}
	}
	return nil
}

// hostdStatus is the part of agentgate-hostd status the CLI reads.
type hostdStatus struct {
	Enrolled        bool     `json:"enrolled"`
	TargetID        string   `json:"target_id"`
	HostKeyID       string   `json:"host_key_id"`
	Runtime         string   `json:"runtime"`
	MountRoots      []string `json:"mount_roots"`
	MountRootsError string   `json:"mount_roots_error"`
	SecretRoot      string   `json:"secret_root"`
	Broker          *struct {
		Image         string `json:"image"`
		UID           int    `json:"uid"`
		GID           int    `json:"gid"`
		EgressNetwork string `json:"egress_network"`
		Pool          string `json:"pool"`
	} `json:"broker"`
}

// brokerReport says whether a target can run launches with secrets and,
// when it cannot, why and what to do. local is this machine's own
// agentgate-hostd status when it is that target's host (nil otherwise).
func brokerReport(t Target, local *hostdStatus) (bool, string, string) {
	for _, c := range t.Capabilities {
		if c == hostproto.CapabilityBrokeredSecrets {
			return true, "the host runs a credential broker per launch", ""
		}
	}
	for _, c := range t.Capabilities {
		if c == hostproto.CapabilityAppliance {
			return false, "the appliance runtime does not run credential brokers, so launches with secrets are refused", "use a docker-host target for launches with secrets"
		}
	}
	switch {
	case local != nil && local.Broker == nil:
		return false, "this host's agentgate-hostd was installed without a credential broker (--broker-image), so launches with secrets are refused",
			"sudo agentgate up --broker-image agentgate-broker@sha256:<digest> [--broker-egress-network NET] (or agentgate-hostd install ... --broker-image ...; see docs/BROKER.md)"
	case local != nil:
		return false, fmt.Sprintf("agentgate-hostd is configured with broker image %s and egress network %s but does not report brokered-secrets: the image is not on this host, the network does not exist, or the secret store %s is unusable",
				local.Broker.Image, local.Broker.EgressNetwork, local.SecretRoot),
			"docker image inspect " + local.Broker.Image + "; docker network inspect " + local.Broker.EgressNetwork + " (docker network create " + local.Broker.EgressNetwork + "); then sudo systemctl restart agentgate-hostd"
	}
	return false, "the host does not report brokered-secrets, so launches with secrets are refused (it does only with --broker-image, the broker image and its egress network present, and its secret store usable)",
		"on the host: sudo agentgate-hostd status (broker: null means not configured), then agentgate up --broker-image ... or agentgate-hostd install ... --broker-image ... (see docs/BROKER.md)"
}

func (u *upRun) readHostdStatus(ctx context.Context) (*hostdStatus, error) {
	res, err := u.runCmd(ctx, u.hostd, []string{"status", "--state-dir", u.o.stateDir}, nil, false)
	if err != nil {
		return nil, err
	}
	if res.Exit != 0 {
		return nil, errors.New(tail(res.Stderr))
	}
	var s hostdStatus
	if err := json.Unmarshal(res.Stdout, &s); err != nil {
		return nil, errors.New("unreadable status output")
	}
	if s.HostKeyID == "" {
		if m := fingerprintText.Find(res.Stdout); m != nil {
			s.HostKeyID = string(m)
		}
	}
	return &s, nil
}

func (u *upRun) findHostd() error {
	if u.hostd != "" {
		return nil
	}
	if u.o.hostd != "" {
		u.hostd = u.o.hostd
	} else if p, err := u.e.app.Runner.LookPath("agentgate-hostd"); err == nil {
		u.hostd = p
	} else if info, err := os.Stat("/usr/local/sbin/agentgate-hostd"); err == nil && info.Mode().IsRegular() {
		u.hostd = "/usr/local/sbin/agentgate-hostd"
	}
	if u.hostd == "" {
		return &Error{Exit: ExitUsage, Code: "hostd_missing", Message: "agentgate-hostd is not installed on this machine.", Hint: "Build it (go build ./cmd/agentgate-hostd) and pass --hostd PATH, or put it in PATH."}
	}
	if !filepath.IsAbs(u.hostd) {
		abs, err := filepath.Abs(u.hostd)
		if err != nil {
			return usageError("--hostd: %v", err)
		}
		u.hostd = abs
	}
	return nil
}

func (u *upRun) hostAgent(ctx context.Context) error {
	if u.o.skipHost {
		u.say("skipped (--skip-host)")
		return nil
	}
	if err := u.findHostd(); err != nil {
		return err
	}
	root := u.e.app.Euid() == 0
	if root {
		if s, err := u.readHostdStatus(ctx); err == nil && s.Enrolled {
			if s.TargetID != u.target.ID {
				return &Error{Exit: ExitConflict, Code: "host_enrolled_elsewhere", Message: "This machine's host agent is enrolled as target " + s.TargetID + ", not " + u.target.Name + " (" + u.target.ID + ").", Hint: "Use --target with that target's name, or uninstall the host agent first."}
			}
			u.localKey, u.localTarget, u.local = s.HostKeyID, s.TargetID, s
			u.say("agentgate-hostd is installed and enrolled as target %s", u.target.Name)
			return u.reconfigureHost(ctx, s)
		}
	}
	if u.token == "" {
		if !root {
			u.say("target %s is already enrolled by a host; this step cannot inspect agentgate-hostd without root", u.target.Name)
			return nil
		}
		return &Error{Exit: ExitConflict, Code: "enrolled_by_another_host", Message: "Target " + u.target.Name + " is enrolled by a host, but this machine's agent is not enrolled.", Hint: "If this machine should be that target, issue a new token (agentgate target enroll " + u.target.Name + ") and re-run; otherwise choose another --target."}
	}
	if !root {
		return u.rootError("host agent", "install agentgate-hostd as a system service and enroll this machine",
			[]string{"agentgate target enroll", u.target.Name, "--token-file", "TOKEN-FILE;", u.hostd, "install --service-url", u.url.String(), "--token-file", "TOKEN-FILE"})
	}
	dir, err := os.MkdirTemp("", "agentgate-up-")
	if err != nil {
		return failure("cannot create a private temporary directory: %v", err)
	}
	defer os.RemoveAll(dir)
	tokenFile := filepath.Join(dir, "enrollment-token")
	if err = writeTokenFile(tokenFile, u.token); err != nil {
		return err
	}
	args := u.installArgs(tokenFile)
	u.say("installing the host agent: %s %s", u.hostd, strings.Join(args, " "))
	res, err := u.runCmd(ctx, u.hostd, args, nil, true)
	os.Remove(tokenFile)
	u.token = ""
	if err != nil {
		return err
	}
	if res.Exit != 0 {
		return &Error{Exit: ExitFailure, Code: "hostd_install_failed", Message: "agentgate-hostd install failed: " + tail(append(res.Stdout, res.Stderr...)), Hint: "Fix what it names; the enrollment token may be spent, and re-running issues a new one."}
	}
	// The host key id comes from agentgate-hostd status, which derives it
	// from the key file itself; the install output is shown, never parsed.
	if s, err := u.readHostdStatus(ctx); err == nil && s.HostKeyID != "" {
		u.localKey, u.localTarget, u.local = s.HostKeyID, s.TargetID, s
	}
	if u.localKey != "" {
		u.say("this machine's host key: %s", u.localKey)
	} else {
		u.say("agentgate-hostd did not print its host key fingerprint")
	}
	return nil
}

// installArgs is agentgate-hostd install for this machine: the service, the
// runtime, the broker and the mount roots; tokenFile is empty when the host
// is already enrolled (install then reconfigures it and spends no token).
func (u *upRun) installArgs(tokenFile string) []string {
	args := []string{"install", "--service-url", u.url.String()}
	if tokenFile != "" {
		args = append(args, "--token-file", tokenFile)
	}
	args = append(args, "--runtime", u.o.runtime, "--state-dir", u.o.stateDir)
	if u.opts.caFile != "" {
		args = append(args, "--ca-file", u.opts.caFile)
	}
	if u.url.Scheme == "http" {
		args = append(args, "--allow-loopback-http")
	}
	for _, kv := range [][2]string{{"--instance", u.o.instance}, {"--appliance-state", u.o.applianceState}, {"--source", u.o.source}} {
		if kv[1] != "" {
			args = append(args, kv[0], kv[1])
		}
	}
	args = append(args, u.o.broker.args()...)
	for _, root := range u.o.mountRoots {
		args = append(args, "--mount-root", root)
	}
	return args
}

// reconfigureHost applies broker settings or mount roots that an enrolled
// host agent lacks: install again without a token for the broker (it
// restarts the agent only when no job is unfinished), mount-roots for the
// roots (read per job; no restart).
func (u *upRun) reconfigureHost(ctx context.Context, s *hostdStatus) error {
	switch {
	case u.o.broker.differs(s):
		args := u.installArgs("")
		u.say("the host agent lacks the requested broker settings; reconfiguring it: %s %s", u.hostd, strings.Join(args, " "))
		res, err := u.runCmd(ctx, u.hostd, args, nil, true)
		if err != nil {
			return err
		}
		if res.Exit != 0 {
			return &Error{Exit: ExitFailure, Code: "hostd_install_failed", Message: "agentgate-hostd install failed: " + tail(append(res.Stdout, res.Stderr...)), Hint: "Fix what it names; the host stays enrolled."}
		}
	case len(u.o.mountRoots) > 0 && strings.Join(s.MountRoots, "\x00") != strings.Join(u.o.mountRoots, "\x00"):
		args := []string{"mount-roots", "--state-dir", u.o.stateDir}
		for _, root := range u.o.mountRoots {
			args = append(args, "--root", root)
		}
		u.say("setting this host's mount roots: %s %s", u.hostd, strings.Join(args, " "))
		res, err := u.runCmd(ctx, u.hostd, args, nil, false)
		if err != nil {
			return err
		}
		if res.Exit != 0 {
			return &Error{Exit: ExitFailure, Code: "mount_roots_failed", Message: "agentgate-hostd mount-roots failed: " + tail(append(res.Stdout, res.Stderr...)), Hint: "Fix what it names."}
		}
	default:
		return nil
	}
	if fresh, err := u.readHostdStatus(ctx); err == nil {
		u.local = fresh
	}
	return nil
}

func (u *upRun) refreshTarget(ctx context.Context) error {
	_, err := u.admin.get(ctx, apiPrefix+"/targets/"+pathEscape(u.target.ID), nil, &u.target)
	return err
}

// pinLocal pins the key this machine's own host agent reported (the out-of-
// band anchor), only when the service reports the same key for the same
// target; a service answer alone never becomes a pin. A service that shows a
// different key or target for this machine's own host agent is a trust
// failure, and nothing is pinned.
func (u *upRun) pinLocal() error {
	if u.localKey == "" {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(u.localKey), []byte(u.target.HostKeyID)) != 1 || (u.localTarget != "" && u.localTarget != u.target.ID) {
		return trustError("host_key_mismatch", "This machine's host agent has key "+u.localKey+" for target "+u.localTarget+", but the service shows key "+u.target.HostKeyID+" for target "+u.target.Name+" ("+u.target.ID+"). Nothing was pinned.",
			"Do not store secrets on this target until you know why: issue a new token (agentgate target enroll "+u.target.Name+") and install the host agent again.")
	}
	u.e.server = u.url
	if st, err := u.e.store(); err == nil {
		if k, err := st.loadTrust(); err == nil {
			if pin := k.find(u.url.String(), u.target.ID); pin != nil && pin.HostKeyID == u.localKey {
				return nil
			}
		}
	}
	if _, err := u.e.pinTarget(u.target, u.localKey, "up", false); err == nil {
		u.say("pinned host key %s on this machine for secret set", u.localKey)
	} else {
		u.say("could not pin the host key: %s", asError(context.Background(), err).Message)
	}
	return nil
}

func (u *upRun) keyApproval(ctx context.Context) error {
	if u.o.skipHost && u.target.ID == "" {
		u.say("skipped (--skip-host)")
		return nil
	}
	if err := u.refreshTarget(ctx); err != nil {
		return err
	}
	t := u.target
	switch t.State {
	case "active":
		u.say("approved (host key %s)", t.HostKeyID)
		return u.pinLocal()
	case "awaiting_key_approval":
	case "pending":
		if u.o.skipHost {
			u.say("skipped: no host has enrolled (--skip-host)")
			return nil
		}
		return &Error{Exit: ExitConflict, Code: "not_enrolled", Message: "Target " + t.Name + " has no enrolled host yet.", Hint: "Check the host agent output above (systemctl status agentgate-hostd)."}
	default:
		return &Error{Exit: ExitConflict, Code: "target_state", Message: "Target " + t.Name + " is " + t.State + "."}
	}
	u.say("host key presented to the service: %s", t.HostKeyID)
	if u.localKey != "" {
		if subtle.ConstantTimeCompare([]byte(u.localKey), []byte(t.HostKeyID)) != 1 {
			return trustError("fingerprint_mismatch", "This machine's host agent has key "+u.localKey+", but the service shows "+t.HostKeyID+" for target "+t.Name+". Do not approve.",
				"Something enrolled a different key with this target's token: issue a new token (agentgate target enroll "+t.Name+") and install the host agent again.")
		}
		u.say("host key reported by this machine's agent:  %s (they match)", u.localKey)
	}
	if u.o.approve {
		if !u.e.app.Term.IsTerminal(0) || !u.e.app.Term.IsTerminal(2) {
			return usageError("--approve needs an interactive terminal to confirm the fingerprint")
		}
		if u.saved == nil || !containsString(u.saved.Roles, "admin") {
			return &Error{Exit: ExitForbidden, Code: "forbidden", Message: "The signed-in identity is not an administrator, so it cannot approve host keys.", Hint: "An administrator runs agentgate target approve-key " + t.Name + " --host-key-id <host's fingerprint>."}
		}
		if u.localKey == "" {
			return trustError("fingerprint_unknown", "The host agent did not report its fingerprint on this machine, so agentgate cannot compare it for you.",
				"Read the fingerprint on the host console, then approve with agentgate target approve-key "+t.Name+" --host-key-id <host's fingerprint>.")
		}
		last := u.localKey[len(u.localKey)-8:]
		u.say("agentgate-hostd on this machine printed host key id %s", u.localKey)
		u.say("the service shows the same id for target %s; approving activates this key for it", t.Name)
		answer, err := u.e.readLine(ctx, "      To approve it, type the last 8 characters of that id (or the whole id): ")
		if err != nil {
			return err
		}
		answer = strings.TrimSpace(answer)
		if subtle.ConstantTimeCompare([]byte(answer), []byte(last)) != 1 && subtle.ConstantTimeCompare([]byte(answer), []byte(u.localKey)) != 1 {
			return &Error{Exit: ExitUsage, Code: "not_confirmed", Message: "The characters do not match; the key was not approved."}
		}
		if _, err = u.admin.mutate(ctx, "POST", apiPrefix+"/targets/"+pathEscape(t.ID)+"/approve-key", map[string]string{"host_key_id": u.localKey, "reason": "Approved with agentgate up after comparing this machine's host agent fingerprint"}, true, &u.target); err != nil {
			return err
		}
		u.say("approved host key %s; target %s is %s", u.localKey, u.target.Name, u.target.State)
		return u.pinLocal()
	}
	u.say("an administrator approves it after comparing it with the host console:")
	u.say("  agentgate target approve-key %s --host-key-id <host's fingerprint>", t.Name)
	u.say("  (or, as that administrator on this machine: agentgate up --approve)")
	if u.o.waitTimeout <= 0 {
		return &Error{Exit: ExitApprovalPending, Code: "key_approval_pending", Message: "The host key of target " + t.Name + " waits for approval.", Hint: "After approval, run agentgate up again."}
	}
	u.say("waiting up to %s for the approval (Ctrl-C stops waiting; nothing is undone)", u.o.waitTimeout)
	deadline := time.Now().Add(u.o.waitTimeout)
	for time.Now().Before(deadline) {
		if err := u.e.app.Sleep(ctx, upPollInterval); err != nil {
			return &Error{Exit: ExitInterrupted, Code: "interrupted", Message: "Stopped waiting for the key approval; run agentgate up again after it."}
		}
		if err := u.refreshTarget(ctx); err != nil {
			return err
		}
		if u.target.State == "active" {
			u.say("approved by an administrator (host key %s)", u.target.HostKeyID)
			return u.pinLocal()
		}
		if u.target.State != "awaiting_key_approval" {
			return &Error{Exit: ExitConflict, Code: "target_state", Message: "Target " + t.Name + " moved to " + u.target.State + " while waiting for approval."}
		}
	}
	return &Error{Exit: ExitApprovalPending, Code: "key_approval_pending", Message: "The host key of target " + t.Name + " still waits for approval after " + u.o.waitTimeout.String() + ".", Hint: "After an administrator approves it, run agentgate up again."}
}

func (u *upRun) provision(ctx context.Context) error {
	if u.o.skipHost {
		u.say("skipped (--skip-host)")
		return nil
	}
	if u.o.runtime == "appliance" {
		if u.e.app.Euid() != 0 {
			return u.rootError("provision", "start the appliance through agentgate-hostd", []string{u.hostd, "provision --state-dir", u.o.stateDir})
		}
		res, err := u.runCmd(ctx, u.hostd, []string{"provision", "--state-dir", u.o.stateDir}, nil, true)
		if err != nil {
			return err
		}
		if res.Exit != 0 {
			return &Error{Exit: ExitFailure, Code: "provision_failed", Message: "agentgate-hostd provision failed: " + tail(append(res.Stdout, res.Stderr...)), Hint: "The appliance error above is verbatim; fix it and re-run."}
		}
		u.say("the appliance reported ready=true")
	} else {
		u.say("docker-host runtime: nothing to start here (the POC instance comes from poc/ssh-diagnostic/configure.py; agentgate-hostd checked it at install)")
	}
	deadline := time.Now().Add(onlineWait)
	for {
		if err := u.refreshTarget(ctx); err != nil {
			return err
		}
		if u.target.Online {
			u.say("target %s is online (last poll %s)", u.target.Name, age(u.target.LastSeen, u.e.app.Now()))
			return nil
		}
		if time.Now().After(deadline) {
			u.e.p.warn("target %s has not polled the service yet; check systemctl status agentgate-hostd on this machine", u.target.Name)
			return nil
		}
		if err := u.e.app.Sleep(ctx, upPollInterval); err != nil {
			return err
		}
	}
}

func (u *upRun) ready(ctx context.Context) error {
	out := map[string]any{"ui": u.url.String(), "context": u.ctxName, "target": u.target, "kernel_verified": false}
	var available bool
	var why, fix string
	if u.target.ID != "" && u.target.State == "active" {
		local := u.local
		if local != nil && local.TargetID != u.target.ID {
			local = nil
		}
		available, why, fix = brokerReport(u.target, local)
		out["brokered_secrets"] = map[string]any{"available": available, "detail": why, "fix": fix}
	}
	if u.e.g.json {
		return u.e.p.value(out)
	}
	if why != "" && !available {
		u.e.p.warn("brokered secrets are not available on %s: %s; to fix: %s", u.target.Name, why, fix)
	}
	u.say("AgentGate is up.")
	u.say("  UI:      %s", u.url)
	u.say("  context: %s (saved admin token)", u.ctxName)
	if u.target.ID != "" {
		u.say("  target:  %s (%s, host key %s)", u.target.Name, u.target.State, u.target.HostKeyID)
	}
	u.say("  note:    enforcement has not been verified on a BPF LSM kernel (kernel_verified=false)")
	u.say("Next:")
	u.say("  agentgate profile new dev --preset python-dev")
	u.say("  agentgate grant dev read /srv/data")
	u.say("  agentgate launch --profile dev --image IMAGE@sha256:DIGEST --dry-run -- python3 -m pytest")
	return nil
}

// prefixWriter indents delegated command output line by line.
type prefixWriter struct {
	w      io.Writer
	prefix string
	mid    bool
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	for _, line := range bytes.SplitAfter(b, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if !p.mid {
			io.WriteString(p.w, p.prefix)
		}
		p.w.Write([]byte(redactText(string(line))))
		p.mid = line[len(line)-1] != '\n'
	}
	return len(b), nil
}
