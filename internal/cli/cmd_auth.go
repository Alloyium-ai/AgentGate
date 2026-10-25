// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"context"
	"flag"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var tokenNameClean = regexp.MustCompile(`[^A-Za-z0-9 ._-]`)

const defaultTokenLifetime = 30 * 24 * time.Hour

func init() {
	register(&command{name: "login", args: "URL", summary: "Sign in to a service and save an API token (mode 0600) as a context.",
		help: `Without --token-stdin, signs in with a local username and password, mints an API token with
your roles (or --role), and saves it. The token itself is never printed.

  --token-stdin        save an existing agt_ token read from standard input (or a hidden prompt)
  --role ROLE          token role; repeat or comma-separate (default: every role you hold)
  --expires DUR        token lifetime, 1h to 90d (default 30d)
  --token-name NAME    token label (default: agentgate-cli on HOSTNAME)
  --save-as NAME       context name to save (default: the current context, or "default")
` + credentialHelp,
		setup: func(fs *flag.FlagSet) runner {
			var cred credentialFlags
			cred.register(fs)
			var roles listFlag
			fs.Var(&roles, "role", "")
			tokenStdin := fs.Bool("token-stdin", false, "")
			expires := fs.String("expires", "30d", "")
			name := fs.String("token-name", "", "")
			saveAs := fs.String("save-as", "", "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				return e.login(ctx, args, cred, roles, *tokenStdin, *expires, *name, *saveAs)
			}
		}})
	register(&command{name: "logout", summary: "Remove the saved token of the current context (--revoke also revokes it).",
		help: "  --revoke    sign in with your password and revoke the token on the service first\n" + credentialHelp,
		setup: func(fs *flag.FlagSet) runner {
			var cred credentialFlags
			cred.register(fs)
			revoke := fs.Bool("revoke", false, "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 0 {
					return usageError("logout takes no arguments (choose the context with --context)")
				}
				return e.logout(ctx, cred, *revoke)
			}
		}})
	register(&command{name: "whoami", summary: "Show the context, service and token in use, and check that the service accepts it.",
		setup: func(fs *flag.FlagSet) runner {
			return func(ctx context.Context, e *env, args, _ []string) error { return e.whoami(ctx) }
		}})
	register(&command{name: "context ls", summary: "List saved contexts.", setup: func(fs *flag.FlagSet) runner {
		return func(ctx context.Context, e *env, args, _ []string) error { return e.contextList() }
	}})
	register(&command{name: "context use", args: "NAME", summary: "Make a saved context the current one.", setup: func(fs *flag.FlagSet) runner {
		return func(ctx context.Context, e *env, args, _ []string) error {
			if len(args) != 1 {
				return usageError("context use takes one context name")
			}
			return e.contextUse(args[0])
		}
	}})
	register(&command{name: "context rm", args: "NAME", summary: "Delete a saved context and its token from this machine.", setup: func(fs *flag.FlagSet) runner {
		return func(ctx context.Context, e *env, args, _ []string) error {
			if len(args) != 1 {
				return usageError("context rm takes one context name")
			}
			return e.contextRemove(args[0])
		}
	}})
	register(&command{name: "token create", summary: "Mint an API token (password sign-in); prints it once, or --save stores it.",
		help: `  --role ROLE          token role; repeat or comma-separate (default: every role you hold)
  --expires DUR        lifetime, 1h to 90d (default 30d)
  --name NAME          token label
  --save               store the token in the current context instead of printing it
` + credentialHelp,
		setup: func(fs *flag.FlagSet) runner {
			var cred credentialFlags
			cred.register(fs)
			var roles listFlag
			fs.Var(&roles, "role", "")
			expires := fs.String("expires", "30d", "")
			name := fs.String("name", "", "")
			save := fs.Bool("save", false, "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 0 {
					return usageError("token create takes no arguments")
				}
				return e.tokenCreate(ctx, cred, roles, *expires, *name, *save)
			}
		}})
	register(&command{name: "token ls", summary: "List your API tokens (an administrator sees every token).", help: credentialHelp,
		setup: func(fs *flag.FlagSet) runner {
			var cred credentialFlags
			cred.register(fs)
			return func(ctx context.Context, e *env, args, _ []string) error { return e.tokenList(ctx, cred) }
		}})
	register(&command{name: "token revoke", args: "ID", summary: "Revoke an API token.", help: "  --reason TEXT\n" + credentialHelp,
		setup: func(fs *flag.FlagSet) runner {
			var cred credentialFlags
			cred.register(fs)
			reason := fs.String("reason", "", "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 1 {
					return usageError("token revoke takes one token id (agentgate token ls)")
				}
				return e.tokenRevoke(ctx, cred, args[0], *reason)
			}
		}})
}

func defaultTokenName(e *env) string {
	host, _ := e.app.Hostname()
	host = tokenNameClean.ReplaceAllString(host, "")
	name := "agentgate-cli"
	if host != "" {
		name += " on " + host
	}
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

func lifetimeSeconds(v string) (int, error) {
	d, err := parseLifetime(v)
	if err != nil {
		return 0, usageError("--expires: %v", err)
	}
	if d < time.Hour || d > 90*24*time.Hour {
		return 0, usageError("--expires is between 1h and 90d")
	}
	return int(d / time.Second), nil
}

// loginTarget builds a token-less client for an explicit URL with only the
// trust settings given on this command line.
func (e *env) loginTarget(args []string) (*url.URL, transportOptions, error) {
	raw := e.g.server
	switch {
	case len(args) == 1:
		raw = args[0]
	case len(args) > 1:
		return nil, transportOptions{}, usageError("login takes one service URL")
	}
	if raw == "" {
		return nil, transportOptions{}, usageError("login needs the service URL, for example agentgate login https://localhost:9443")
	}
	u, err := serverURL(raw)
	if err != nil {
		return nil, transportOptions{}, err
	}
	o := transportOptions{caFile: e.g.caFile, pin: e.g.pinCert, allowLoopbackHTTP: e.g.insecure}
	if o.caFile != "" {
		abs, err := filepath.Abs(o.caFile)
		if err != nil {
			return nil, o, usageError("--ca-file: %v", err)
		}
		o.caFile = abs
	}
	if o.pin != "" {
		if o.pin, err = normalizePin(o.pin); err != nil {
			return nil, o, err
		}
	}
	return u, o, nil
}

func (e *env) login(ctx context.Context, args []string, cred credentialFlags, roles []string, tokenStdin bool, expires, name, saveAs string) error {
	u, o, err := e.loginTarget(args)
	if err != nil {
		return err
	}
	if saveAs == "" {
		cfg, err := e.config()
		if err != nil {
			return err
		}
		saveAs = e.contextName(cfg)
	}
	if err := validContextName(saveAs); err != nil {
		return err
	}
	saved := &Context{Server: u.String(), CAFile: o.caFile, CertSHA256: o.pin, AllowLoopbackHTTP: o.allowLoopbackHTTP}
	if tokenStdin {
		if cred.username != "" || cred.passwordStdin || cred.passwordFile != "" || len(roles) > 0 {
			return usageError("--token-stdin saves an existing token; it takes no sign-in or role flags")
		}
		token, err := e.readTokenInput(ctx)
		if err != nil {
			return err
		}
		c, err := e.clientFor(u, token, o)
		if err != nil {
			return err
		}
		if _, err = c.get(ctx, apiPrefix+"/launch-spec-schema", nil, nil); err != nil {
			return err
		}
		saved.Token = token
	} else {
		seconds, err := lifetimeSeconds(expires)
		if err != nil {
			return err
		}
		if name == "" {
			name = defaultTokenName(e)
		}
		c, err := e.clientFor(u, "", o)
		if err != nil {
			return err
		}
		username, password, err := e.credentials(ctx, cred, "login")
		if err != nil {
			return err
		}
		created, subject, err := mintToken(ctx, c, username, password, roles, seconds, name, "Sign in the agentgate CLI")
		zero(password)
		if err != nil {
			return err
		}
		saved.Token, saved.TokenID, saved.TokenName, saved.Subject, saved.Roles, saved.ExpiresAt = created.Token, created.ID, created.Name, subject, created.Roles, created.ExpiresAt
	}
	st, err := e.store()
	if err != nil {
		return err
	}
	if err = st.update(func(cfg *Config) error {
		cfg.Contexts[saveAs] = saved
		cfg.CurrentContext = saveAs
		return nil
	}); err != nil {
		return err
	}
	out := map[string]any{"context": saveAs, "server": saved.Server, "subject": saved.Subject, "roles": saved.Roles, "token_id": saved.TokenID, "token_name": saved.TokenName, "expires_at": saved.ExpiresAt, "config": filepath.Join(st.dir, configFileName)}
	if e.g.json {
		return e.p.value(out)
	}
	who := saved.Subject
	if who == "" {
		who = "the token's holder"
	}
	e.p.line("Signed in to %s as %s.", saved.Server, who)
	if saved.TokenID != "" {
		e.p.line("Token %q (%s), roles %s, expires %s.", saved.TokenName, saved.TokenID, joinOr(saved.Roles, "-"), saved.ExpiresAt)
	}
	e.p.line("Saved to context %q in %s (mode 0600). The token is not shown.", saveAs, filepath.Join(st.dir, configFileName))
	return nil
}

func (e *env) readTokenInput(ctx context.Context) (string, error) {
	var raw []byte
	var err error
	if e.app.Term.IsTerminal(0) {
		raw, err = e.app.Term.ReadSecret(ctx, "API token (input hidden): ")
	} else {
		raw, err = e.readStdinSecret()
	}
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	zero(raw)
	if !apiTokenFormat.MatchString(token) {
		return "", usageError("an API token is agt_ followed by 43 characters")
	}
	return token, nil
}

// mintToken signs in, creates a token and signs out.
func mintToken(ctx context.Context, c *Client, username string, password []byte, roles []string, seconds int, name, reason string) (CreatedToken, string, error) {
	var created CreatedToken
	s, err := signIn(ctx, c, username, password)
	if err != nil {
		return created, "", err
	}
	defer s.close(ctx)
	if len(roles) == 0 {
		roles = s.info.Actor.Roles
	}
	if len(roles) == 0 {
		return created, "", &Error{Exit: ExitForbidden, Code: "no_roles", Message: "Your account holds no roles.", Hint: "Ask an administrator to grant you a role."}
	}
	body := map[string]any{"name": name, "roles": roles, "expires_in_seconds": seconds, "reason": reason}
	if _, err = s.call(ctx, "POST", apiPrefix+"/api-tokens", body, &created); err != nil {
		return created, "", err
	}
	if !apiTokenFormat.MatchString(created.Token) {
		return created, "", &Error{Exit: ExitServer, Code: "invalid_response", Message: "The service returned a token in an unknown format."}
	}
	return created, s.info.Actor.Subject, nil
}

func (e *env) logout(ctx context.Context, cred credentialFlags, revoke bool) error {
	st, err := e.store()
	if err != nil {
		return err
	}
	cfg, err := e.config()
	if err != nil {
		return err
	}
	name := e.contextName(cfg)
	saved := cfg.Contexts[name]
	if saved == nil || saved.Token == "" {
		return &Error{Exit: ExitNotFound, Code: "not_signed_in", Message: "Context " + name + " holds no token.", Hint: "agentgate context ls lists the contexts."}
	}
	if revoke {
		if saved.TokenID == "" {
			return usageError("the saved token's id is unknown (it was saved with --token-stdin); revoke it with agentgate token revoke ID or in the UI")
		}
		u, err := serverURL(saved.Server)
		if err != nil {
			return err
		}
		c, err := e.clientFor(u, "", transportOptions{caFile: saved.CAFile, pin: saved.CertSHA256, allowLoopbackHTTP: saved.AllowLoopbackHTTP})
		if err != nil {
			return err
		}
		username, password, err := e.credentials(ctx, cred, "logout --revoke")
		if err != nil {
			return err
		}
		s, err := signIn(ctx, c, username, password)
		zero(password)
		if err != nil {
			return err
		}
		_, err = s.call(ctx, "DELETE", apiPrefix+"/api-tokens/"+pathEscape(saved.TokenID), map[string]string{"reason": "Sign out the agentgate CLI"}, nil)
		s.close(ctx)
		if err != nil {
			return err
		}
	}
	tokenID, expiresAt := saved.TokenID, saved.ExpiresAt
	if err = st.update(func(cfg *Config) error {
		if c := cfg.Contexts[name]; c != nil {
			c.Token, c.TokenID, c.TokenName, c.Subject, c.Roles, c.ExpiresAt = "", "", "", "", nil, ""
		}
		return nil
	}); err != nil {
		return err
	}
	if e.g.json {
		return e.p.value(map[string]any{"context": name, "removed": true, "revoked": revoke, "token_id": tokenID})
	}
	e.p.line("Removed the token from context %q.", name)
	if !revoke {
		if tokenID != "" {
			e.p.line("It stays valid on the service until %s; revoke it with: agentgate token revoke %s", expiresAt, tokenID)
		} else {
			e.p.line("It stays valid on the service until it expires; revoke it in the UI or with agentgate token revoke ID.")
		}
	}
	return nil
}

func (e *env) whoami(ctx context.Context) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	source := "context " + e.ctxName
	if e.app.Getenv("AGENTGATE_TOKEN") != "" {
		source = "AGENTGATE_TOKEN"
	}
	if _, err = c.get(ctx, apiPrefix+"/launch-spec-schema", nil, nil); err != nil {
		return err
	}
	out := map[string]any{"context": e.ctxName, "server": e.server.String(), "token_source": source, "accepted": true}
	if source != "AGENTGATE_TOKEN" {
		out["subject"], out["roles"], out["token_id"], out["token_name"], out["expires_at"] = e.ctx.Subject, e.ctx.Roles, e.ctx.TokenID, e.ctx.TokenName, e.ctx.ExpiresAt
	}
	if e.g.json {
		return e.p.value(out)
	}
	pairs := [][2]string{{"context", e.ctxName}, {"server", e.server.String()}, {"token from", source}}
	if source != "AGENTGATE_TOKEN" {
		subject := e.ctx.Subject
		if subject == "" {
			subject = "unknown (saved with --token-stdin)"
		}
		pairs = append(pairs, [2]string{"subject", subject}, [2]string{"roles", joinOr(e.ctx.Roles, "unknown")})
		if e.ctx.TokenID != "" {
			pairs = append(pairs, [2]string{"token", e.ctx.TokenName + " (" + e.ctx.TokenID + ")"}, [2]string{"expires", e.ctx.ExpiresAt + " (" + age(e.ctx.ExpiresAt, e.app.Now()) + ")"})
		}
	}
	pairs = append(pairs, [2]string{"service", "accepts the token"})
	e.p.fields("", pairs)
	return nil
}

func (e *env) contextList() error {
	cfg, err := e.config()
	if err != nil {
		return err
	}
	current := e.contextName(cfg)
	if e.g.json {
		type row struct {
			Name      string   `json:"name"`
			Current   bool     `json:"current"`
			Server    string   `json:"server"`
			Subject   string   `json:"subject,omitempty"`
			Roles     []string `json:"roles,omitempty"`
			ExpiresAt string   `json:"expires_at,omitempty"`
			HasToken  bool     `json:"has_token"`
		}
		rows := []row{}
		for _, n := range contextNames(cfg) {
			c := cfg.Contexts[n]
			rows = append(rows, row{n, n == current, c.Server, c.Subject, c.Roles, c.ExpiresAt, c.Token != ""})
		}
		return e.p.value(map[string]any{"items": rows})
	}
	if e.g.quiet {
		for _, n := range contextNames(cfg) {
			e.p.line("%s", n)
		}
		return nil
	}
	rows := [][]string{}
	for _, n := range contextNames(cfg) {
		c := cfg.Contexts[n]
		mark := ""
		if n == current {
			mark = "*"
		}
		token := "no"
		if c.Token != "" {
			token = "yes"
		}
		rows = append(rows, []string{mark, n, c.Server, c.Subject, joinOr(c.Roles, ""), token, c.ExpiresAt})
	}
	e.p.table([]string{"", "NAME", "SERVER", "SUBJECT", "ROLES", "TOKEN", "EXPIRES"}, rows)
	return nil
}

func (e *env) contextUse(name string) error {
	st, err := e.store()
	if err != nil {
		return err
	}
	if err = st.update(func(cfg *Config) error {
		if cfg.Contexts[name] == nil {
			return &Error{Exit: ExitNotFound, Code: "not_found", Message: "No saved context " + name + ".", Hint: "agentgate context ls lists them."}
		}
		cfg.CurrentContext = name
		return nil
	}); err != nil {
		return err
	}
	e.p.note("Current context: %s", name)
	return nil
}

func (e *env) contextRemove(name string) error {
	st, err := e.store()
	if err != nil {
		return err
	}
	var tokenID string
	if err = st.update(func(cfg *Config) error {
		c := cfg.Contexts[name]
		if c == nil {
			return &Error{Exit: ExitNotFound, Code: "not_found", Message: "No saved context " + name + ".", Hint: "agentgate context ls lists them."}
		}
		tokenID = c.TokenID
		delete(cfg.Contexts, name)
		if cfg.CurrentContext == name {
			cfg.CurrentContext = ""
		}
		return nil
	}); err != nil {
		return err
	}
	e.p.note("Removed context %s.", name)
	if tokenID != "" {
		e.p.note("Its token %s stays valid on the service until it expires; revoke it with agentgate token revoke %s.", tokenID, tokenID)
	}
	return nil
}

// sessionClient is a token-less client for the current context's server.
func (e *env) sessionClient() (*Client, error) {
	if err := e.resolve(); err != nil {
		return nil, err
	}
	return e.clientFor(e.server, "", e.transportOptions())
}

func (e *env) tokenCreate(ctx context.Context, cred credentialFlags, roles []string, expires, name string, save bool) error {
	seconds, err := lifetimeSeconds(expires)
	if err != nil {
		return err
	}
	if name == "" {
		name = defaultTokenName(e)
	}
	c, err := e.sessionClient()
	if err != nil {
		return err
	}
	username, password, err := e.credentials(ctx, cred, "token create")
	if err != nil {
		return err
	}
	created, subject, err := mintToken(ctx, c, username, password, roles, seconds, name, "Create an API token with the agentgate CLI")
	zero(password)
	if err != nil {
		return err
	}
	if save {
		st, err := e.store()
		if err != nil {
			return err
		}
		server, opts := e.server.String(), e.transportOptions()
		if err = st.update(func(cfg *Config) error {
			c := cfg.Contexts[e.ctxName]
			if c == nil || c.Server != server {
				c = &Context{Server: server, CAFile: opts.caFile, CertSHA256: opts.pin, AllowLoopbackHTTP: opts.allowLoopbackHTTP}
				cfg.Contexts[e.ctxName] = c
			}
			c.Token, c.TokenID, c.TokenName, c.Subject, c.Roles, c.ExpiresAt = created.Token, created.ID, created.Name, subject, created.Roles, created.ExpiresAt
			if cfg.CurrentContext == "" {
				cfg.CurrentContext = e.ctxName
			}
			return nil
		}); err != nil {
			return err
		}
		meta := map[string]any{"id": created.ID, "name": created.Name, "roles": created.Roles, "expires_at": created.ExpiresAt, "saved_to_context": e.ctxName}
		if e.g.json {
			return e.p.value(meta)
		}
		e.p.line("Created token %q (%s), roles %s, expires %s; saved to context %q. The token is not shown.", created.Name, created.ID, joinOr(created.Roles, "-"), created.ExpiresAt, e.ctxName)
		return nil
	}
	if e.g.json {
		return e.p.value(created)
	}
	if e.g.quiet {
		e.p.line("%s", created.Token)
		return nil
	}
	e.p.warn("the token is shown once; store it now (agentgate login URL --token-stdin reads it back)")
	e.p.line("%s", created.Token)
	e.p.note("id %s, roles %s, expires %s", created.ID, joinOr(created.Roles, "-"), created.ExpiresAt)
	return nil
}

func (e *env) tokenList(ctx context.Context, cred credentialFlags) error {
	c, err := e.sessionClient()
	if err != nil {
		return err
	}
	username, password, err := e.credentials(ctx, cred, "token ls")
	if err != nil {
		return err
	}
	s, err := signIn(ctx, c, username, password)
	zero(password)
	if err != nil {
		return err
	}
	defer s.close(ctx)
	var list items[APIToken]
	raw, err := s.call(ctx, "GET", apiPrefix+"/api-tokens", nil, &list)
	if err != nil {
		return err
	}
	return e.emit(raw, func() error {
		if e.g.quiet {
			for _, t := range list.Items {
				e.p.line("%s", t.ID)
			}
			return nil
		}
		rows := [][]string{}
		for _, t := range list.Items {
			state := "active"
			if t.Revoked != "" {
				state = "revoked"
			} else if exp, err := time.Parse(time.RFC3339, t.Expires); err == nil && !exp.After(e.app.Now()) {
				state = "expired"
			}
			rows = append(rows, []string{t.ID, t.Name, t.Subject, joinOr(t.Roles, ""), state, t.Expires, t.LastUsed})
		}
		e.p.table([]string{"ID", "NAME", "SUBJECT", "ROLES", "STATE", "EXPIRES", "LAST USED"}, rows)
		return nil
	})
}

func (e *env) tokenRevoke(ctx context.Context, cred credentialFlags, id, reason string) error {
	reason, err := defaultReason(reason, "Revoke an API token with the agentgate CLI")
	if err != nil {
		return err
	}
	c, err := e.sessionClient()
	if err != nil {
		return err
	}
	username, password, err := e.credentials(ctx, cred, "token revoke")
	if err != nil {
		return err
	}
	s, err := signIn(ctx, c, username, password)
	zero(password)
	if err != nil {
		return err
	}
	defer s.close(ctx)
	raw, err := s.call(ctx, "DELETE", apiPrefix+"/api-tokens/"+pathEscape(id), map[string]string{"reason": reason}, nil)
	if err != nil {
		return err
	}
	return e.emit(raw, func() error {
		e.p.line("Revoked token %s.", id)
		if e.ctx != nil && e.ctx.TokenID == id {
			e.p.note("It was the token of context %s; run agentgate logout to remove it from this machine.", e.ctxName)
		}
		return nil
	})
}
