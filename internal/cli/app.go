// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Package cli is the agentgate command-line client. It is a thin client of
// the control plane REST API (docs/PROVISIONING.md): it holds no policy logic
// of its own, keeps API tokens in a private configuration file, and never
// reads a secret value from its arguments or environment.
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// App is one CLI process. Every dependency on the outside world is a field,
// so tests run commands against fakes.
type App struct {
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
	Getenv    func(string) string
	Term      Terminal
	Runner    Runner
	Transport http.RoundTripper // nil: built from the context's trust settings
	Now       func() time.Time
	// Euid decides whether steps that need root may run. File custody
	// checks always use the real effective user id.
	Euid     func() int
	Hostname func() (string, error)
	Sleep    func(context.Context, time.Duration) error
	Version  string
	// HomeOf looks up an account's home directory (the account database);
	// under sudo the configuration lives in root's, never where HOME points.
	HomeOf func(uid int) (string, error)
}

type globals struct {
	context, server, caFile, pinCert        string
	insecure, json, quiet, noColor, verbose bool
	yes, help                               bool
	timeout                                 time.Duration
}

// globalValueFlags take a value; splitCommand needs to know them.
var globalValueFlags = map[string]bool{"context": true, "server": true, "ca-file": true, "pin-cert": true, "timeout": true}

func (g *globals) register(fs *flag.FlagSet) {
	fs.StringVar(&g.context, "context", g.context, "")
	fs.StringVar(&g.server, "server", g.server, "")
	fs.StringVar(&g.caFile, "ca-file", g.caFile, "")
	fs.StringVar(&g.pinCert, "pin-cert", g.pinCert, "")
	fs.BoolVar(&g.insecure, "insecure", g.insecure, "")
	fs.BoolVar(&g.json, "json", g.json, "")
	fs.BoolVar(&g.quiet, "quiet", g.quiet, "")
	fs.BoolVar(&g.quiet, "q", g.quiet, "")
	fs.BoolVar(&g.noColor, "no-color", g.noColor, "")
	fs.BoolVar(&g.verbose, "verbose", g.verbose, "")
	fs.BoolVar(&g.verbose, "v", g.verbose, "")
	fs.BoolVar(&g.yes, "yes", g.yes, "")
	fs.BoolVar(&g.yes, "y", g.yes, "")
	fs.BoolVar(&g.help, "help", g.help, "")
	fs.BoolVar(&g.help, "h", g.help, "")
	fs.DurationVar(&g.timeout, "timeout", g.timeout, "")
}

const globalHelp = `Global flags:
  --context NAME     use this saved context (default: the current one; env AGENTGATE_CONTEXT)
  --server URL       service origin (env AGENTGATE_URL); a saved token is sent only to its own server
  --ca-file FILE     trust only this CA for the service certificate
  --pin-cert SHA256  also require this SHA-256 server certificate fingerprint
  --insecure         allow plain http, and only to a loopback address (prints a warning)
  --json             print one JSON value with the API's field names
  -q, --quiet        print only what scripts need
  --no-color         no colors (also NO_COLOR, or when standard output is not a terminal)
  -v, --verbose      log requests to standard error (tokens and secrets are redacted)
  -y, --yes          confirm a destructive action without a prompt (where scripts may)
  --timeout DUR      per-request time limit (default 30s)
  -h, --help         show help`

// command is one leaf command.
type command struct {
	name    string
	args    string
	summary string
	help    string
	setup   func(fs *flag.FlagSet) runner
}

type runner func(ctx context.Context, e *env, args, tail []string) error

var registry []*command

func register(c *command) { registry = append(registry, c) }

func commandsByName() map[string]*command {
	out := map[string]*command{}
	for _, c := range registry {
		out[c.name] = c
	}
	return out
}

// groups are the command words that take a subcommand.
func groups() map[string][]string {
	out := map[string][]string{}
	for _, c := range registry {
		if i := strings.IndexByte(c.name, ' '); i > 0 {
			out[c.name[:i]] = append(out[c.name[:i]], c.name[i+1:])
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

// splitCommand finds the command words; flags before them must be global.
func splitCommand(args []string) (path []string, rest []string) {
	grp := groups()
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			rest = append(rest, a)
			name := strings.TrimLeft(a, "-")
			if !strings.Contains(name, "=") && globalValueFlags[name] && i+1 < len(args) {
				rest = append(rest, args[i+1])
				i++
			}
			i++
			continue
		}
		path = append(path, a)
		i++
		if len(path) == 1 && grp[a] != nil {
			continue
		}
		break
	}
	return path, append(rest, args[i:]...)
}

// parseArgs parses flags anywhere among the positional arguments. Everything
// after a literal "--" is returned as tail, unparsed.
func parseArgs(fs *flag.FlagSet, args []string) (pos, tail []string, err error) {
	for i, a := range args {
		if a == "--" {
			tail = append([]string{}, args[i+1:]...)
			args = args[:i]
			break
		}
	}
	for {
		if err = fs.Parse(args); err != nil {
			return nil, nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, tail, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// Main runs one command line and returns the process exit code.
func (a *App) Main(ctx context.Context, args []string) int {
	a.defaults()
	g := &globals{timeout: defaultTimeout}
	if v := a.Getenv("AGENTGATE_CONTEXT"); v != "" {
		g.context = v
	}
	e := &env{app: a, g: g}
	e.p = &printer{out: a.Stdout, err: a.Stderr}
	path, rest := splitCommand(args)
	if len(path) == 0 || path[0] == "help" {
		pre := flag.NewFlagSet("agentgate", flag.ContinueOnError)
		pre.SetOutput(io.Discard)
		g.register(pre)
		pos, _, err := parseArgs(pre, rest)
		if err != nil {
			return e.report(ctx, usageError("%v", err))
		}
		if len(pos) > 0 {
			if c := lookup(pos); c != nil {
				printCommandHelp(a.Stdout, c)
				return ExitOK
			}
			if subs := groups()[pos[0]]; subs != nil && len(pos) == 1 {
				fmt.Fprintf(a.Stdout, "agentgate %s subcommands: %s\n", pos[0], strings.Join(subs, ", "))
				return ExitOK
			}
			return e.report(ctx, usageError("unknown command %q", strings.Join(pos, " ")))
		}
		printMainHelp(a.Stdout)
		if len(path) == 0 && !g.help {
			return ExitUsage
		}
		return ExitOK
	}
	c := lookup(path)
	if c == nil {
		if subs := groups()[path[0]]; subs != nil {
			if len(path) == 1 {
				fmt.Fprintf(a.Stdout, "agentgate %s needs a subcommand: %s\n", path[0], strings.Join(subs, ", "))
				return ExitUsage
			}
			return e.report(ctx, usageError("unknown subcommand %q for %s (use one of: %s)", path[1], path[0], strings.Join(subs, ", ")))
		}
		return e.report(ctx, usageError("unknown command %q", path[0]))
	}
	fs := flag.NewFlagSet("agentgate "+c.name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	g.register(fs)
	run := c.setup(fs)
	pos, tail, err := parseArgs(fs, rest)
	if g.help || errors.Is(err, flag.ErrHelp) {
		printCommandHelp(a.Stdout, c)
		return ExitOK
	}
	if err != nil {
		return e.report(ctx, usageError("%v", err))
	}
	e.p.json, e.p.quiet = g.json, g.quiet
	e.p.color = !g.noColor && a.Getenv("NO_COLOR") == "" && a.Getenv("TERM") != "dumb" && a.Term.IsTerminal(1) && !g.json
	return e.report(ctx, run(ctx, e, pos, tail))
}

func lookup(path []string) *command {
	return commandsByName()[strings.Join(path, " ")]
}

func (a *App) defaults() {
	if a.Getenv == nil {
		a.Getenv = os.Getenv
	}
	if a.Now == nil {
		a.Now = time.Now
	}
	if a.Euid == nil {
		a.Euid = os.Geteuid
	}
	if a.Hostname == nil {
		a.Hostname = os.Hostname
	}
	if a.HomeOf == nil {
		a.HomeOf = accountHome
	}
	if a.Stdin == nil {
		a.Stdin = strings.NewReader("")
	}
	if a.Version == "" {
		a.Version = Version()
	}
	if a.Sleep == nil {
		a.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
}

// report prints err and returns its exit code.
func (e *env) report(ctx context.Context, err error) int {
	if err == nil {
		return ExitOK
	}
	ce := asError(ctx, err)
	if ce.Exit == ExitInterrupted {
		if ce.Message == "" || ce.Message == "Interrupted." {
			fmt.Fprintln(e.app.Stderr, "agentgate: interrupted")
		} else {
			fmt.Fprintln(e.app.Stderr, "agentgate: "+ce.Message)
		}
	} else {
		label := e.p.paint(colorRed, "error:")
		fmt.Fprintf(e.app.Stderr, "%s %s\n", label, clean(ce.Message))
		var meta []string
		if ce.Code != "" {
			meta = append(meta, "code "+ce.Code)
		}
		if ce.Status != 0 {
			meta = append(meta, fmt.Sprintf("HTTP %d", ce.Status))
		}
		if ce.RequestID != "" {
			meta = append(meta, "request "+ce.RequestID)
		}
		if len(meta) > 0 {
			fmt.Fprintf(e.app.Stderr, "  (%s)\n", strings.Join(meta, ", "))
		}
		if ce.Hint != "" {
			fmt.Fprintf(e.app.Stderr, "  next: %s\n", clean(ce.Hint))
		}
	}
	if e.g.json && !ce.reported {
		body := map[string]any{"error": map[string]any{"code": ce.Code, "message": ce.Message, "hint": ce.Hint, "exit_code": ce.Exit, "status": ce.Status, "request_id": ce.RequestID}}
		raw, _ := json.MarshalIndent(body, "", "  ")
		fmt.Fprintln(e.app.Stdout, string(raw))
	}
	return ce.Exit
}

// helpOrder is the order of the command list in agentgate help.
var helpOrder = []string{"up", "login", "logout", "whoami", "context ls", "context use", "context rm",
	"target ls", "target add", "target status", "target approve-key", "target pin", "target enroll", "target rename", "target retire",
	"profile ls", "profile show", "profile new", "profile versions", "profile approval", "preset ls", "grant",
	"launch", "ps", "show", "logs", "events", "stop", "approve", "reject", "audit",
	"secret set", "secret ls", "secret rm", "token create", "token ls", "token revoke", "schema launch-spec", "completion", "version"}

func orderedCommands() []*command {
	byName := commandsByName()
	out := []*command{}
	seen := map[string]bool{}
	for _, n := range helpOrder {
		if c := byName[n]; c != nil {
			out = append(out, c)
			seen[n] = true
		}
	}
	for _, c := range registry {
		if !seen[c.name] {
			out = append(out, c)
		}
	}
	return out
}

func printMainHelp(w io.Writer) {
	fmt.Fprintln(w, "agentgate provisions the eBPF-enforced agent sandbox, defines agent access, and launches agents.")
	fmt.Fprintln(w, "\nUsage: agentgate COMMAND [ARGS] [FLAGS]")
	fmt.Fprintln(w, "\nCommands:")
	for _, c := range orderedCommands() {
		syn := c.name
		if c.args != "" {
			syn += " " + c.args
		}
		if len(syn) > 36 {
			fmt.Fprintf(w, "  %s\n  %-36s %s\n", syn, "", c.summary)
		} else {
			fmt.Fprintf(w, "  %-36s %s\n", syn, c.summary)
		}
	}
	fmt.Fprintln(w, "\n"+globalHelp)
	fmt.Fprintln(w, "\nExit codes and examples: docs/CLI.md. Run agentgate COMMAND --help for a command's flags.")
}

func printCommandHelp(w io.Writer, c *command) {
	syn := "agentgate " + c.name
	if c.args != "" {
		syn += " " + c.args
	}
	fmt.Fprintf(w, "Usage: %s\n\n%s\n", syn, c.summary)
	if c.help != "" {
		fmt.Fprintf(w, "\n%s\n", strings.TrimRight(c.help, "\n"))
	}
	fmt.Fprintln(w, "\n"+globalHelp)
}

// env is the state of one command run.
type env struct {
	app *App
	g   *globals
	p   *printer
	in  *bufio.Reader

	loaded  bool
	st      store
	cfg     *Config
	ctxName string
	ctx     *Context
	server  *url.URL
	token   string
	cli     *Client
}

func (e *env) store() (store, error) {
	if e.st.dir == "" {
		dir, note, err := configDir(e.app.Getenv, os.Geteuid(), e.app.HomeOf)
		if err != nil {
			return store{}, err
		}
		if note != "" && e.p != nil {
			e.p.note("%s", note)
		}
		e.st = store{dir: dir, euid: os.Geteuid()}
	}
	return e.st, nil
}

// config loads the configuration once.
func (e *env) config() (*Config, error) {
	if e.cfg != nil {
		return e.cfg, nil
	}
	st, err := e.store()
	if err != nil {
		return nil, err
	}
	cfg, err := st.load()
	if err != nil {
		return nil, err
	}
	e.cfg = cfg
	return cfg, nil
}

func (e *env) contextName(cfg *Config) string {
	switch {
	case e.g.context != "":
		return e.g.context
	case cfg != nil && cfg.CurrentContext != "":
		return cfg.CurrentContext
	}
	return defaultContext
}

// resolve finds the service and credential for this run. A saved token is
// only ever sent to the server it was saved for.
func (e *env) resolve() error {
	if e.loaded {
		return nil
	}
	cfg, err := e.config()
	if err != nil {
		return err
	}
	e.ctxName = e.contextName(cfg)
	if e.g.context != "" && cfg.Contexts[e.g.context] == nil && e.g.server == "" && e.app.Getenv("AGENTGATE_URL") == "" {
		return usageError("no saved context %q (agentgate context ls lists them)", e.g.context)
	}
	saved := cfg.Contexts[e.ctxName]
	raw := e.g.server
	if raw == "" {
		raw = e.app.Getenv("AGENTGATE_URL")
	}
	if raw == "" && saved != nil {
		raw = saved.Server
	}
	if raw == "" {
		return &Error{Exit: ExitAuth, Code: "not_configured", Message: "No service is configured.", Hint: "Run agentgate login URL (or agentgate up on the service host), or set AGENTGATE_URL and AGENTGATE_TOKEN."}
	}
	u, err := serverURL(raw)
	if err != nil {
		return err
	}
	e.server = u
	own := saved != nil && saved.Server == u.String()
	ctx := &Context{Server: u.String()}
	if own {
		copied := *saved
		ctx = &copied
	}
	e.ctx = ctx
	e.token = e.app.Getenv("AGENTGATE_TOKEN")
	if e.token == "" && own {
		e.token = saved.Token
	}
	if e.token != "" && !apiTokenFormat.MatchString(e.token) {
		return &Error{Exit: ExitAuth, Code: "invalid_token_format", Message: "The configured API token is not an agt_ token.", Hint: "Run agentgate login URL again."}
	}
	e.loaded = true
	return nil
}

func (e *env) transportOptions() transportOptions {
	o := transportOptions{caFile: e.g.caFile, pin: e.g.pinCert, allowLoopbackHTTP: e.g.insecure}
	if o.caFile == "" {
		o.caFile = e.app.Getenv("AGENTGATE_CA_FILE")
	}
	if e.ctx != nil {
		if o.caFile == "" {
			o.caFile = e.ctx.CAFile
		}
		if o.pin == "" {
			o.pin = e.ctx.CertSHA256
		}
		o.allowLoopbackHTTP = o.allowLoopbackHTTP || e.ctx.AllowLoopbackHTTP
	}
	return o
}

// clientFor builds a client for an explicit server and token.
func (e *env) clientFor(u *url.URL, token string, o transportOptions) (*Client, error) {
	var rt http.RoundTripper = e.app.Transport
	if u.Scheme == "http" {
		if !o.allowLoopbackHTTP || !isLoopbackHost(u.Host) {
			_, err := newTransport(u, o)
			return nil, err
		}
		e.p.warn("plain http to %s: the token travels unencrypted on this machine's loopback interface", u.Host)
	}
	if rt == nil {
		t, err := newTransport(u, o)
		if err != nil {
			return nil, err
		}
		rt = t
	} else if o.caFile != "" || o.pin != "" {
		// Validate the settings even when a test transport is injected.
		if _, err := newTransport(u, o); err != nil {
			return nil, err
		}
	}
	var verbose io.Writer
	if e.g.verbose {
		verbose = e.app.Stderr
	}
	c := newClient(u, token, rt, e.g.timeout, verbose, e.app.Version)
	c.sleep = e.app.Sleep
	return c, nil
}

// client returns the API client for this run.
func (e *env) client() (*Client, error) {
	if e.cli != nil {
		return e.cli, nil
	}
	if err := e.resolve(); err != nil {
		return nil, err
	}
	c, err := e.clientFor(e.server, e.token, e.transportOptions())
	if err != nil {
		return nil, err
	}
	e.cli = c
	return c, nil
}

// authed returns a client that has a token.
func (e *env) authed() (*Client, error) {
	c, err := e.client()
	if err != nil {
		return nil, err
	}
	if e.token == "" {
		return nil, &Error{Exit: ExitAuth, Code: "not_signed_in", Message: "No API token for " + e.server.String() + ".", Hint: "Run agentgate login " + e.server.String() + " (or set AGENTGATE_TOKEN)."}
	}
	return c, nil
}

// emit prints raw API JSON with --json, or calls human otherwise.
func (e *env) emit(raw []byte, human func() error) error {
	if e.g.json {
		return e.p.rawJSON(raw)
	}
	return human()
}
