// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

const (
	maxSpecBytes       = 64 << 10
	defaultWaitTimeout = 15 * time.Minute
)

var imageNamePart = regexp.MustCompile(`[^a-z0-9-]+`)

type launchFlags struct {
	file, name, target, mode, lifetime, profile, image, workdir, approval string
	mounts, secrets, envs                                                 multiFlag
	dryRun, wait                                                          bool
	until                                                                 string
	waitTimeout                                                           time.Duration
}

func init() {
	register(&command{name: "launch", args: "[-f SPEC | FLAGS] [-- COMMAND...]", summary: "Launch an agent into the sandbox with the access given at launch (or --dry-run to see exactly what it may do).",
		help: `Spec:
  -f FILE|-                 an agentgate.launch.v1 document (agentgate schema launch-spec)
or flags:
  --name NAME               launch name (default: from the image)
  --target NAME             target (default local)
  --mode oneshot|session    run COMMAND once, or a long-running agent (default oneshot)
  --lifetime DUR            hard cap: oneshot 1s-1h (default 10m), session 1m-24h (default 1h)
  --profile NAME[@VERSION]  access profile (default: its latest version)
  --image REF@sha256:DIGEST immutable image reference
  --mount SRC:NAME[:ro|snapshot|rw]   host folder at /var/lib/agentgate/mounts/NAME (default ro)
  --secret REF[:ENV]        brokered secret; ENV (default REF_BASE_URL) receives the broker address
  --env K=V                 environment (never secrets: the service rejects credential-like names)
  --workdir DIR             working directory (default /var/lib/agentgate/workspace)
  --approval auto|required  ask for a second human even when nothing else requires it
  -- COMMAND...             the agent command
Behavior:
  --dry-run                 print the resolved plan, digests, effective permissions and approvals; create nothing
  --wait                    follow the launch until it runs (or ends); waits through approval
  --until running|done      what --wait waits for (default running)
  --wait-timeout DUR        give up waiting after DUR (default 15m); the launch continues
Exit codes: 0 queued or running, 8 waiting for approval, 12 ended without reaching the awaited state.`,
		setup: func(fs *flag.FlagSet) runner {
			var f launchFlags
			fs.StringVar(&f.file, "f", "", "")
			fs.StringVar(&f.file, "file", "", "")
			fs.StringVar(&f.name, "name", "", "")
			fs.StringVar(&f.target, "target", "", "")
			fs.StringVar(&f.mode, "mode", "", "")
			fs.StringVar(&f.lifetime, "lifetime", "", "")
			fs.StringVar(&f.profile, "profile", "", "")
			fs.StringVar(&f.image, "image", "", "")
			fs.StringVar(&f.workdir, "workdir", "", "")
			fs.StringVar(&f.approval, "approval", "", "")
			fs.Var(&f.mounts, "mount", "")
			fs.Var(&f.secrets, "secret", "")
			fs.Var(&f.envs, "env", "")
			fs.BoolVar(&f.dryRun, "dry-run", false, "")
			fs.BoolVar(&f.wait, "wait", false, "")
			fs.StringVar(&f.until, "until", "running", "")
			fs.DurationVar(&f.waitTimeout, "wait-timeout", defaultWaitTimeout, "")
			return func(ctx context.Context, e *env, args, tail []string) error {
				return e.launch(ctx, f, args, tail)
			}
		}})
	register(&command{name: "ps", summary: "List launches, newest first.",
		help: "  --state STATE   only this state\n  --active        only launches that have not ended\n  --limit N       at most N (default 50, at most 200)",
		setup: func(fs *flag.FlagSet) runner {
			state := fs.String("state", "", "")
			active := fs.Bool("active", false, "")
			limit := fs.Int("limit", 50, "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 0 {
					return usageError("ps takes no arguments")
				}
				return e.ps(ctx, *state, *active, *limit)
			}
		}})
	register(&command{name: "show", args: "ID", summary: "Show a launch: state, plan, effective permissions, jobs and receipt.", setup: func(fs *flag.FlagSet) runner {
		return func(ctx context.Context, e *env, args, _ []string) error {
			if len(args) != 1 {
				return usageError("show takes one launch id")
			}
			return e.show(ctx, args[0])
		}
	}})
	register(&command{name: "logs", args: "ID", summary: "Print an agent's output; -f follows it until the launch ends.",
		help: "  -f, --follow      keep printing new output until the launch ends\n  --after N         start after line N\n  --stream NAME     only stdout or stderr",
		setup: func(fs *flag.FlagSet) runner {
			follow := fs.Bool("f", false, "")
			fs.BoolVar(follow, "follow", false, "")
			after := fs.Int("after", 0, "")
			stream := fs.String("stream", "", "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 1 {
					return usageError("logs takes one launch id")
				}
				if *stream != "" && *stream != "stdout" && *stream != "stderr" {
					return usageError("--stream is stdout or stderr")
				}
				return e.logs(ctx, args[0], *follow, *after, *stream)
			}
		}})
	register(&command{name: "events", args: "ID", summary: "Print a launch's ordered events; -f streams them (resumes after disconnects).",
		help: "  -f, --follow   stream new events until the launch ends\n  --after N      start after event N",
		setup: func(fs *flag.FlagSet) runner {
			follow := fs.Bool("f", false, "")
			fs.BoolVar(follow, "follow", false, "")
			after := fs.Int("after", 0, "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 1 {
					return usageError("events takes one launch id")
				}
				return e.events(ctx, args[0], *follow, *after)
			}
		}})
	register(&command{name: "stop", args: "ID", summary: "Stop a launch (idempotent); a running session asks for confirmation.",
		help: "  --reason TEXT\n  --wait            follow until the launch has ended\n  --wait-timeout DUR\n  --yes             confirm stopping a running session without a prompt",
		setup: func(fs *flag.FlagSet) runner {
			reason := fs.String("reason", "", "")
			wait := fs.Bool("wait", false, "")
			timeout := fs.Duration("wait-timeout", defaultWaitTimeout, "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 1 {
					return usageError("stop takes one launch id")
				}
				return e.stop(ctx, args[0], *reason, *wait, *timeout)
			}
		}})
	for _, approve := range []bool{true, false} {
		approve := approve
		verb := map[bool]string{true: "approve", false: "reject"}[approve]
		register(&command{name: verb, args: "ID", summary: map[bool]string{true: "Approve another human's launch after reviewing its plan (approver).", false: "Reject a launch waiting for approval (approver)."}[approve],
			help: "  --reason TEXT   recorded in the audit trail (prompted on a terminal)\n  --yes           approve without the confirmation prompt\nYou can never decide a launch you requested.",
			setup: func(fs *flag.FlagSet) runner {
				reason := fs.String("reason", "", "")
				return func(ctx context.Context, e *env, args, _ []string) error {
					if len(args) != 1 {
						return usageError("%s takes one launch id", verb)
					}
					return e.decide(ctx, args[0], approve, *reason)
				}
			}})
	}
}

// buildSpec assembles a launch spec from flags. The service validates it.
func (e *env) buildSpec(ctx context.Context, c *Client, f launchFlags, tail []string) ([]byte, error) {
	if f.profile == "" || f.image == "" {
		return nil, usageError("launch needs -f SPEC, or at least --profile and --image")
	}
	spec := hostproto.LaunchSpec{Version: hostproto.LaunchSpecVersion, Name: f.name, Target: f.target, Mode: f.mode, Approval: f.approval,
		Agent:  hostproto.LaunchAgent{Image: f.image, Command: append([]string{}, tail...), Env: map[string]string{}, Workdir: f.workdir},
		Mounts: []hostproto.SpecMount{}, Secrets: []hostproto.SpecSecret{}}
	if spec.Target == "" {
		spec.Target = "local"
	}
	if spec.Mode == "" {
		spec.Mode = "oneshot"
	}
	if spec.Approval == "" {
		spec.Approval = "auto"
	}
	if spec.Agent.Workdir == "" {
		spec.Agent.Workdir = "/var/lib/agentgate/workspace"
	}
	if spec.Mode == "oneshot" && len(tail) == 0 {
		return nil, usageError("a oneshot launch runs a command: put it after --, for example: agentgate launch ... -- python3 -m pytest")
	}
	if spec.Name == "" {
		base := path.Base(strings.SplitN(strings.SplitN(f.image, "@", 2)[0], ":", 2)[0])
		spec.Name = strings.Trim(imageNamePart.ReplaceAllString(strings.ToLower(base), "-"), "-")
		if len(spec.Name) > 40 {
			spec.Name = spec.Name[:40]
		}
		if spec.Name == "" {
			spec.Name = "agent"
		}
	}
	lifetime := f.lifetime
	if lifetime == "" {
		lifetime = map[string]string{"oneshot": "10m", "session": "1h"}[spec.Mode]
	}
	if lifetime != "" {
		d, err := parseLifetime(lifetime)
		if err != nil {
			return nil, usageError("--lifetime: %v", err)
		}
		spec.LifetimeSeconds = int(d / time.Second)
	}
	name, version, hasVersion := strings.Cut(f.profile, "@")
	spec.Access.Profile = name
	if hasVersion {
		n, err := strconv.Atoi(version)
		if err != nil || n < 1 {
			return nil, usageError("--profile NAME@VERSION takes a positive version number")
		}
		spec.Access.Version = n
	} else {
		p, err := e.getProfile(ctx, c, name)
		if err != nil {
			return nil, err
		}
		spec.Access.Version = p.LatestVersion
		e.p.note("Using profile %s version %d (the latest).", p.Name, p.LatestVersion)
	}
	for _, kv := range f.envs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, usageError("--env takes NAME=VALUE")
		}
		if _, dup := spec.Agent.Env[k]; dup {
			return nil, usageError("--env %s is given twice", k)
		}
		spec.Agent.Env[k] = v
	}
	for _, m := range f.mounts {
		parts := strings.Split(m, ":")
		if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
			return nil, usageError("--mount takes SOURCE:NAME[:ro|snapshot|rw]")
		}
		mode := "read-only"
		if len(parts) == 3 {
			var ok bool
			if mode, ok = map[string]string{"ro": "read-only", "read-only": "read-only", "snapshot": "snapshot", "rw": "read-write", "read-write": "read-write"}[parts[2]]; !ok {
				return nil, usageError("--mount mode is ro, snapshot or rw")
			}
		}
		spec.Mounts = append(spec.Mounts, hostproto.SpecMount{Name: parts[1], Source: parts[0], Mode: mode})
	}
	for _, s := range f.secrets {
		ref, envName, ok := strings.Cut(s, ":")
		if !ok {
			envName = strings.ToUpper(strings.ReplaceAll(ref, "-", "_")) + "_BASE_URL"
		}
		if ref == "" || envName == "" {
			return nil, usageError("--secret takes REF[:ENV]")
		}
		spec.Secrets = append(spec.Secrets, hostproto.SpecSecret{Ref: ref, Expose: hostproto.SecretExpose{Env: envName}})
	}
	return json.Marshal(spec)
}

func (e *env) launchSpec(ctx context.Context, c *Client, f launchFlags, args, tail []string) ([]byte, error) {
	if len(args) != 0 {
		return nil, usageError("put the agent command after --, for example: agentgate launch ... -- python3 -m pytest")
	}
	if f.file == "" {
		return e.buildSpec(ctx, c, f, tail)
	}
	if f.name != "" || f.target != "" || f.mode != "" || f.lifetime != "" || f.profile != "" || f.image != "" || f.workdir != "" || f.approval != "" || len(f.mounts)+len(f.secrets)+len(f.envs)+len(tail) > 0 {
		return nil, usageError("-f takes the whole spec; do not combine it with spec flags or a command")
	}
	var raw []byte
	var err error
	if f.file == "-" {
		raw, err = e.readAllStdin(maxSpecBytes)
	} else {
		raw, err = readBounded(f.file, maxSpecBytes)
	}
	if err != nil {
		return nil, usageError("cannot read the launch spec %s: %v", f.file, err)
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || !json.Valid(raw) {
		return nil, usageError("%s is not one JSON document", f.file)
	}
	return raw, nil
}

func (e *env) launch(ctx context.Context, f launchFlags, args, tail []string) error {
	if f.until != "running" && f.until != "done" {
		return usageError("--until is running or done")
	}
	if f.dryRun && f.wait {
		return usageError("--dry-run creates nothing to wait for")
	}
	c, err := e.authed()
	if err != nil {
		return err
	}
	spec, err := e.launchSpec(ctx, c, f, args, tail)
	if err != nil {
		return err
	}
	if f.dryRun {
		var out PlanResult
		raw, err := c.call(ctx, request{method: "POST", path: apiPrefix + "/launch-plans", body: spec, retry: true, idemKey: newIdempotencyKey()}, &out)
		if err != nil {
			return err
		}
		return e.emit(raw, func() error {
			e.printPlan(out.Plan, nameOf(out.Spec), "", true)
			return nil
		})
	}
	var out LaunchCreated
	raw, err := c.call(ctx, request{method: "POST", path: apiPrefix + "/launches", body: spec, retry: true, idemKey: newIdempotencyKey()}, &out)
	if err != nil {
		return err
	}
	l := out.Launch
	if !f.wait {
		if e.g.json {
			if err := e.p.rawJSON(raw); err != nil {
				return err
			}
		} else if e.g.quiet {
			e.p.line("%s", l.ID)
		} else {
			e.p.line("Launch %s (%s) created: %s.", l.ID, l.Name, e.p.state(l.State))
			e.printPlanBrief(out.Plan)
			e.printNext(l, out.Plan)
		}
		if l.State == "approval_pending" {
			return &Error{Exit: ExitApprovalPending, Code: "approval_pending", Message: "Launch " + l.ID + " waits for approval by a different human.", Hint: "An approver runs: agentgate approve " + l.ID, reported: e.g.json}
		}
		return nil
	}
	if !e.g.json && !e.g.quiet {
		e.p.line("Launch %s (%s) created: %s.", l.ID, l.Name, e.p.state(l.State))
		e.printPlanBrief(out.Plan)
	}
	until := func(s string) bool { return s == "running" }
	if f.until == "done" {
		until = terminalState
	}
	final, werr := e.follow(ctx, c, l, out.Plan, 0, until, f.waitTimeout)
	if e.g.json {
		detail := map[string]any{"launch": final, "plan": out.Plan}
		if err := e.p.value(detail); err != nil {
			return err
		}
	}
	if werr == nil {
		werr = launchOutcome(final, f.until)
	}
	var ce *Error
	if errors.As(werr, &ce) && e.g.json {
		ce.reported = true
	}
	return werr
}

// launchOutcome maps the followed state to the documented exit code.
func launchOutcome(l Launch, until string) error {
	switch {
	case until == "running" && l.State == "running":
		return nil
	case until == "done" && l.State == "stopped":
		return nil
	case until == "stop" && (l.State == "stopped" || l.State == "cancelled"):
		return nil
	}
	msg := "Launch " + l.ID + " ended " + l.State
	if l.TerminalReason != "" {
		msg += ": " + l.TerminalReason
	}
	if l.EvidenceMissing != "" {
		msg += " (evidence missing: " + l.EvidenceMissing + ")"
	}
	return &Error{Exit: ExitLaunchFailed, Code: "launch_" + l.State, Message: msg + ".", Hint: "agentgate show " + l.ID + " shows the plan, the jobs and the receipt; agentgate logs " + l.ID + " the output."}
}

func nameOf(spec json.RawMessage) string {
	var s struct {
		Name string `json:"name"`
	}
	json.Unmarshal(spec, &s)
	return s.Name
}

func (e *env) getLaunch(ctx context.Context, c *Client, id string) (LaunchDetail, []byte, error) {
	var d LaunchDetail
	raw, err := c.get(ctx, apiPrefix+"/launches/"+pathEscape(id), nil, &d)
	return d, raw, err
}

// follow prints a launch's state changes until until(state) holds, the launch
// ends, the timeout passes or the user interrupts. Interrupting never stops
// the launch.
func (e *env) follow(ctx context.Context, c *Client, l Launch, plan LaunchPlan, from int, until func(string) bool, timeout time.Duration) (Launch, error) {
	state := l.State
	shownApproval := false
	showApproval := func() {
		if shownApproval || e.g.json || e.g.quiet {
			return
		}
		shownApproval = true
		e.p.line("Waiting for approval: a different human with the approver role must decide this launch.")
		for _, r := range plan.ApprovalReasons {
			e.p.line("  - %s", clean(r))
		}
		e.p.line("  The approver runs: agentgate approve %s --reason \"...\"", l.ID)
		e.p.line("  You cannot approve your own launch. Ctrl-C stops waiting; the launch keeps waiting for its decision.")
	}
	if state == "approval_pending" {
		showApproval()
	}
	if until(state) || terminalState(state) {
		return l, nil
	}
	wctx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		wctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	follower := &eventFollower{c: c, id: l.ID, after: from, sleep: e.app.Sleep}
	follower.onReconnect = func(attempt, after int, _ error) {
		if e.g.verbose {
			e.p.note("reconnecting to the event stream after event %d (attempt %d)", after, attempt)
		}
	}
	err := follower.run(wctx, func(ev LaunchEvent) (bool, error) {
		if !e.g.json && !e.g.quiet {
			e.printEvent(ev)
		}
		if ev.Kind != "state" {
			return false, nil
		}
		state = ev.To
		if state == "approval_pending" {
			showApproval()
		}
		return until(state) || terminalState(state), nil
	})
	if d, _, gerr := e.getLaunch(context.WithoutCancel(ctx), c, l.ID); gerr == nil {
		l = d.Launch
	} else {
		l.State = state
	}
	switch {
	case ctx.Err() != nil:
		return l, &Error{Exit: ExitInterrupted, Code: "interrupted", Message: fmt.Sprintf("Stopped waiting. Launch %s keeps going (state %s): agentgate show %s; agentgate stop %s stops it.", l.ID, l.State, l.ID, l.ID)}
	case wctx.Err() != nil:
		if l.State == "approval_pending" {
			return l, &Error{Exit: ExitApprovalPending, Code: "approval_pending", Message: fmt.Sprintf("Launch %s still waits for approval after %s.", l.ID, timeout), Hint: "An approver runs agentgate approve " + l.ID + "; follow it with agentgate events " + l.ID + " -f."}
		}
		return l, &Error{Exit: ExitTimeout, Code: "wait_timeout", Message: fmt.Sprintf("Launch %s is %s after %s.", l.ID, l.State, timeout), Hint: "It keeps going: agentgate events " + l.ID + " -f follows it."}
	case err != nil:
		return l, err
	}
	return l, nil
}

func (e *env) printEvent(ev LaunchEvent) {
	when := ev.Time
	if t, err := time.Parse(time.RFC3339Nano, ev.Time); err == nil {
		when = t.UTC().Format("15:04:05")
	}
	switch ev.Kind {
	case "state":
		from := ev.From
		if from == "" {
			from = "-"
		}
		e.p.line("%s", strings.TrimRight(fmt.Sprintf("%s  %s -> %s  %s", when, from, e.p.state(ev.To), clean(ev.Reason)), " "))
	default:
		e.p.line("%s", strings.TrimRight(fmt.Sprintf("%s  %s  %s", when, ev.Kind, clean(ev.Reason)), " "))
	}
}

func (e *env) printNext(l Launch, plan LaunchPlan) {
	switch l.State {
	case "approval_pending":
		e.p.line("Approval required:")
		for _, r := range plan.ApprovalReasons {
			e.p.line("  - %s", clean(r))
		}
		e.p.line("A different human with the approver role decides it: agentgate approve %s --reason \"...\"", l.ID)
		e.p.line("You cannot approve your own launch. Follow it: agentgate launch ... --wait, or agentgate events %s -f", l.ID)
	case "queued", "approved":
		exp := ""
		if l.ExpiresAt != "" {
			exp = "; it expires at " + l.ExpiresAt
		}
		e.p.line("Queued for its target%s.", exp)
		e.p.line("Follow: agentgate events %s -f   Output: agentgate logs %s -f   Stop: agentgate stop %s", l.ID, l.ID, l.ID)
	}
}

// printPlanBrief prints the identity of a plan in a few lines.
func (e *env) printPlanBrief(p LaunchPlan) {
	e.p.fields("  ", [][2]string{{"target", targetLabel(p)}, {"access", profileLabel(p)}, {"mode", modeLabel(p, "")}, {"spec digest", p.SpecDigest}, {"policy digest", p.PolicyDigest}})
}

func targetLabel(p LaunchPlan) string {
	return p.Target["name"] + " (" + p.Target["id"] + ")"
}

func profileLabel(p LaunchPlan) string {
	if inline, _ := p.Profile["inline"].(bool); inline {
		return "inline access document (not a reviewed profile)"
	}
	name, _ := p.Profile["name"].(string)
	digest, _ := p.Profile["digest"].(string)
	version := fmt.Sprint(p.Profile["version"])
	return fmt.Sprintf("profile %s version %s (digest %s)", name, version, shortDigest(digest))
}

func modeLabel(p LaunchPlan, expires string) string {
	s := p.Mode + ", lifetime " + humanSeconds(p.LifetimeSeconds)
	if expires == "" {
		expires = p.ExpiresAt
	}
	if expires != "" {
		s += ", expires " + expires
	}
	return s
}

// printPlan is the "what exactly may this agent do" view.
func (e *env) printPlan(p LaunchPlan, name, launchID string, dryRun bool) {
	title := "Launch plan"
	if name != "" {
		title += " for " + name
	}
	if dryRun {
		title += " (dry run: nothing was created)"
	}
	e.p.line("%s", e.p.paint(colorBold, title))
	expires := p.ExpiresAt
	if dryRun && expires != "" {
		expires += " if queued now (the lifetime starts when the launch is queued)"
	}
	e.p.fields("  ", [][2]string{
		{"target", targetLabel(p)}, {"access", profileLabel(p)}, {"mode", modeLabel(p, expires)},
		{"image", p.Image}, {"command", joinOr([]string{quoteArgs(p.Command)}, "(image default)")}, {"workdir", p.Workdir},
		{"spec digest", p.SpecDigest}, {"policy digest", p.PolicyDigest},
	})
	perm := p.Permissions
	web := "none"
	if len(perm.Web) > 0 {
		web = strings.Join(perm.Web, ", ") + " to public addresses"
	}
	e.p.line("\n%s", e.p.paint(colorBold, "What this agent may do"))
	rows := [][2]string{
		{"network", "default " + perm.Network + "; IPv6 " + perm.IPv6},
		{"web", web},
		{"dns", joinOr(perm.DNS, "none")},
		{"taskboard", perm.Taskboard},
		{"read", joinOr(perm.ReadOnly, "nothing")},
		{"write", joinOr(perm.Writable, "nothing")},
		{"execute", joinOr(perm.Execute, "nothing")},
		{"denied", joinOr(perm.Deny, "none")},
		{"devices", joinOr(perm.Devices, "none")},
		{"signals", joinOr(perm.Signals, "none") + " (own process tree only)"},
		{"anonymous exec", map[bool]string{true: "allowed (JIT memory)", false: "no"}[perm.AnonymousExecute]},
	}
	for _, m := range p.Mounts {
		kind := map[string]string{"read-only": "read-only, live", "snapshot": "read-only snapshot copy", "read-write": "writable, live"}[m.Mode]
		rows = append(rows, [2]string{"mount " + m.Name, m.Source + " -> " + m.Path + " (" + kind + ")"})
	}
	if len(p.Mounts) == 0 {
		rows = append(rows, [2]string{"mounts", "none"})
	}
	for _, s := range p.Secrets {
		rows = append(rows, [2]string{"secret " + s.Ref, "$" + s.Env + " = broker for " + strings.Join(s.Upstreams, ", ") + " (header " + s.Header + "; the value never enters the sandbox)"})
	}
	if len(p.Secrets) == 0 {
		rows = append(rows, [2]string{"secrets", "none"})
	}
	e.p.fields("  ", rows)
	e.p.line("\n%s %s", e.p.paint(colorBold, "Approval:"), p.Approval)
	for _, r := range p.ApprovalReasons {
		e.p.line("  - %s", clean(r))
	}
	if p.Approval == "required" {
		id := launchID
		if id == "" {
			id = "ID"
		}
		e.p.line("  A different human with the approver role decides it (agentgate approve %s); never the requester.", id)
	}
	if len(p.Notices) > 0 {
		e.p.line("\n%s", e.p.paint(colorBold, "Notices"))
		for _, n := range p.Notices {
			e.p.line("  - %s", clean(n))
		}
	}
}

func (e *env) targetNames(ctx context.Context, c *Client) map[string]string {
	var list items[Target]
	names := map[string]string{}
	if _, err := c.get(ctx, apiPrefix+"/targets", nil, &list); err == nil {
		for _, t := range list.Items {
			names[t.ID] = t.Name
		}
	}
	return names
}

func (e *env) ps(ctx context.Context, state string, active bool, limit int) error {
	if limit < 1 || limit > 200 {
		return usageError("--limit is 1 to 200")
	}
	c, err := e.authed()
	if err != nil {
		return err
	}
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	if state != "" {
		q.Set("state", state)
	}
	var list items[Launch]
	raw, err := c.get(ctx, apiPrefix+"/launches", q, &list)
	if err != nil {
		return err
	}
	shown := []Launch{}
	for _, l := range list.Items {
		if !active || !terminalState(l.State) {
			shown = append(shown, l)
		}
	}
	if e.g.json {
		if !active {
			return e.p.rawJSON(raw)
		}
		return e.p.value(map[string]any{"items": shown})
	}
	if e.g.quiet {
		for _, l := range shown {
			e.p.line("%s", l.ID)
		}
		return nil
	}
	names := e.targetNames(ctx, c)
	rows := [][]string{}
	now := e.app.Now()
	for _, l := range shown {
		target := names[l.TargetID]
		if target == "" {
			target = short(l.TargetID)
		}
		expires := ""
		if l.ExpiresAt != "" && !terminalState(l.State) {
			expires = age(l.ExpiresAt, now)
		}
		rows = append(rows, []string{l.ID, l.Name, target, l.Mode, e.p.state(l.State), l.RequestedBy, age(l.Created, now), expires})
	}
	e.p.table([]string{"ID", "NAME", "TARGET", "MODE", "STATE", "REQUESTED BY", "CREATED", "EXPIRES"}, rows)
	return nil
}

func (e *env) show(ctx context.Context, id string) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	d, raw, err := e.getLaunch(ctx, c, id)
	if err != nil {
		return err
	}
	if e.g.json {
		return e.p.rawJSON(raw)
	}
	l := d.Launch
	pairs := [][2]string{{"id", l.ID}, {"name", l.Name}, {"state", e.p.state(l.State)}, {"requested by", l.RequestedBy}, {"created", l.Created}}
	if l.DecidedBy != "" {
		pairs = append(pairs, [2]string{"decided by", l.DecidedBy + ": " + l.DecisionReason})
	}
	for _, kv := range [][2]string{{"queued", l.QueuedAt}, {"started", l.StartedAt}, {"expires", l.ExpiresAt}, {"ended", l.EndedAt}, {"stop reason", l.StopReason}, {"end reason", l.TerminalReason}, {"evidence missing", l.EvidenceMissing}} {
		if kv[1] != "" {
			pairs = append(pairs, kv)
		}
	}
	pairs = append(pairs, [2]string{"kernel verified", fmt.Sprint(l.KernelVerified)})
	e.p.fields("", pairs)
	var plan LaunchPlan
	if json.Unmarshal(l.Plan, &plan) == nil && plan.SpecDigest != "" {
		e.p.line("")
		e.printPlan(plan, l.Name, l.ID, false)
	}
	if len(d.Jobs) > 0 {
		e.p.line("\n%s", e.p.paint(colorBold, "Host jobs"))
		rows := [][]string{}
		for _, j := range d.Jobs {
			rows = append(rows, []string{j.ID, j.Type, j.State, strconv.Itoa(j.Attempts), j.Created, j.Completed})
		}
		e.p.table([]string{"JOB", "TYPE", "STATE", "ATTEMPTS", "CREATED", "COMPLETED"}, rows)
	}
	if len(l.Receipt) > 0 {
		var r hostproto.Receipt
		if json.Unmarshal(l.Receipt, &r) == nil {
			e.p.line("\n%s", e.p.paint(colorBold, "Evidence receipt (reported by the host)"))
			exit := "none"
			if r.ExitCode != nil {
				exit = strconv.Itoa(*r.ExitCode)
			}
			counts := []string{}
			for host, n := range r.BrokerCounts {
				counts = append(counts, fmt.Sprintf("%s=%d", host, n))
			}
			e.p.fields("  ", [][2]string{{"reason", r.Reason}, {"exit code", exit}, {"domain empty", fmt.Sprint(r.DomainEmpty)}, {"enforcement released", fmt.Sprint(r.EnforcementReleased)},
				{"guard digest", r.GuardDigest}, {"broker requests", joinOr(sortedStrings(counts), "none")}, {"kernel verified", fmt.Sprint(r.KernelVerified)}})
		}
	}
	return nil
}

func (e *env) logs(ctx context.Context, id string, follow bool, after int, stream string) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	all := []LogLine{}
	truncated := false
	print := func(lines []LogLine) {
		for _, line := range lines {
			if stream != "" && line.Stream != stream {
				continue
			}
			if e.g.json {
				if follow {
					raw, _ := json.Marshal(line)
					e.p.line("%s", raw)
				} else {
					all = append(all, line)
				}
				continue
			}
			text := clean(line.Text)
			if line.Stream == "stderr" && !e.g.quiet {
				e.p.line("%s", e.p.paint(colorYellow, text))
			} else {
				e.p.line("%s", text)
			}
		}
	}
	drain := func() error {
		for {
			var page LogPage
			if _, err := c.get(ctx, apiPrefix+"/launches/"+pathEscape(id)+"/logs", url.Values{"after": {strconv.Itoa(after)}, "limit": {"1000"}}, &page); err != nil {
				return err
			}
			print(page.Items)
			truncated = page.Truncated
			if len(page.Items) == 0 {
				return nil
			}
			after = page.Items[len(page.Items)-1].Seq
			if len(page.Items) < 1000 {
				return nil
			}
		}
	}
	if err := drain(); err != nil {
		return err
	}
	if follow {
		// Agent output is not on the event stream, so following polls the
		// bounded log endpoint, and checks the launch state between polls.
		idle := 0
		for {
			d, _, err := e.getLaunch(ctx, c, id)
			if err != nil {
				return err
			}
			before := after
			if err := drain(); err != nil {
				return err
			}
			if terminalState(d.Launch.State) {
				e.p.note("Launch %s %s.", id, d.Launch.State)
				break
			}
			if after == before {
				idle++
			} else {
				idle = 0
			}
			wait := time.Second << min(idle, 2)
			if err := e.app.Sleep(ctx, wait); err != nil {
				return &Error{Exit: ExitInterrupted, Code: "interrupted", Message: "Stopped following the output; the launch keeps going."}
			}
		}
	}
	if e.g.json && !follow {
		return e.p.value(map[string]any{"items": all, "truncated": truncated})
	}
	if truncated {
		e.p.note("The service keeps at most 1 MiB and 20000 lines per launch; later output was not kept.")
	}
	return nil
}

func (e *env) events(ctx context.Context, id string, follow bool, after int) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	all := []LaunchEvent{}
	emit := func(ev LaunchEvent) {
		if e.g.json {
			if follow {
				raw, _ := json.Marshal(ev)
				e.p.line("%s", raw)
			} else {
				all = append(all, ev)
			}
			return
		}
		e.printEvent(ev)
	}
	if !follow {
		for {
			var page items[LaunchEvent]
			if _, err := c.get(ctx, apiPrefix+"/launches/"+pathEscape(id)+"/events", url.Values{"after": {strconv.Itoa(after)}, "limit": {"500"}}, &page); err != nil {
				return err
			}
			for _, ev := range page.Items {
				emit(ev)
				after = ev.Seq
			}
			if len(page.Items) < 500 {
				break
			}
		}
		if e.g.json {
			return e.p.value(map[string]any{"items": all})
		}
		return nil
	}
	follower := &eventFollower{c: c, id: id, after: after, sleep: e.app.Sleep}
	err = follower.run(ctx, func(ev LaunchEvent) (bool, error) {
		emit(ev)
		return ev.Kind == "state" && terminalState(ev.To), nil
	})
	if ctx.Err() != nil {
		return &Error{Exit: ExitInterrupted, Code: "interrupted", Message: "Stopped following events; the launch keeps going."}
	}
	return err
}

func (e *env) stop(ctx context.Context, id, reason string, wait bool, timeout time.Duration) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	d, _, err := e.getLaunch(ctx, c, id)
	if err != nil {
		return err
	}
	l := d.Launch
	if reason, err = defaultReason(reason, "Stopped with the agentgate CLI"); err != nil {
		return err
	}
	if l.Mode == "session" && (l.State == "running" || l.State == "provisioning") {
		if err := e.confirm(ctx, "Stop running session "+l.Name+" ("+l.ID+")? Its processes are killed", "--yes"); err != nil {
			return err
		}
	}
	var out Launch
	raw, err := c.mutate(ctx, "POST", apiPrefix+"/launches/"+pathEscape(id)+"/stop", map[string]string{"reason": reason}, true, &out)
	if err != nil {
		return err
	}
	if !wait {
		return e.emit(raw, func() error {
			switch out.State {
			case "stopping":
				e.p.line("Launch %s is stopping; the host kills its processes and returns the receipt. agentgate stop %s --wait follows it.", out.ID, out.ID)
			default:
				e.p.line("Launch %s is %s.", out.ID, e.p.state(out.State))
			}
			return nil
		})
	}
	if !e.g.json && !e.g.quiet {
		e.p.line("Launch %s is %s; waiting for it to end.", out.ID, e.p.state(out.State))
	}
	last := 0
	var page items[LaunchEvent]
	if _, err := c.get(ctx, apiPrefix+"/launches/"+pathEscape(id)+"/events", url.Values{"after": {"0"}, "limit": {"500"}}, &page); err == nil && len(page.Items) > 0 {
		last = page.Items[len(page.Items)-1].Seq
	}
	final, werr := e.follow(ctx, c, out, LaunchPlan{}, last, terminalState, timeout)
	if e.g.json {
		e.p.value(final)
	} else if werr == nil && !e.g.quiet {
		e.p.line("Launch %s ended %s.", final.ID, e.p.state(final.State))
	}
	if werr == nil {
		werr = launchOutcome(final, "stop")
	}
	var ce *Error
	if errors.As(werr, &ce) && e.g.json {
		ce.reported = true
	}
	return werr
}

func (e *env) decide(ctx context.Context, id string, approve bool, reason string) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	d, _, err := e.getLaunch(ctx, c, id)
	if err != nil {
		return err
	}
	l := d.Launch
	verb := map[bool]string{true: "approve", false: "reject"}[approve]
	if l.State != "approval_pending" {
		return &Error{Exit: ExitConflict, Code: "not_pending", Message: "Launch " + l.ID + " is " + l.State + "; it is not waiting for a decision.", Hint: "agentgate show " + l.ID}
	}
	interactive := e.app.Term.IsTerminal(0) && e.app.Term.IsTerminal(2)
	if approve && interactive && !e.g.json {
		var plan LaunchPlan
		if json.Unmarshal(l.Plan, &plan) == nil {
			e.printPlan(plan, l.Name, l.ID, false)
			e.p.line("")
		}
	}
	if strings.TrimSpace(reason) == "" {
		if !interactive {
			return usageError("%s needs --reason in a script", verb)
		}
		if reason, err = e.readLine(ctx, "Reason for the audit trail: "); err != nil {
			return err
		}
	}
	if reason, err = defaultReason(reason, ""); err != nil {
		return err
	}
	if approve {
		if err := e.confirm(ctx, "Approve launch "+l.Name+" ("+l.ID+") requested by "+l.RequestedBy+"?", "--yes"); err != nil {
			return err
		}
	}
	var out Launch
	raw, err := c.mutate(ctx, "POST", apiPrefix+"/launches/"+pathEscape(id)+"/"+verb, map[string]string{"reason": reason}, true, &out)
	if err != nil {
		var ce *Error
		if errors.As(err, &ce) && ce.Code == "self_approval" {
			ce.Message = "You requested launch " + l.ID + "; the service never lets the requester decide their own launch, with any credential."
			ce.Hint = "Ask a different human with the approver role to run: agentgate " + verb + " " + l.ID
		}
		return err
	}
	return e.emit(raw, func() error {
		e.p.line("Launch %s %s: %s.", out.ID, map[bool]string{true: "approved", false: "rejected"}[approve], e.p.state(out.State))
		if approve && out.ExpiresAt != "" {
			e.p.line("Its lifetime started; it expires at %s.", out.ExpiresAt)
		}
		return nil
	})
}
