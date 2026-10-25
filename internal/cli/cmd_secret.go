// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

type secretFlags struct {
	upstreams, profiles, launchers listFlag
	rules, extraHeaders            multiFlag
	header, scheme, basicUser      string
	target, reason                 string
	anyPath, wait                  bool
	waitTimeout                    time.Duration
}

func init() {
	register(&command{name: "secret set", args: "NAME --upstream HOST --allow-profile P", summary: "Seal a credential to a target's host key and store it (admin); the value is read from a hidden prompt or stdin.",
		help: `  --upstream HOST          exact upstream host the broker may send it to (repeatable, 1 to 8)
  --header NAME            header that carries it (default x-api-key; Authorization for bearer tokens)
  --scheme Bearer|Basic    how the broker writes the header (Authorization only; Bearer is its default)
  --username NAME          the Basic scheme's user name (also --basic-user)
  --rule METHODS:PATH[:exact|prefix]
                           a request the broker may forward with the credential (default exact), for example
                           POST:/v1/messages or GET,POST:/v1/:prefix (repeatable; deny by default)
  --allow-any-path         the explicit wildcard: every method on every path of the upstreams
  --extra-header NAME=VALUE  a non-secret header the broker sets on every request (repeatable)
  --target NAME            target that stores it (default local)
  --allow-profile NAME     profile whose launches may use it (repeatable, required)
  --allow-launcher SUBJECT human who may launch with it (repeatable; default: you)
  --wait                   wait for the host's receipt and verify it (proves the host stored this value)
  --wait-timeout DUR       default 2m
  --reason TEXT
The target's seal key must be signed by the host key pinned on this machine (docs/CLI.md).
The broker forwards nothing by default: give at least one --rule, or --allow-any-path for the
explicit wildcard (every method and path; every plan that uses it warns and needs approval).
The value is never read from arguments or the environment. On a terminal it is prompted twice
with echo off; otherwise it is read from standard input (one trailing newline is removed).`,
		setup: func(fs *flag.FlagSet) runner {
			var f secretFlags
			fs.Var(&f.upstreams, "upstream", "")
			fs.Var(&f.profiles, "allow-profile", "")
			fs.Var(&f.launchers, "allow-launcher", "")
			fs.Var(&f.rules, "rule", "")
			fs.Var(&f.extraHeaders, "extra-header", "")
			fs.StringVar(&f.header, "header", "x-api-key", "")
			fs.StringVar(&f.scheme, "scheme", "", "")
			fs.StringVar(&f.basicUser, "username", "", "")
			fs.StringVar(&f.basicUser, "basic-user", "", "")
			fs.StringVar(&f.target, "target", "local", "")
			fs.StringVar(&f.reason, "reason", "", "")
			fs.BoolVar(&f.anyPath, "allow-any-path", false, "")
			fs.BoolVar(&f.wait, "wait", false, "")
			fs.DurationVar(&f.waitTimeout, "wait-timeout", 2*time.Minute, "")
			return func(ctx context.Context, e *env, args, tail []string) error {
				if len(args) != 1 || len(tail) != 0 {
					return usageError("secret set takes one secret name; the value is read from a prompt or standard input, never from arguments")
				}
				return e.secretSet(ctx, args[0], f)
			}
		}})
	register(&command{name: "secret ls", summary: "List secrets: full metadata for administrators, or the names a launch may use; values never leave their host.",
		help: `  --target NAME     only this target (the launcher view needs one; default local)
  --profile NAME    the launcher view: whether this profile may use each secret
  --for-launch      the launcher view even for an administrator
Administrators see every secret's metadata (GET /secrets). Everyone else, or --for-launch and
--profile, sees what a launch spec needs (GET /targets/{id}/secrets): names, states, upstream
hosts, a rule summary and whether you (and the profile) may reference each. -q prints only the
names usable now.`,
		setup: func(fs *flag.FlagSet) runner {
			target := fs.String("target", "", "")
			profile := fs.String("profile", "", "")
			forLaunch := fs.Bool("for-launch", false, "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 0 {
					return usageError("secret ls takes no arguments")
				}
				return e.secretList(ctx, *target, *profile, *forLaunch)
			}
		}})
	register(&command{name: "secret rm", args: "NAME|ID", summary: "Remove a secret from its host (admin; confirms).",
		help: "  --target NAME   target of a secret named by name (default local)\n  --reason TEXT\n  --yes           confirm without a prompt",
		setup: func(fs *flag.FlagSet) runner {
			target := fs.String("target", "local", "")
			reason := fs.String("reason", "", "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 1 {
					return usageError("secret rm takes one secret name or id")
				}
				return e.secretRemove(ctx, args[0], *target, *reason)
			}
		}})
}

// parseRule reads METHODS:PATH[:exact|prefix].
func parseRule(spec string) (BrokerRule, error) {
	methods, rest, ok := strings.Cut(spec, ":")
	if !ok || methods == "" || !strings.HasPrefix(rest, "/") {
		return BrokerRule{}, usageError("--rule takes METHODS:PATH[:exact|prefix], for example POST:/v1/messages (got %q)", spec)
	}
	// A rule without a match type is exact: the service requires one.
	r := BrokerRule{Path: rest, Match: "exact"}
	for _, m := range []string{"exact", "prefix"} {
		if strings.HasSuffix(rest, ":"+m) {
			r.Path, r.Match = strings.TrimSuffix(rest, ":"+m), m
		}
	}
	for _, m := range strings.Split(methods, ",") {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" || m == "*" {
			return BrokerRule{}, usageError("--rule names methods (GET, POST, ...); use --allow-any-path for the wildcard")
		}
		r.Methods = append(r.Methods, m)
	}
	return r, nil
}

// secretInjection builds the broker settings of POST /secrets: the scheme
// and Basic user name, the rules (required: deny by default) and the
// non-secret extra headers. The service checks them again with the broker's
// own validator.
func secretInjection(f secretFlags) (map[string]any, error) {
	body := map[string]any{}
	authorization := strings.EqualFold(f.header, "authorization")
	switch {
	case f.scheme == "":
	case strings.EqualFold(f.scheme, "bearer"):
		body["scheme"] = "Bearer"
	case strings.EqualFold(f.scheme, "basic"):
		body["scheme"] = "Basic"
	default:
		return nil, usageError("--scheme is Bearer or Basic")
	}
	if body["scheme"] != nil && !authorization {
		return nil, usageError("--scheme %s needs --header Authorization", body["scheme"])
	}
	if f.basicUser != "" && body["scheme"] != "Basic" {
		return nil, usageError("--username needs --scheme Basic")
	}
	if body["scheme"] == "Basic" && f.basicUser == "" {
		return nil, usageError("--scheme Basic needs --username")
	}
	if f.basicUser != "" {
		body["username"] = f.basicUser
	}
	rules := []BrokerRule{}
	for _, spec := range f.rules {
		r, err := parseRule(spec)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	if f.anyPath {
		if len(rules) > 0 {
			return nil, usageError("--allow-any-path is the whole rule set; do not combine it with --rule")
		}
		rules = []BrokerRule{{Methods: []string{"*"}, Path: "/"}}
	}
	if len(rules) == 0 {
		return nil, usageError("the broker forwards nothing by default: give --rule METHODS:PATH (for example POST:/v1/messages), or --allow-any-path for every method and path of the upstreams")
	}
	body["rules"] = rules
	if len(f.extraHeaders) > 0 {
		extra := map[string]string{}
		for _, kv := range f.extraHeaders {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || !hostproto.HeaderPattern.MatchString(k) || v == "" {
				return nil, usageError("--extra-header takes NAME=VALUE")
			}
			if _, dup := extra[k]; dup {
				return nil, usageError("--extra-header %s is given twice", k)
			}
			extra[k] = v
		}
		body["extra_headers"] = extra
	}
	return body, nil
}

func (e *env) secretSet(ctx context.Context, name string, f secretFlags) error {
	if !hostproto.NamePattern.MatchString(name) {
		return usageError("a secret name matches ^[a-z0-9][a-z0-9-]{0,39}$")
	}
	if len(f.upstreams) < 1 || len(f.upstreams) > 8 {
		return usageError("give 1 to 8 --upstream hosts")
	}
	for _, u := range f.upstreams {
		if !hostproto.UpstreamPattern.MatchString(u) {
			return usageError("--upstream %q is not an exact lowercase host name (optionally :port)", u)
		}
	}
	if !hostproto.HeaderPattern.MatchString(f.header) {
		return usageError("--header is an HTTP header name")
	}
	if len(f.profiles) == 0 {
		return usageError("give at least one --allow-profile: the profiles whose launches may use the secret")
	}
	injection, err := secretInjection(f)
	if err != nil {
		return err
	}
	c, err := e.authed()
	if err != nil {
		return err
	}
	launchers := []string(f.launchers)
	if len(launchers) == 0 {
		if e.ctx.Subject == "" {
			return usageError("give --allow-launcher SUBJECT (for example local:alice): the humans who may launch with the secret")
		}
		launchers = []string{e.ctx.Subject}
	}
	reason, err := defaultReason(f.reason, "Store secret "+name+" with the agentgate CLI")
	if err != nil {
		return err
	}
	t, _, err := e.getTarget(ctx, c, f.target)
	if err != nil {
		return err
	}
	if t.State != "active" {
		return &Error{Exit: ExitConflict, Code: "target_unavailable", Message: "Target " + t.Name + " is " + t.State + "; secrets go only to an active target.", Hint: targetNext(t, "")}
	}
	st, err := e.store()
	if err != nil {
		return err
	}
	known, err := st.loadTrust()
	if err != nil {
		return err
	}
	sk, err := e.sealKey(ctx, c, t)
	if err != nil {
		return err
	}
	pin := known.find(e.server.String(), t.ID)
	plan, err := planSeal(pin, t, sk, e.app.Now())
	if err != nil {
		return err
	}
	if plan.HostKeyFingerprint != "" && pin.HostKeyFingerprint == "" {
		// Record the full fingerprint of the verified key next to the pin.
		entry := *pin
		entry.HostKeyFingerprint = plan.HostKeyFingerprint
		if _, err := st.pin(entry, true); err != nil {
			return err
		}
	}
	value, err := e.readNewSecret(ctx, "Value for secret "+name, true)
	if err != nil {
		return err
	}
	sealed, err := func() (*sealedValue, error) {
		defer zero(value)
		return plan.seal(name, value)
	}()
	if err != nil {
		return err
	}
	defer sealed.wipe()
	rawSealed, _ := base64.RawURLEncoding.DecodeString(sealed.ciphertext)
	sum := sha256.Sum256(rawSealed)
	body := map[string]any{"name": name, "target": t.ID, "upstreams": []string(f.upstreams), "header": f.header, "ciphertext": sealed.ciphertext,
		"allowed_profiles": []string(f.profiles), "allowed_launchers": launchers, "reason": reason}
	for k, v := range injection {
		body[k] = v
	}
	var out Secret
	if _, err = c.mutate(ctx, "POST", apiPrefix+"/secrets", body, false, &out); err != nil {
		return err
	}
	local := hex.EncodeToString(sum[:])
	if out.Fingerprint != "" && out.Fingerprint != local {
		return trustError("ciphertext_changed", "The service recorded ciphertext SHA-256 "+out.Fingerprint+" for secret "+out.Name+", but this machine sent "+local+".",
			"Remove the secret (agentgate secret rm "+out.Name+" --target "+t.Name+") and do not store secrets through this service until you know why.")
	}
	result := map[string]any{"secret": out, "seal": plan, "sealed_sha256": local}
	if !e.g.json {
		e.p.line("Stored secret %s for target %s (id %s, state %s until the host confirms).", out.Name, t.Name, out.ID, e.p.state(out.State))
		rules := []string{}
		for _, r := range out.Rules {
			rules = append(rules, ruleText(r))
		}
		header := strings.TrimSpace(out.Header + " " + out.Scheme)
		if out.Username != "" {
			header += " (user " + out.Username + ")"
		}
		pairs := [][2]string{{"host key", plan.HostKeyID + " (pinned), " + plan.HostKeyFingerprint}, {"sealed with", plan.Method}, {"seal key", plan.SealKeyID},
			{"ciphertext sha256", out.Fingerprint}, {"upstreams", strings.Join(out.Upstreams, ", ")}, {"header", header}, {"rules", joinOr(rules, "none")}}
		if len(out.ExtraHeaders) > 0 {
			names := []string{}
			for k := range out.ExtraHeaders {
				names = append(names, k)
			}
			pairs = append(pairs, [2]string{"extra headers", strings.Join(sortedStrings(names), ", ")})
		}
		pairs = append(pairs, [2]string{"profiles", strings.Join(out.AllowedProfiles, ", ")}, [2]string{"launchers", strings.Join(out.AllowedLaunchers, ", ")})
		e.p.fields("  ", pairs)
		if out.Wildcard {
			e.p.warn("secret %s uses wildcard rules: the broker forwards every method on every path of %s with it", out.Name, strings.Join(out.Upstreams, ", "))
		}
	}
	if f.wait {
		fp, err := e.awaitReceipt(ctx, c, out, sealed, f.waitTimeout)
		if err != nil {
			if e.g.json {
				e.p.value(result)
				var ce *Error
				if errors.As(err, &ce) {
					ce.reported = true
				}
			}
			return err
		}
		result["value_fingerprint"], result["receipt_verified"] = fp, true
		if !e.g.json {
			e.p.line("The host's receipt verifies: it stored exactly this value (fingerprint %s).", fp)
		}
	} else if !e.g.json {
		e.p.note("Run with --wait to verify the host's receipt for this value (only this run holds the secret that checks it).")
	}
	if e.g.json {
		return e.p.value(result)
	}
	e.p.note("Reference it in a launch with --secret %s[:ENV]; the agent sees only the broker address.", out.Name)
	return nil
}

func ruleText(r BrokerRule) string {
	s := strings.Join(r.Methods, ",") + " " + r.Path
	if r.Match != "" {
		s += " (" + r.Match + ")"
	}
	return s
}

// awaitReceipt polls for the host's receipt and verifies it against the
// sealed envelope that only this process holds.
func (e *env) awaitReceipt(ctx context.Context, c *Client, sec Secret, sealed *sealedValue, timeout time.Duration) (string, error) {
	deadline := e.app.Now().Add(timeout)
	start := time.Now()
	for {
		var ans SecretReceiptAnswer
		_, err := c.get(ctx, apiPrefix+"/secrets/"+pathEscape(sec.ID)+"/receipt", nil, &ans)
		var ce *Error
		switch {
		case err == nil && len(ans.Receipt) > 0:
			return sealed.verify(ans.Receipt)
		case errors.As(err, &ce) && ce.Code == "receipt_unavailable":
		case err != nil:
			return "", err
		}
		var list items[Secret]
		if _, err := c.get(ctx, apiPrefix+"/secrets", nil, &list); err == nil {
			for _, s := range list.Items {
				if s.ID == sec.ID && (s.State == "failed" || s.State == "deleted" || s.State == "deleting") {
					return "", &Error{Exit: ExitLaunchFailed, Code: "secret_" + s.State, Message: "The host did not store secret " + sec.Name + " (state " + s.State + ").", Hint: "Check agentgate-hostd on the target; the value may be outside what the broker can inject (8 to 8192 visible ASCII bytes)."}
				}
			}
		}
		if time.Since(start) > timeout || e.app.Now().After(deadline) {
			return "", &Error{Exit: ExitTimeout, Code: "receipt_timeout", Message: "The host has not confirmed secret " + sec.Name + " within " + timeout.String() + ".", Hint: "It may still: agentgate secret ls shows the state. The receipt can be verified only by this run, which holds the sealing secret."}
		}
		if err := e.app.Sleep(ctx, 2*time.Second); err != nil {
			return "", &Error{Exit: ExitInterrupted, Code: "interrupted", Message: "Stopped waiting for the receipt; the secret stays submitted."}
		}
	}
}

// sealKey fetches the target's host-signed seal key (GET
// /targets/{id}/seal-key); nil when the host has not published one yet.
func (e *env) sealKey(ctx context.Context, c *Client, t Target) (*sealKeyAnswer, error) {
	var sk sealKeyAnswer
	_, err := c.get(ctx, apiPrefix+"/targets/"+pathEscape(t.ID)+"/seal-key", nil, &sk)
	var ce *Error
	if errors.As(err, &ce) && (ce.Exit == ExitNotFound || ce.Code == "seal_key_unavailable") {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sk, nil
}

func (e *env) secretList(ctx context.Context, target, profile string, forLaunch bool) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	if forLaunch || profile != "" || (e.ctx != nil && len(e.ctx.Roles) > 0 && !containsString(e.ctx.Roles, "admin")) {
		return e.launcherSecrets(ctx, c, target, profile)
	}
	var list items[Secret]
	raw, err := c.get(ctx, apiPrefix+"/secrets", nil, &list)
	var ce *Error
	if errors.As(err, &ce) && ce.Exit == ExitForbidden {
		e.p.note("Only administrators list secret metadata; showing the secrets a launch on the target may use.")
		return e.launcherSecrets(ctx, c, target, profile)
	}
	if err != nil {
		return err
	}
	targetID := ""
	if target != "" {
		t, _, err := e.getTarget(ctx, c, target)
		if err != nil {
			return err
		}
		targetID = t.ID
		kept := []Secret{}
		for _, s := range list.Items {
			if s.TargetID == targetID {
				kept = append(kept, s)
			}
		}
		list.Items = kept
	}
	if targetID != "" && e.g.json {
		return e.p.value(map[string]any{"items": list.Items})
	}
	return e.emit(raw, func() error {
		if e.g.quiet {
			for _, s := range list.Items {
				e.p.line("%s", s.ID)
			}
			return nil
		}
		names := e.targetNames(ctx, c)
		rows := [][]string{}
		for _, s := range list.Items {
			target := names[s.TargetID]
			if target == "" {
				target = short(s.TargetID)
			}
			rules := ""
			switch {
			case s.Wildcard:
				rules = "WILDCARD"
			case len(s.Rules) > 0:
				texts := []string{}
				for _, r := range s.Rules {
					texts = append(texts, ruleText(r))
				}
				rules = strings.Join(texts, "; ")
			default:
				rules = "none (unusable: secret_rules_missing)"
			}
			state := e.p.state(s.State)
			if s.Removal == "unconfirmed" {
				state += " (removal unconfirmed: the value may remain on the host)"
			}
			rows = append(rows, []string{s.Name, target, state, strings.Join(s.Upstreams, ","), strings.TrimSpace(s.Header + " " + s.Scheme), rules, strings.Join(s.AllowedProfiles, ","), strings.Join(s.AllowedLaunchers, ","), s.ValueFingerprint, short(s.ID)})
		}
		e.p.table([]string{"NAME", "TARGET", "STATE", "UPSTREAMS", "HEADER", "RULES", "PROFILES", "LAUNCHERS", "VALUE FINGERPRINT", "ID"}, rows)
		return nil
	})
}

// targetSecrets reads what a launcher may know of a target's secrets.
func (e *env) targetSecrets(ctx context.Context, c *Client, target, profile string) (TargetSecrets, []byte, error) {
	var out TargetSecrets
	t, _, err := e.getTarget(ctx, c, target)
	if err != nil {
		return out, nil, err
	}
	q := url.Values{}
	if profile != "" {
		q.Set("profile", profile)
	}
	raw, err := c.get(ctx, apiPrefix+"/targets/"+pathEscape(t.ID)+"/secrets", q, &out)
	return out, raw, err
}

func (e *env) launcherSecrets(ctx context.Context, c *Client, target, profile string) error {
	if target == "" {
		target = "local"
	}
	list, raw, err := e.targetSecrets(ctx, c, target, profile)
	if err != nil {
		return err
	}
	return e.emit(raw, func() error {
		if e.g.quiet {
			for _, s := range list.Items {
				if s.Usable {
					e.p.line("%s", s.Name)
				}
			}
			return nil
		}
		rows := [][]string{}
		for _, s := range list.Items {
			rules := fmt.Sprintf("%d", s.RuleCount)
			if s.WildcardRules {
				rules = "WILDCARD"
			}
			usable := "yes"
			if !s.Usable {
				usable = "no: " + s.Reason
			}
			prof := "-"
			if s.ProfileAllowed != nil {
				prof = map[bool]string{true: "yes", false: "no"}[*s.ProfileAllowed]
			}
			rows = append(rows, []string{s.Name, e.p.state(s.State), strings.Join(s.Upstreams, ","), rules, map[bool]string{true: "yes", false: "no"}[s.LauncherAllowed], prof, clean(usable)})
		}
		e.p.table([]string{"NAME", "STATE", "UPSTREAMS", "RULES", "YOU", "PROFILE", "USABLE"}, rows)
		if len(list.Items) > 0 {
			e.p.note("Reference one with agentgate launch --target %s --secret NAME[:ENV]; the agent sees only the broker address.", list.Target)
		}
		return nil
	})
}

func (e *env) secretRemove(ctx context.Context, ref, target, reason string) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	var list items[Secret]
	if _, err = c.get(ctx, apiPrefix+"/secrets", nil, &list); err != nil {
		return err
	}
	var found *Secret
	for i, s := range list.Items {
		if s.ID == ref {
			found = &list.Items[i]
			break
		}
	}
	if found == nil {
		t, _, err := e.getTarget(ctx, c, target)
		if err != nil {
			return err
		}
		for i, s := range list.Items {
			if s.Name == ref && s.TargetID == t.ID && s.State != "deleted" {
				found = &list.Items[i]
				break
			}
		}
	}
	if found == nil {
		return &Error{Exit: ExitNotFound, Code: "not_found", Message: "No secret " + ref + " on target " + target + ".", Hint: "agentgate secret ls lists them."}
	}
	if reason, err = defaultReason(reason, "Remove secret "+found.Name+" with the agentgate CLI"); err != nil {
		return err
	}
	if found.State != "deleting" && found.State != "deleted" {
		if err = e.confirm(ctx, "Remove secret "+found.Name+" ("+found.ID+") from its host? Launches can no longer use it", "--yes"); err != nil {
			return err
		}
	}
	var out Secret
	raw, err := c.mutate(ctx, "DELETE", apiPrefix+"/secrets/"+pathEscape(found.ID), map[string]string{"reason": reason}, true, &out)
	if err != nil {
		return err
	}
	return e.emit(raw, func() error {
		e.p.line("Secret %s is %s; the host removes the value when it collects the job.", out.Name, e.p.state(out.State))
		return nil
	})
}
