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
	"strings"

	"alloyium.local/kernel-poc/internal/hostproto"
)

type secretFlags struct {
	upstreams, profiles, launchers listFlag
	header, scheme, target, reason string
}

func init() {
	register(&command{name: "secret set", args: "NAME --upstream HOST --allow-profile P", summary: "Seal a credential to a target's host key and store it (admin); the value is read from a hidden prompt or stdin.",
		help: `  --upstream HOST          exact upstream host the broker may send it to (repeatable, 1 to 8)
  --header NAME            header that carries it (default x-api-key; Authorization for bearer tokens)
  --scheme Bearer          prefix the value with "Bearer " (only with --header Authorization)
  --target NAME            target that stores it (default local)
  --allow-profile NAME     profile whose launches may use it (repeatable, required)
  --allow-launcher SUBJECT human who may launch with it (repeatable; default: you)
  --reason TEXT
The target's seal key must be signed by the host key pinned on this machine (docs/CLI.md).
The value is never read from arguments or the environment. On a terminal it is prompted twice
with echo off; otherwise it is read from standard input (one trailing newline is removed).`,
		setup: func(fs *flag.FlagSet) runner {
			var f secretFlags
			fs.Var(&f.upstreams, "upstream", "")
			fs.Var(&f.profiles, "allow-profile", "")
			fs.Var(&f.launchers, "allow-launcher", "")
			fs.StringVar(&f.header, "header", "x-api-key", "")
			fs.StringVar(&f.scheme, "scheme", "", "")
			fs.StringVar(&f.target, "target", "local", "")
			fs.StringVar(&f.reason, "reason", "", "")
			return func(ctx context.Context, e *env, args, tail []string) error {
				if len(args) != 1 || len(tail) != 0 {
					return usageError("secret set takes one secret name; the value is read from a prompt or standard input, never from arguments")
				}
				return e.secretSet(ctx, args[0], f)
			}
		}})
	register(&command{name: "secret ls", summary: "List secret metadata (admin); values never leave their host.", setup: func(fs *flag.FlagSet) runner {
		return func(ctx context.Context, e *env, args, _ []string) error { return e.secretList(ctx) }
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
	prefix := ""
	switch {
	case f.scheme == "":
	case strings.EqualFold(f.scheme, "bearer"):
		if !strings.EqualFold(f.header, "authorization") {
			return usageError("--scheme Bearer needs --header Authorization")
		}
		prefix = "Bearer "
	default:
		return usageError("--scheme supports only Bearer")
	}
	if len(f.profiles) == 0 {
		return usageError("give at least one --allow-profile: the profiles whose launches may use the secret")
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
	sealed, err := func() (string, error) {
		defer zero(value)
		if prefix == "" {
			return plan.seal(name, value)
		}
		full := make([]byte, 0, len(prefix)+len(value))
		full = append(append(full, prefix...), value...)
		defer zero(full)
		return plan.seal(name, full)
	}()
	if err != nil {
		return err
	}
	rawSealed, _ := base64.RawURLEncoding.DecodeString(sealed)
	sum := sha256.Sum256(rawSealed)
	body := map[string]any{"name": name, "target": t.ID, "upstreams": []string(f.upstreams), "header": f.header, "ciphertext": sealed,
		"allowed_profiles": []string(f.profiles), "allowed_launchers": launchers, "reason": reason}
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
	if e.g.json {
		return e.p.value(result)
	}
	e.p.line("Stored secret %s for target %s (id %s, state %s until the host confirms).", out.Name, t.Name, out.ID, e.p.state(out.State))
	e.p.fields("  ", [][2]string{{"host key", plan.HostKeyID + " (pinned), " + plan.HostKeyFingerprint}, {"sealed with", plan.Method}, {"seal key", plan.SealKeyID},
		{"ciphertext sha256", out.Fingerprint}, {"upstreams", strings.Join(out.Upstreams, ", ")}, {"header", out.Header},
		{"profiles", strings.Join(out.AllowedProfiles, ", ")}, {"launchers", strings.Join(out.AllowedLaunchers, ", ")}})
	e.p.note("Reference it in a launch with --secret %s[:ENV]; the agent sees only the broker address.", out.Name)
	return nil
}

// sealKey fetches the target's signed seal key; nil when the service does
// not publish one (the endpoint is a pending control plane change).
func (e *env) sealKey(ctx context.Context, c *Client, t Target) (*sealKeyAnswer, error) {
	var sk sealKeyAnswer
	_, err := c.get(ctx, apiPrefix+"/targets/"+pathEscape(t.ID)+"/seal-key", nil, &sk)
	var ce *Error
	if errors.As(err, &ce) && ce.Exit == ExitNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sk, nil
}

func (e *env) secretList(ctx context.Context) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	var list items[Secret]
	raw, err := c.get(ctx, apiPrefix+"/secrets", nil, &list)
	if err != nil {
		return err
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
			rows = append(rows, []string{s.Name, target, e.p.state(s.State), strings.Join(s.Upstreams, ","), s.Header, strings.Join(s.AllowedProfiles, ","), strings.Join(s.AllowedLaunchers, ","), short(s.ID)})
		}
		e.p.table([]string{"NAME", "TARGET", "STATE", "UPSTREAMS", "HEADER", "PROFILES", "LAUNCHERS", "ID"}, rows)
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
