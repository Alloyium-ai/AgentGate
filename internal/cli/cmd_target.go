// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
)

func init() {
	register(&command{name: "target ls", summary: "List targets with their state, host key and local pin.", setup: func(fs *flag.FlagSet) runner {
		return func(ctx context.Context, e *env, args, _ []string) error { return e.targetList(ctx) }
	}})
	register(&command{name: "target add", args: "NAME", summary: "Create a target and its one-time enrollment token (admin).",
		help: "  --token-file F   write the one-time token to a new mode 0600 file instead of printing it\n  --reason TEXT",
		setup: func(fs *flag.FlagSet) runner {
			reason := fs.String("reason", "", "")
			tokenFile := fs.String("token-file", "", "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 1 {
					return usageError("target add takes one target name")
				}
				return e.targetEnrollment(ctx, args[0], true, *reason, *tokenFile)
			}
		}})
	register(&command{name: "target enroll", args: "NAME", summary: "Issue a new one-time enrollment token for a target (reinstall, key rotation).",
		help: "  --token-file F   write the one-time token to a new mode 0600 file instead of printing it\n  --reason TEXT",
		setup: func(fs *flag.FlagSet) runner {
			reason := fs.String("reason", "", "")
			tokenFile := fs.String("token-file", "", "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 1 {
					return usageError("target enroll takes one target name")
				}
				return e.targetEnrollment(ctx, args[0], false, *reason, *tokenFile)
			}
		}})
	register(&command{name: "target status", args: "NAME", summary: "Show one target, its host key, the local pin and the next step.", setup: func(fs *flag.FlagSet) runner {
		return func(ctx context.Context, e *env, args, _ []string) error {
			if len(args) != 1 {
				return usageError("target status takes one target name or id")
			}
			return e.targetStatus(ctx, args[0])
		}
	}})
	register(&command{name: "target approve-key", args: "NAME", summary: "Approve the host key fingerprint the host printed (admin), and pin it locally.",
		help: `  --host-key-id ID   the fingerprint the host printed (ed25519:...); prompted on a terminal
  --reason TEXT
The service compares it with the key the host presented. Never copy the value the service shows:
type or paste the one from the host's own console.`,
		setup: func(fs *flag.FlagSet) runner {
			keyID := fs.String("host-key-id", "", "")
			reason := fs.String("reason", "", "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 1 {
					return usageError("target approve-key takes one target name")
				}
				return e.targetApprove(ctx, args[0], *keyID, *reason)
			}
		}})
	register(&command{name: "target pin", args: "NAME", summary: "Pin an already approved target's host key on this machine (for secret set).",
		help: "  --host-key-id ID   the fingerprint the host printed\n  --replace          replace a different existing pin",
		setup: func(fs *flag.FlagSet) runner {
			keyID := fs.String("host-key-id", "", "")
			replace := fs.Bool("replace", false, "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 1 || *keyID == "" {
					return usageError("target pin takes one target name and --host-key-id ID")
				}
				return e.targetPin(ctx, args[0], *keyID, *replace)
			}
		}})
	register(&command{name: "target mount-roots", args: "NAME", summary: "Set the host folders launches on a target may mount or snapshot (admin).",
		help: `  --root PATH   a folder launches may mount at or below (repeatable, at most 16)
  --clear       refuse every host folder (the default for a new target)
  --reason TEXT
Every mount still needs a second human's approval. Protected trees (system, container and VM state,
backups, logs, mail, spools), credential stores and home directories are never allowed.`,
		setup: func(fs *flag.FlagSet) runner {
			var roots multiFlag
			fs.Var(&roots, "root", "")
			clear := fs.Bool("clear", false, "")
			reason := fs.String("reason", "", "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 1 || (len(roots) == 0) == !*clear {
					return usageError("target mount-roots takes one target name and either --root PATH (repeatable) or --clear")
				}
				return e.targetMountRoots(ctx, args[0], []string(roots), *reason)
			}
		}})
	register(&command{name: "target rename", args: "NAME NEW-NAME", summary: "Rename a target (admin).", help: "  --reason TEXT",
		setup: func(fs *flag.FlagSet) runner {
			reason := fs.String("reason", "", "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 2 {
					return usageError("target rename takes the current and the new name")
				}
				return e.targetRename(ctx, args[0], args[1], *reason)
			}
		}})
	register(&command{name: "target retire", args: "NAME", summary: "Retire a target: remove its secrets from the host, then revoke its host key (admin; confirms).",
		help: `  --reason TEXT
  --yes            confirm without a prompt
  --force          finish without the host's confirmation that it removed its secrets
                   (the values may remain on the host; wipe it)
A target whose host may hold secrets is "retiring" until the host collects one secret-delete
per secret and confirms it; the last confirmation retires it. Live launches refuse retirement.`,
		setup: func(fs *flag.FlagSet) runner {
			reason := fs.String("reason", "", "")
			force := fs.Bool("force", false, "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 1 {
					return usageError("target retire takes one target name")
				}
				return e.targetRetire(ctx, args[0], *reason, *force)
			}
		}})
}

func (e *env) getTarget(ctx context.Context, c *Client, ref string) (Target, []byte, error) {
	var t Target
	raw, err := c.get(ctx, apiPrefix+"/targets/"+pathEscape(ref), nil, &t)
	return t, raw, err
}

// pinState describes the local pin of a target.
func (e *env) pinState(t Target) (string, *KnownTarget) {
	st, err := e.store()
	if err != nil {
		return "unknown", nil
	}
	k, err := st.loadTrust()
	if err != nil {
		return "unreadable", nil
	}
	pin := k.find(e.server.String(), t.ID)
	switch {
	case pin == nil:
		return "not pinned", nil
	case t.HostKeyID == "":
		return "pinned " + pin.HostKeyID + " (the service shows no key)", pin
	case subtle.ConstantTimeCompare([]byte(pin.HostKeyID), []byte(t.HostKeyID)) == 1:
		return "pinned, matches", pin
	}
	return "MISMATCH: pinned " + pin.HostKeyID, pin
}

func (e *env) targetList(ctx context.Context) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	var list items[Target]
	raw, err := c.get(ctx, apiPrefix+"/targets", nil, &list)
	if err != nil {
		return err
	}
	return e.emit(raw, func() error {
		if e.g.quiet {
			for _, t := range list.Items {
				e.p.line("%s", t.Name)
			}
			return nil
		}
		rows := [][]string{}
		for _, t := range list.Items {
			online := "no"
			if t.Online {
				online = "yes"
			}
			pin, _ := e.pinState(t)
			seen := ""
			if t.LastSeen != "" {
				seen = age(t.LastSeen, e.app.Now())
			}
			rows = append(rows, []string{t.Name, short(t.ID), e.p.state(t.State), online, t.HostKeyID, pin, seen})
		}
		e.p.table([]string{"NAME", "ID", "STATE", "ONLINE", "HOST KEY", "PIN", "LAST SEEN"}, rows)
		return nil
	})
}

// writeTokenFile creates a new private file for a one-time token.
func writeTokenFile(path, token string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return usageError("%s exists; choose a new file for the one-time token", path)
		}
		return failure("cannot create %s: %v", path, err)
	}
	_, err = f.WriteString(token + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return failure("cannot write %s: %v", path, err)
	}
	return nil
}

func (e *env) targetEnrollment(ctx context.Context, name string, create bool, reason, tokenFile string) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	var out TargetEnrollment
	var raw []byte
	if create {
		if reason, err = defaultReason(reason, "Add target "+name+" with the agentgate CLI"); err != nil {
			return err
		}
		raw, err = c.mutate(ctx, "POST", apiPrefix+"/targets", map[string]string{"name": name, "reason": reason}, false, &out)
	} else {
		if reason, err = defaultReason(reason, "Re-enroll target "+name+" with the agentgate CLI"); err != nil {
			return err
		}
		raw, err = c.mutate(ctx, "POST", apiPrefix+"/targets/"+pathEscape(name)+"/enrollment", map[string]string{"reason": reason}, false, &out)
	}
	if err != nil {
		return err
	}
	if tokenFile != "" {
		if err := writeTokenFile(tokenFile, out.Enrollment.Token); err != nil {
			e.p.warn("the one-time token could not be written; issue another with agentgate target enroll %s", name)
			return err
		}
	}
	if e.g.json {
		if tokenFile != "" {
			out.Enrollment.Token = ""
			return e.p.value(map[string]any{"target": out.Target, "enrollment": out.Enrollment, "token_file": tokenFile})
		}
		return e.p.rawJSON(raw)
	}
	verb := "Created"
	if !create {
		verb = "Re-enrolling"
	}
	e.p.line("%s target %s (id %s, state %s).", verb, out.Target.Name, out.Target.ID, out.Target.State)
	file := tokenFile
	if tokenFile == "" {
		file = "TOKEN-FILE"
		e.p.line("One-time enrollment token (works once, until %s):", out.Enrollment.ExpiresAt)
		e.p.line("%s", out.Enrollment.Token)
		e.p.note("Write it to a mode 0600 file for the host agent; a token on a command line is visible to other users.")
	} else {
		e.p.line("Wrote the one-time enrollment token (works once, until %s) to %s.", out.Enrollment.ExpiresAt, tokenFile)
	}
	e.p.line("On the host, as root:")
	e.p.line("  agentgate-hostd install --service-url %s --token-file %s", e.server.String(), file)
	e.p.line("Then compare the fingerprint the host prints with agentgate target status %s, and approve it:", out.Target.Name)
	e.p.line("  agentgate target approve-key %s --host-key-id ed25519:<the host's fingerprint>", out.Target.Name)
	return nil
}

func (e *env) targetStatus(ctx context.Context, ref string) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	t, raw, err := e.getTarget(ctx, c, ref)
	if err != nil {
		return err
	}
	pin, _ := e.pinState(t)
	if e.g.json {
		return e.p.rawJSON(raw)
	}
	online := "no"
	if t.Online {
		online = "yes"
	}
	seen := "never"
	if t.LastSeen != "" {
		seen = t.LastSeen + " (" + age(t.LastSeen, e.app.Now()) + ")"
	}
	e.p.fields("", [][2]string{
		{"name", t.Name}, {"id", t.ID}, {"state", e.p.state(t.State)}, {"online", online}, {"last seen", seen},
		{"hostname", t.Hostname}, {"agent version", t.AgentVersion}, {"capabilities", joinOr(t.Capabilities, "none")},
		{"host key", joinOr([]string{t.HostKeyID}, "none")}, {"local pin", pin}, {"job key", t.JobKeyID},
		{"mount roots", joinOr(t.MountRoots, "none (every host folder mount is refused)")}, {"host mount roots", t.hostRootsText()},
		{"heartbeat", fmt.Sprintf("every %ds", t.HeartbeatSeconds)}, {"kernel verified", fmt.Sprint(t.KernelVerified)},
	})
	if next := targetNext(t, pin); next != "" {
		e.p.line("\nnext: %s", next)
	}
	return nil
}

func targetNext(t Target, pin string) string {
	switch t.State {
	case "pending":
		return "install the host agent with the enrollment token (agentgate target enroll " + t.Name + " issues a new one)"
	case "awaiting_key_approval":
		return "compare " + t.HostKeyID + " with the fingerprint the host printed, then: agentgate target approve-key " + t.Name + " --host-key-id <host's fingerprint>"
	case "rekey_required":
		return "the service job key rotated: agentgate target enroll " + t.Name + " and install the host agent again"
	case "retiring":
		return "the host removes its secrets when it next polls; the last confirmation retires the target (a host that is gone: agentgate target retire " + t.Name + " --force)"
	case "active":
		if strings.HasPrefix(pin, "not pinned") {
			return "pin the key for secret set after comparing it with the host: agentgate target pin " + t.Name + " --host-key-id <host's fingerprint>"
		}
		if strings.HasPrefix(pin, "MISMATCH") {
			return "the service shows a different host key than you pinned: do not store secrets on this target until you know why"
		}
		if !t.Online {
			return "the host agent has not polled recently: check systemctl status agentgate-hostd on the host"
		}
	}
	return ""
}

func (e *env) targetApprove(ctx context.Context, ref, keyID, reason string) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	t, _, err := e.getTarget(ctx, c, ref)
	if err != nil {
		return err
	}
	if t.State != "awaiting_key_approval" {
		return &Error{Exit: ExitConflict, Code: "no_pending_key", Message: "Target " + t.Name + " is " + t.State + "; it has no host key waiting for approval.", Hint: targetNext(t, "")}
	}
	if keyID == "" {
		if !e.app.Term.IsTerminal(0) {
			return usageError("pass --host-key-id with the fingerprint the host printed")
		}
		e.p.note("The service reports that target %s presented host key %s.", t.Name, t.HostKeyID)
		e.p.note("Compare it with the fingerprint agentgate-hostd printed on the host itself.")
		if keyID, err = e.readLine(ctx, "Type or paste the host's fingerprint to approve it: "); err != nil {
			return err
		}
		keyID = strings.TrimSpace(keyID)
	}
	if !hostKeyIDPattern.MatchString(keyID) {
		return usageError("a host key fingerprint is ed25519: and 32 lowercase hex characters")
	}
	if reason, err = defaultReason(reason, "The host key fingerprint matches the host console"); err != nil {
		return err
	}
	var approved Target
	raw, err := c.mutate(ctx, "POST", apiPrefix+"/targets/"+pathEscape(t.ID)+"/approve-key", map[string]string{"host_key_id": keyID, "reason": reason}, true, &approved)
	if err != nil {
		var ce *Error
		if errors.As(err, &ce) && ce.Code == "fingerprint_mismatch" {
			ce.Exit = ExitTrust
		}
		return err
	}
	// The pin is the fingerprint the operator compared with the host
	// console, never the service's answer: a service that approves one key
	// and reports another must not become the anchor that secret set trusts.
	if approved.ID != t.ID || subtle.ConstantTimeCompare([]byte(keyID), []byte(approved.HostKeyID)) != 1 {
		return trustError("host_key_mismatch", "The service accepted the approval of target "+t.Name+" but answered with host key "+approved.HostKeyID+" for target "+approved.ID+", not the "+keyID+" you typed. Nothing was pinned on this machine.",
			"Do not store secrets on this target: find out why the service disagrees with the host console, then retire the target or issue a new token (agentgate target enroll "+t.Name+").")
	}
	previous, perr := e.pinTarget(approved, keyID, "approve-key", true)
	if e.g.json {
		if perr != nil {
			return perr
		}
		return e.p.rawJSON(raw)
	}
	e.p.line("Approved host key %s for target %s; the target is %s.", keyID, approved.Name, approved.State)
	if perr != nil {
		e.p.warn("the key was approved but not pinned on this machine")
		return perr
	}
	if previous != nil {
		e.p.line("Replaced the previous local pin %s.", previous.HostKeyID)
	}
	e.p.line("Pinned it on this machine for secret set.")
	return nil
}

// pinTarget pins keyID, the fingerprint the operator obtained out of band
// (typed from the host console, or read from this machine's own host agent),
// for target t of this service. The service's answer is never the source of
// a pin: keyID must equal the host key the service reports (constant time),
// or nothing is pinned and the caller gets a trust failure.
func (e *env) pinTarget(t Target, keyID, source string, replace bool) (*KnownTarget, error) {
	if keyID == "" || subtle.ConstantTimeCompare([]byte(keyID), []byte(t.HostKeyID)) != 1 {
		return nil, trustError("host_key_mismatch", "The service reports host key "+t.HostKeyID+" for target "+t.Name+", not "+keyID+". Nothing was pinned.",
			"Do not pin or store secrets: find out why the host and the service disagree (re-enroll the host if needed).")
	}
	st, err := e.store()
	if err != nil {
		return nil, err
	}
	return st.pin(KnownTarget{Server: e.server.String(), TargetID: t.ID, TargetName: t.Name, HostKeyID: keyID, PinnedAt: e.app.Now().UTC().Format("2006-01-02T15:04:05Z"), Source: source}, replace)
}

func (e *env) targetPin(ctx context.Context, ref, keyID string, replace bool) error {
	if !hostKeyIDPattern.MatchString(keyID) {
		return usageError("a host key fingerprint is ed25519: and 32 lowercase hex characters")
	}
	c, err := e.authed()
	if err != nil {
		return err
	}
	t, _, err := e.getTarget(ctx, c, ref)
	if err != nil {
		return err
	}
	if t.State != "active" {
		return &Error{Exit: ExitConflict, Code: "target_not_active", Message: "Target " + t.Name + " is " + t.State + "; pin a target after its key is approved.", Hint: targetNext(t, "")}
	}
	if subtle.ConstantTimeCompare([]byte(keyID), []byte(t.HostKeyID)) != 1 {
		return trustError("host_key_mismatch", "The service reports host key "+t.HostKeyID+" for target "+t.Name+", not "+keyID+".", "Do not pin or store secrets: find out why the host and the service disagree (re-enroll the host if needed).")
	}
	previous, err := e.pinTarget(t, keyID, "pin", replace)
	if err != nil {
		return err
	}
	if e.g.json {
		return e.p.value(map[string]any{"target_id": t.ID, "target": t.Name, "host_key_id": keyID, "pinned": true})
	}
	if previous != nil {
		e.p.line("Replaced pin %s.", previous.HostKeyID)
	}
	e.p.line("Pinned host key %s for target %s.", keyID, t.Name)
	return nil
}

func (e *env) targetMountRoots(ctx context.Context, ref string, roots []string, reason string) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	if roots == nil {
		roots = []string{}
	}
	if reason, err = defaultReason(reason, "Set the mount roots of target "+ref+" with the agentgate CLI"); err != nil {
		return err
	}
	var t Target
	raw, err := c.mutate(ctx, "POST", apiPrefix+"/targets/"+pathEscape(ref)+"/mount-roots", map[string]any{"mount_roots": roots, "reason": reason}, true, &t)
	if err != nil {
		return err
	}
	return e.emit(raw, func() error {
		if len(t.MountRoots) == 0 {
			e.p.line("Target %s: launches may mount no host folder.", t.Name)
		} else {
			e.p.line("Target %s: launches may mount host folders at or below %s (each mount needs approval).", t.Name, strings.Join(t.MountRoots, ", "))
		}
		return nil
	})
}

func (e *env) targetRename(ctx context.Context, ref, name, reason string) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	if reason, err = defaultReason(reason, "Rename target "+ref+" to "+name); err != nil {
		return err
	}
	var t Target
	raw, err := c.mutate(ctx, "PATCH", apiPrefix+"/targets/"+pathEscape(ref), map[string]string{"name": name, "reason": reason}, true, &t)
	if err != nil {
		return err
	}
	return e.emit(raw, func() error {
		e.p.line("Renamed target %s to %s.", ref, t.Name)
		return nil
	})
}

func (e *env) targetRetire(ctx context.Context, ref, reason string, force bool) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	t, _, err := e.getTarget(ctx, c, ref)
	if err != nil {
		return err
	}
	if reason, err = defaultReason(reason, "Retire target "+t.Name+" with the agentgate CLI"); err != nil {
		return err
	}
	if t.State != "retired" {
		question := "Retire target " + t.Name + "? Its host removes every secret stored on it, then its host key is revoked"
		if force {
			question = "Retire target " + t.Name + " WITHOUT the host confirming that it removed its secrets? The values may remain on the host"
		}
		if err = e.confirm(ctx, question, "--yes"); err != nil {
			return err
		}
	}
	body := map[string]any{"reason": reason}
	if force {
		body["force"] = true
	}
	var out Target
	raw, err := c.mutate(ctx, "DELETE", apiPrefix+"/targets/"+pathEscape(t.ID), body, true, &out)
	var ce *Error
	if errors.As(err, &ce) && ce.Code == "secrets_on_host" {
		ce.Hint = "Approve the host key so the host can remove them (agentgate target approve-key " + t.Name + "), or retire with --force and wipe the host."
	}
	if err != nil {
		return err
	}
	return e.emit(raw, func() error {
		switch out.State {
		case "retiring":
			e.p.line("Target %s is retiring: its host removes each secret when it next polls, and the last confirmation retires it.", out.Name)
			e.p.note("Follow it with agentgate target status %s; agentgate secret ls shows each secret's state.", out.Name)
		default:
			e.p.line("Target %s is %s.", out.Name, out.State)
		}
		return nil
	})
}
