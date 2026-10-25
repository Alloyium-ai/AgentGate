// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// doctor checks, in order, everything a launch needs from this machine's
// point of view and prints exactly what to fix. It only reads: it never
// changes the service, the host or the local configuration.

// Check outcomes.
const (
	checkOK   = "ok"
	checkWarn = "warn"
	checkFail = "FAIL"
)

// doctorCheck is one line of the report.
type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// The service refuses signed host requests beyond hostproto.MaxClockSkew; the
// doctor warns well before that.
const doctorSkewWarn = 15 * time.Second

func init() {
	register(&command{name: "doctor", summary: "Check the service, the token and a target, and say exactly what to fix.",
		help: `  --target NAME        the target to check (default local)
  --max-heartbeat-age D  how old the last heartbeat may be (default: 3 heartbeats)
  --state-dir DIR      this machine's host agent state, read as root to explain brokered-secrets (default /var/lib/agentgate-hostd)
Checks: the service answers; this machine's clock and the host's agree with the service's; the token is
accepted; the target exists, its host key is approved and pinned here, its host agent polls, it reports
the kernel-bpf-lsm (bpf-lsm) and brokered-secrets capabilities and a seal key, and its own mount roots
cover the service's. It changes nothing. Exit 0 when nothing failed, 1 otherwise.`,
		setup: func(fs *flag.FlagSet) runner {
			target := fs.String("target", "local", "")
			maxAge := fs.Duration("max-heartbeat-age", 0, "")
			stateDir := fs.String("state-dir", defaultHostdState, "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 0 {
					return usageError("doctor takes no arguments; name the target with --target")
				}
				if *maxAge < 0 {
					return usageError("--max-heartbeat-age is a positive duration")
				}
				return e.doctor(ctx, *target, *maxAge, *stateDir)
			}
		}})
}

func (e *env) doctor(ctx context.Context, target string, maxAge time.Duration, stateDir string) error {
	checks := e.doctorChecks(ctx, target, maxAge, stateDir)
	failed := 0
	for _, c := range checks {
		if c.Status == checkFail {
			failed++
		}
	}
	if e.g.json {
		if err := e.p.value(map[string]any{"ok": failed == 0, "checks": checks}); err != nil {
			return err
		}
	} else {
		for _, c := range checks {
			e.p.line("%-5s %-18s %s", c.Status, c.Name, c.Detail)
			if c.Fix != "" {
				e.p.line("      %-18s fix: %s", "", c.Fix)
			}
		}
		e.p.line("")
		if failed == 0 {
			e.p.line("Nothing failed. kernel_verified stays false until enforcement is verified on the host's kernel.")
		}
	}
	if failed > 0 {
		return &Error{Exit: ExitFailure, Code: "doctor_failed", Message: fmt.Sprintf("%d check(s) failed.", failed), Hint: "Apply each fix above, then run agentgate doctor again.", reported: e.g.json}
	}
	return nil
}

func (e *env) doctorChecks(ctx context.Context, ref string, maxAge time.Duration, stateDir string) []doctorCheck {
	var out []doctorCheck
	add := func(name, status, detail, fix string) {
		out = append(out, doctorCheck{Name: name, Status: status, Detail: detail, Fix: fix})
	}
	if err := e.resolve(); err != nil {
		add("service", checkFail, asError(ctx, err).Message, "agentgate login URL (or agentgate up on the service host)")
		return out
	}
	c, err := e.clientFor(e.server, e.token, e.transportOptions())
	if err != nil {
		ae := asError(ctx, err)
		add("service", checkFail, ae.Message, firstNonEmpty(ae.Hint, "check the service URL and its CA: agentgate login "+e.server.String()+" --ca-file FILE"))
		return out
	}
	// 1. The service answers its health check.
	sent := e.app.Now()
	resp, err := c.do(ctx, request{method: "GET", path: "/healthz", noAuth: true, retry: true})
	received := e.app.Now()
	if err != nil {
		ae := asError(ctx, err)
		add("service", checkFail, e.server.String()+": "+ae.Message,
			firstNonEmpty(ae.Hint, "start the service (agentgate up, or docker compose up -d in its deployment directory) and check the URL"))
		return out
	}
	if resp.status != http.StatusOK {
		add("service", checkFail, fmt.Sprintf("%s/healthz answered HTTP %d", e.server, resp.status), "check docker compose logs control (or the service's journal)")
		return out
	}
	add("service", checkOK, e.server.String()+" answers", "")

	// 2. Clock skew between this machine and the service (the Date header,
	// one-second resolution, taken at the middle of the round trip).
	if date, perr := http.ParseTime(resp.header.Get("Date")); perr != nil {
		add("clock", checkWarn, "the service sent no Date header, so the skew is unknown", "")
	} else {
		local := sent.Add(received.Sub(sent) / 2)
		skew := local.Sub(date)
		if skew < 0 {
			skew = -skew
		}
		text := fmt.Sprintf("this machine and the service differ by %s", skew.Truncate(time.Second))
		switch {
		case skew > hostproto.MaxClockSkew:
			add("clock", checkFail, text+fmt.Sprintf("; the service refuses host requests beyond %s", hostproto.MaxClockSkew),
				"synchronize the clocks of this machine and the service (timedatectl set-ntp true; chronyc tracking)")
		case skew > doctorSkewWarn:
			add("clock", checkWarn, text, "synchronize the clocks (timedatectl set-ntp true) before the skew reaches "+hostproto.MaxClockSkew.String())
		default:
			add("clock", checkOK, text, "")
		}
	}

	// 3. The token is accepted.
	if e.token == "" {
		add("token", checkFail, "no API token for "+e.server.String(), "agentgate login "+e.server.String())
		return out
	}
	if _, err = c.get(ctx, apiPrefix+"/launch-spec-schema", nil, nil); err != nil {
		ae := asError(ctx, err)
		fix := "agentgate login " + e.server.String()
		if ae.Exit != ExitAuth {
			fix = firstNonEmpty(ae.Hint, "check the service")
		}
		add("token", checkFail, ae.Message, fix)
		return out
	}
	detail := "accepted"
	if e.ctx != nil && e.ctx.Subject != "" {
		detail = "accepted for " + e.ctx.Subject + " (" + joinOr(e.ctx.Roles, "no roles") + ")"
	}
	if e.ctx != nil && e.ctx.ExpiresAt != "" {
		if exp, perr := time.Parse(time.RFC3339, e.ctx.ExpiresAt); perr == nil && exp.Sub(e.app.Now()) < 7*24*time.Hour {
			add("token", checkWarn, detail+"; expires "+e.ctx.ExpiresAt+" ("+age(e.ctx.ExpiresAt, e.app.Now())+")", "agentgate token create --save (or agentgate login "+e.server.String()+")")
		} else {
			add("token", checkOK, detail, "")
		}
	} else {
		add("token", checkOK, detail, "")
	}

	// 4. The target.
	t, _, err := e.getTarget(ctx, c, ref)
	if err != nil {
		ae := asError(ctx, err)
		switch ae.Exit {
		case ExitNotFound:
			add("target", checkFail, "no target named "+ref, "agentgate target add "+ref+" (or agentgate up --target "+ref+" on the host)")
		case ExitForbidden:
			add("target", checkFail, ae.Message, "use a token with a role that may read targets")
		default:
			add("target", checkFail, ae.Message, firstNonEmpty(ae.Hint, "check the service"))
		}
		return out
	}
	name := t.Name
	switch t.State {
	case "active":
		add("target", checkOK, name+" ("+t.ID+") is active", "")
	case "pending":
		add("target", checkFail, name+" has no host yet (pending enrollment)",
			"on the host: agentgate up --target "+name+" (or agentgate target enroll "+name+" and agentgate-hostd install --token-file FILE)")
		return out
	case "awaiting_key_approval":
		add("host key", checkFail, name+" waits for its host key "+t.HostKeyID+" to be approved",
			"compare it with agentgate-hostd status on the host, then: agentgate target approve-key "+name+" --host-key-id <the host's id>")
		return out
	case "rekey_required":
		add("target", checkFail, name+" must enroll again (the service job key rotated)", "agentgate target enroll "+name+", then agentgate-hostd install on the host again")
		return out
	default:
		add("target", checkFail, name+" is "+t.State, "a retiring or retired target runs nothing; add a new target")
		return out
	}

	// 5. The approved host key, pinned on this machine.
	pin, _ := e.pinState(t)
	switch {
	case strings.HasPrefix(pin, "pinned, matches"):
		add("host key", checkOK, t.HostKeyID+" approved and pinned here", "")
	case strings.HasPrefix(pin, "MISMATCH"):
		add("host key", checkFail, "the service shows "+t.HostKeyID+" but this machine "+strings.TrimPrefix(pin, "MISMATCH: "),
			"do not store secrets on "+name+" until you know why; compare with agentgate-hostd status on the host")
	default:
		add("host key", checkWarn, t.HostKeyID+" approved, "+pin+" on this machine",
			"compare with agentgate-hostd status on the host, then: agentgate target pin "+name+" --host-key-id <the host's id> (needed for secret set)")
	}

	// 6. The host agent polls (heartbeat age).
	limit := maxAge
	if limit == 0 {
		hb := t.HeartbeatSeconds
		if hb <= 0 {
			hb = int(hostproto.DefaultPollInterval / time.Second)
		}
		limit = time.Duration(hb*hostproto.MissedHeartbeatsLimit) * time.Second
	}
	if seen, perr := time.Parse(time.RFC3339Nano, t.LastSeen); t.LastSeen == "" || perr != nil {
		add("heartbeat", checkFail, "the host agent has never polled", "on the host: systemctl status agentgate-hostd; journalctl -u agentgate-hostd")
	} else {
		ago := e.app.Now().Sub(seen)
		if ago < 0 {
			ago = 0
		}
		text := fmt.Sprintf("last heartbeat %s ago (limit %s)", ago.Truncate(time.Second), limit)
		if ago > limit || !t.Online {
			add("heartbeat", checkFail, text+"; the service shows the host offline", "on the host: systemctl restart agentgate-hostd; journalctl -u agentgate-hostd (check its clock and its route to "+e.server.String()+")")
		} else {
			add("heartbeat", checkOK, text, "")
		}
	}

	// 7. The host's clock, as its last heartbeat showed it. The host signs
	// every request with its own time and the service refuses one beyond
	// hostproto.MaxClockSkew, so a host whose clock drifts that far stops
	// polling altogether (stale_request) and the heartbeat check fails.
	if t.HostClockSkewMS == nil {
		add("host clock", checkWarn, "no heartbeat has reported the host's clock yet", "wait for the host agent's next poll (or update agentgate-hostd and the service)")
	} else {
		skew := time.Duration(*t.HostClockSkewMS) * time.Millisecond
		ahead := "ahead of"
		if skew < 0 {
			skew, ahead = -skew, "behind"
		}
		text := fmt.Sprintf("the host's clock was %s %s the service's at its last heartbeat", skew.Round(time.Second), ahead)
		if at, perr := time.Parse(time.RFC3339Nano, t.HostClockMeasuredAt); perr == nil {
			text += " (" + age(t.HostClockMeasuredAt, e.app.Now()) + ")"
			if e.app.Now().Sub(at) > limit {
				text += "; the host has not polled since, which a skew beyond " + hostproto.MaxClockSkew.String() + " would cause"
			}
		}
		fix := "on the host: timedatectl set-ntp true; chronyc tracking (the service refuses host requests beyond " + hostproto.MaxClockSkew.String() + ")"
		switch {
		case skew > hostproto.MaxClockSkew:
			add("host clock", checkFail, text, fix)
		case skew > doctorSkewWarn:
			add("host clock", checkWarn, text, fix)
		default:
			add("host clock", checkOK, text, "")
		}
	}

	// 8. Capabilities: kernel enforcement and brokered secrets.
	has := map[string]bool{}
	for _, cap := range t.Capabilities {
		has[cap] = true
	}
	if has[hostproto.CapabilityBPFLSM] {
		add("kernel-bpf-lsm", checkOK, "the host reports BPF LSM enforcement (bpf-lsm); kernel_verified stays false until verified", "")
	} else {
		add("kernel-bpf-lsm", checkFail, "the host does not report bpf-lsm, so it fails every launch closed",
			"boot the host with BPF LSM (CONFIG_BPF_LSM=y and bpf in lsm=, check /sys/kernel/security/lsm), run poc/ssh-diagnostic/verify-kernel.sh, then systemctl restart agentgate-hostd")
	}
	if available, why, fix := brokerReport(t, e.localHostd(ctx, stateDir, t.ID)); available {
		add("brokered-secrets", checkOK, why, "")
		if t.SealKeyID == "" {
			add("seal key", checkFail, "the host has not published a signed seal key, so no secret can be sealed to it",
				"update agentgate-hostd on the host and wait for its next poll")
		} else {
			add("seal key", checkOK, "published "+t.SealKeyID[:min(16, len(t.SealKeyID))]+"... until "+t.SealKeyNotAfter, "")
		}
	} else {
		add("brokered-secrets", checkWarn, why, fix)
	}

	// 9. Mount roots: a host folder mounts only inside the service's roots
	// for the target and inside the host operator's own.
	service := joinOr(t.MountRoots, "none")
	switch {
	case t.HostMountRoots == nil:
		add("mount roots", checkWarn, "the host does not report mount roots of its own (an agentgate-hostd older than them), so only the service's list ("+service+") limits host folders",
			"update agentgate-hostd on the host, then list the folders there: sudo agentgate-hostd mount-roots --root PATH")
	case len(t.MountRootsNotOnHost) > 0:
		add("mount roots", checkWarn, "the host refuses mounts in "+strings.Join(t.MountRootsNotOnHost, ", ")+" (the service allows "+service+", the host "+joinOr(*t.HostMountRoots, "none")+")",
			"on the host: sudo agentgate-hostd mount-roots --root PATH ... (or narrow the service's list: agentgate target mount-roots "+name+" --root PATH)")
	case len(t.MountRoots) == 0:
		add("mount roots", checkOK, "no host folder may be mounted: the service lists no mount roots for "+name+" (the host allows "+joinOr(*t.HostMountRoots, "none")+")", "")
	default:
		add("mount roots", checkOK, "launches may mount folders inside "+service+" (the host allows "+joinOr(*t.HostMountRoots, "none")+")", "")
	}
	return out
}

// localHostd reads this machine's own agentgate-hostd status when doctor runs
// as root and that agent is the target's host; nil otherwise.
func (e *env) localHostd(ctx context.Context, stateDir, targetID string) *hostdStatus {
	if e.app.Runner == nil || e.app.Euid() != 0 {
		return nil
	}
	path, err := e.app.Runner.LookPath("agentgate-hostd")
	if err != nil {
		path = "/usr/local/sbin/agentgate-hostd"
	}
	res, err := e.app.Runner.Run(ctx, Cmd{Path: path, Args: []string{"status", "--state-dir", stateDir}})
	if err != nil || res.Exit != 0 {
		return nil
	}
	var s hostdStatus
	if json.Unmarshal(res.Stdout, &s) != nil || !s.Enrolled || s.TargetID != targetID {
		return nil
	}
	return &s
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
