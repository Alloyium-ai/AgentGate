// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/access"
	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/pocpolicy"
)

// Launch states.
const (
	StateRequested       = "requested"
	StateApprovalPending = "approval_pending"
	StateApproved        = "approved"
	StateQueued          = "queued"
	StateProvisioning    = "provisioning"
	StateRunning         = "running"
	StateStopping        = "stopping"
	StateStopped         = "stopped"
	StateExpired         = "expired"
	StateFailed          = "failed"
	StateRejected        = "rejected"
	StateCancelled       = "cancelled"
)

// LaunchTransitions is the complete state machine. transitionLaunch refuses
// every pair that is not listed.
var LaunchTransitions = map[string][]string{
	StateRequested:       {StateApprovalPending, StateApproved, StateRejected, StateCancelled},
	StateApprovalPending: {StateApproved, StateRejected, StateCancelled},
	StateApproved:        {StateQueued, StateCancelled, StateFailed},
	StateQueued:          {StateProvisioning, StateStopping, StateFailed, StateCancelled},
	StateProvisioning:    {StateRunning, StateStopping, StateFailed},
	StateRunning:         {StateStopping, StateExpired, StateFailed},
	StateStopping:        {StateStopped, StateExpired, StateFailed},
}

// TerminalState reports whether a launch state is final.
func TerminalState(state string) bool {
	switch state {
	case StateStopped, StateExpired, StateFailed, StateRejected, StateCancelled:
		return true
	}
	return false
}

func transitionAllowed(from, to string) bool {
	for _, next := range LaunchTransitions[from] {
		if next == to {
			return true
		}
	}
	return false
}

// Evidence-missing reasons.
const (
	MissingNotStarted = "not_started"
	MissingLostHost   = "lost_host"
)

// Bounds on launch history.
const (
	maxLaunchProgressEvents = 2000
	maxLaunchLogBytes       = 1 << 20
	maxLaunchLogLines       = 20000
	stopJobLifetime         = 24 * time.Hour
	resultGrace             = 5 * time.Minute
	stopGraceSeconds        = 10
)

// Permissions summarizes what the effective policy allows.
type Permissions struct {
	Network string   `json:"network_default"`
	IPv6    string   `json:"ipv6"`
	Web     []string `json:"web"`
	DNS     []string `json:"dns_resolvers"`
	// Taskboard is the taskboard exception, empty in a broker launch; Broker
	// is then the one exact private endpoint the agent may reach.
	Taskboard        string   `json:"taskboard"`
	Broker           string   `json:"broker,omitempty"`
	ReadOnly         []string `json:"read_only"`
	Writable         []string `json:"writable"`
	Execute          []string `json:"execute"`
	Deny             []string `json:"deny"`
	Devices          []string `json:"devices"`
	Signals          []string `json:"signals"`
	AnonymousExecute bool     `json:"anonymous_execute"`
}

// PlanSecret is one brokered secret in a plan. It names the secret and how
// the broker uses it, never a value. The approval covers exactly these rules.
type PlanSecret struct {
	Ref          string                 `json:"ref"`
	SecretID     string                 `json:"secret_id"`
	Env          string                 `json:"env"`
	Upstreams    []string               `json:"upstreams"`
	Header       string                 `json:"header"`
	Scheme       string                 `json:"scheme"`
	Username     string                 `json:"username,omitempty"`
	Rules        []hostproto.BrokerRule `json:"rules"`
	Wildcard     bool                   `json:"wildcard_rules"`
	ExtraHeaders map[string]string      `json:"extra_headers"`
	// BaseURL is the value Env receives inside the sandbox.
	BaseURL string `json:"base_url"`
	// ValueFingerprint is the host's keyed fingerprint of the stored value.
	ValueFingerprint string `json:"value_fingerprint,omitempty"`
}

// LaunchPlan is the resolved plan returned when a launch is created or
// planned. It is stored with the launch and never changes.
type LaunchPlan struct {
	SpecDigest      string                  `json:"spec_digest"`
	PolicyDigest    string                  `json:"policy_digest"`
	Target          map[string]string       `json:"target"`
	Profile         map[string]any          `json:"profile"`
	Mode            string                  `json:"mode"`
	LifetimeSeconds int                     `json:"lifetime_seconds"`
	ExpiresAt       string                  `json:"expires_at,omitempty"`
	ExpiryRule      string                  `json:"expiry_rule"`
	Image           string                  `json:"image"`
	Command         []string                `json:"command"`
	Workdir         string                  `json:"workdir"`
	Approval        string                  `json:"approval"`
	ApprovalReasons []string                `json:"approval_reasons"`
	Permissions     Permissions             `json:"permissions"`
	Mounts          []hostproto.LaunchMount `json:"mounts"`
	Secrets         []PlanSecret            `json:"secrets"`
	// Broker is the launch's broker endpoint and network, present exactly
	// when the launch brokers secrets. It is in the signed policy as well.
	Broker         *PlanBroker `json:"broker,omitempty"`
	KernelVerified bool        `json:"kernel_verified"`
	Notices        []string    `json:"notices"`
}

// Launch is the API view of a launch.
type Launch struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	SpecDigest       string          `json:"spec_digest"`
	TargetID         string          `json:"target_id"`
	ProfileVersionID string          `json:"profile_version_id,omitempty"`
	PolicyDigest     string          `json:"policy_digest"`
	Mode             string          `json:"mode"`
	LifetimeSeconds  int             `json:"lifetime_seconds"`
	ApprovalRequired bool            `json:"approval_required"`
	State            string          `json:"state"`
	RequestedBy      string          `json:"requested_by"`
	DecidedBy        string          `json:"decided_by,omitempty"`
	DecisionReason   string          `json:"decision_reason,omitempty"`
	StopReason       string          `json:"stop_reason,omitempty"`
	TerminalReason   string          `json:"terminal_reason,omitempty"`
	EvidenceMissing  string          `json:"evidence_missing,omitempty"`
	KernelVerified   bool            `json:"kernel_verified"`
	Created          string          `json:"created_at"`
	Updated          string          `json:"updated_at"`
	QueuedAt         string          `json:"queued_at,omitempty"`
	ExpiresAt        string          `json:"expires_at,omitempty"`
	StartedAt        string          `json:"started_at,omitempty"`
	EndedAt          string          `json:"ended_at,omitempty"`
	Revision         int             `json:"revision"`
	Plan             json.RawMessage `json:"plan,omitempty"`
	Receipt          json.RawMessage `json:"receipt,omitempty"`
	Spec             json.RawMessage `json:"spec,omitempty"`
	Policy           json.RawMessage `json:"policy,omitempty"`
}

type launchRow struct {
	Launch
	policy, plan, receipt string
	expiresMS             int64
	eventSeq, logSeq      int
	logBytes              int
}

const launchColumns = "id,name,spec_digest,target_id,profile_version_id,policy,policy_digest,plan,mode,lifetime_seconds,approval_required,state,requested_by,decided_by,decision_reason,stop_reason,terminal_reason,evidence_missing,receipt,kernel_verified,created,updated,queued_at,expires_at,started_at,ended_at,event_seq,log_seq,log_bytes,revision"

func scanLaunch(row rowScanner) (launchRow, error) {
	var l launchRow
	err := row.Scan(&l.ID, &l.Name, &l.SpecDigest, &l.TargetID, &l.ProfileVersionID, &l.policy, &l.PolicyDigest, &l.plan, &l.Mode, &l.LifetimeSeconds, &l.ApprovalRequired, &l.State, &l.RequestedBy, &l.DecidedBy, &l.DecisionReason, &l.StopReason, &l.TerminalReason, &l.EvidenceMissing, &l.receipt, &l.KernelVerified, &l.Created, &l.Updated, &l.QueuedAt, &l.expiresMS, &l.StartedAt, &l.EndedAt, &l.eventSeq, &l.logSeq, &l.logBytes, &l.Revision)
	if err != nil {
		return l, err
	}
	l.Plan = json.RawMessage(l.plan)
	if l.receipt != "" {
		l.Receipt = json.RawMessage(l.receipt)
	}
	if l.expiresMS > 0 {
		l.ExpiresAt = time.UnixMilli(l.expiresMS).UTC().Format(time.RFC3339Nano)
	}
	return l, nil
}

func launchFrom(q queryer, id string) (launchRow, error) {
	l, err := scanLaunch(q.QueryRow("SELECT "+launchColumns+" FROM launches WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return l, fail(404, "not_found", "The launch does not exist.")
	}
	return l, err
}

// transition is one requested state change.
type transition struct {
	To              string
	Reason          string
	EvidenceMissing string
	Receipt         string
	Actor           Actor
	Op              *Operation
	Data            any
}

// transitionLaunch is the only code that changes a launch state. It refuses
// pairs outside LaunchTransitions, requires evidence for terminal states and
// a confirmed cleanup for stopped and expired, compares and sets the
// revision, and writes the launch event and its audit record in the caller's
// transaction, so the change and its audit commit together or not at all.
func (s *Store) transitionLaunch(tx *sql.Tx, l *launchRow, t transition) error {
	from := l.State
	if !transitionAllowed(from, t.To) {
		return fail(409, "illegal_transition", "The launch cannot move from "+from+" to "+t.To+".")
	}
	receipt := l.receipt
	if t.Receipt != "" {
		if receipt != "" && receipt != t.Receipt {
			return fail(409, "receipt_exists", "The launch already holds a different receipt.")
		}
		receipt = t.Receipt
	}
	missing := l.EvidenceMissing
	if TerminalState(t.To) {
		if receipt == "" && t.EvidenceMissing == "" {
			return fail(409, "evidence_required", "A terminal launch needs a receipt or an explicit evidence_missing reason.")
		}
		if receipt == "" {
			missing = t.EvidenceMissing
		}
	}
	if t.To == StateStopped || t.To == StateExpired {
		var r hostproto.Receipt
		if receipt == "" || json.Unmarshal([]byte(receipt), &r) != nil || !r.DomainEmpty || !r.EnforcementReleased {
			return fail(409, "cleanup_unconfirmed", "A launch is stopped only after the host confirms an empty domain and released enforcement.")
		}
	}
	now := stamp()
	started, ended := l.StartedAt, l.EndedAt
	if t.To == StateRunning && started == "" {
		started = now
	}
	terminalReason := l.TerminalReason
	if TerminalState(t.To) {
		ended, terminalReason = now, t.Reason
	}
	stopReason := l.StopReason
	if t.To == StateStopping && stopReason == "" {
		stopReason = t.Reason
	}
	res, err := tx.Exec("UPDATE launches SET state=?,updated=?,started_at=?,ended_at=?,terminal_reason=?,stop_reason=?,evidence_missing=?,receipt=?,event_seq=event_seq+1,revision=revision+1 WHERE id=? AND state=? AND revision=?",
		t.To, now, started, ended, terminalReason, stopReason, missing, receipt, l.ID, from, l.Revision)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fail(409, "launch_changed", "The launch changed concurrently. Read it again.")
	}
	actor := t.Actor
	if actor.Subject == "" {
		actor = Actor{Subject: "agentgate-scheduler", Kind: "system"}
	}
	data := t.Data
	if data == nil {
		data = map[string]any{}
	}
	if _, err = tx.Exec("INSERT INTO launch_events VALUES(?,?,?,?,?,?,?,?,?)", l.ID, l.eventSeq+1, now, "state", from, t.To, actor.Subject, t.Reason, jsonText(data)); err != nil {
		return err
	}
	audit := Operation{Actor: actor, Action: "launch.state.changed", Resource: "launch:" + l.ID, Version: l.ProfileVersionID, Run: l.ID, Reason: t.Reason,
		Before: map[string]string{"state": from},
		After:  map[string]string{"state": t.To, "spec_digest": l.SpecDigest, "policy_digest": l.PolicyDigest, "evidence_missing": missing}}
	if t.Op != nil {
		audit.RequestID, audit.CorrelationID = t.Op.RequestID, t.Op.CorrelationID
	}
	if audit.RequestID == "" {
		audit.RequestID = "scheduler-" + newID()
	}
	if audit.Reason == "" {
		audit.Reason = "Launch state change"
	}
	if _, err = appendAudit(tx, audit, "committed"); err != nil {
		return err
	}
	l.State, l.Updated, l.StartedAt, l.EndedAt, l.TerminalReason, l.StopReason, l.EvidenceMissing, l.receipt = t.To, now, started, ended, terminalReason, stopReason, missing, receipt
	if receipt != "" {
		l.Receipt = json.RawMessage(receipt)
	}
	l.eventSeq++
	l.Revision++
	return nil
}

// appendLaunchEvent records a progress event, bounded per launch.
func appendLaunchEvent(tx *sql.Tx, l *launchRow, kind, actor, message string, data any) error {
	var count int
	if err := tx.QueryRow("SELECT count(*) FROM launch_events WHERE launch_id=? AND kind<>'state'", l.ID).Scan(&count); err != nil {
		return err
	}
	if count >= maxLaunchProgressEvents {
		return nil
	}
	if data == nil {
		data = map[string]any{}
	}
	if _, err := tx.Exec("UPDATE launches SET event_seq=event_seq+1 WHERE id=?", l.ID); err != nil {
		return err
	}
	l.eventSeq++
	_, err := tx.Exec("INSERT INTO launch_events VALUES(?,?,?,?,?,?,?,?,?)", l.ID, l.eventSeq, stamp(), kind, l.State, l.State, actor, message, jsonText(data))
	return err
}

func summarize(d pocpolicy.Document) Permissions {
	p := Permissions{Network: d.Default, IPv6: d.IPv6, DNS: append([]string{}, d.DNS.Resolvers...), Web: []string{}}
	if d.Broker != nil {
		p.Broker = d.Broker.Address + ":" + itoa(d.Broker.Port)
	} else {
		p.Taskboard = d.Taskboard.Address + ":" + itoa(d.Taskboard.Port)
	}
	current := access.CurrentWeb(d)
	for _, n := range []string{"http", "https", "quic"} {
		if current[n] {
			p.Web = append(p.Web, n)
		}
	}
	if fs := d.Filesystem; fs != nil {
		p.ReadOnly = append([]string{}, fs.ReadOnly...)
		p.Writable = append([]string{fs.Workspace}, fs.Scratch...)
		p.Execute = append([]string{}, fs.Execute...)
		p.Deny = append([]string{}, fs.Deny...)
		p.Devices = append([]string{}, fs.Devices...)
		p.AnonymousExecute = fs.Memory.AnonymousExecute
	}
	if d.Process != nil {
		p.Signals = append([]string{}, d.Process.Signals...)
	}
	return p
}

func itoa(n int) string { return strconv.Itoa(n) }

type resolved struct {
	spec      hostproto.LaunchSpec
	canonical []byte
	target    Target
	profile   *Profile
	version   *ProfileVersion
	policy    pocpolicy.Document
	raw       []byte
	plan      LaunchPlan
}

// resolveLaunch turns a validated spec into an effective policy and plan.
// launchID chooses the broker endpoint of a launch with secrets.
func (s *Store) resolveLaunch(tx *sql.Tx, spec hostproto.LaunchSpec, canonical []byte, specDigest, requester, launchID string) (resolved, error) {
	r := resolved{spec: spec, canonical: canonical}
	target, err := s.targetBy(tx, spec.Target)
	if err != nil {
		return r, fail(422, "target_unavailable", "The launch target does not exist.")
	}
	if target.State != "active" {
		return r, fail(422, "target_unavailable", "The launch target is not enrolled and active.")
	}
	r.target = target
	plan := LaunchPlan{SpecDigest: specDigest, Target: map[string]string{"id": target.ID, "name": target.Name}, Mode: spec.Mode, LifetimeSeconds: spec.LifetimeSeconds,
		ExpiryRule: "the lifetime starts when the launch is queued; the host and the kernel policy end it at expires_at",
		Image:      spec.Agent.Image, Command: spec.Agent.Command, Workdir: spec.Agent.Workdir, ApprovalReasons: []string{}, Mounts: []hostproto.LaunchMount{}, Secrets: []PlanSecret{}, Notices: []string{}}
	var doc pocpolicy.Document
	if len(spec.Access.Inline) > 0 {
		if doc, err = pocpolicy.Parse(spec.Access.Inline); err != nil {
			return r, specError("access.inline is invalid: %v", err)
		}
		plan.Profile = map[string]any{"inline": true}
		plan.ApprovalReasons = append(plan.ApprovalReasons, "inline access documents are not reviewed profiles")
	} else {
		p, err := s.profileBy(tx, spec.Access.Profile)
		if err != nil {
			return r, fail(422, "profile_unavailable", "The access profile does not exist.")
		}
		v, err := profileVersionFrom(tx, p.ID, spec.Access.Version)
		if err != nil {
			return r, fail(422, "profile_unavailable", "The access profile version does not exist.")
		}
		if doc, err = v.document(); err != nil {
			return r, err
		}
		if doc.Version != pocpolicy.VersionV2 {
			return r, fail(422, "profile_version_one", "A launch needs a version two profile; add a version with filesystem and process controls.")
		}
		r.profile, r.version = &p, &v
		plan.Profile = map[string]any{"id": p.ID, "name": p.Name, "version": v.Number, "version_id": v.ID, "digest": v.Digest}
		if p.ApprovedDigest != "" {
			plan.Profile["approved_version"], plan.Profile["approved_digest"] = p.ApprovedVersion, p.ApprovedDigest
		}
		reasons, err := s.profileApprovalReasons(tx, p, v, doc, len(spec.Secrets) > 0)
		if err != nil {
			return r, err
		}
		if len(reasons) > 0 {
			plan.ApprovalReasons = append(plan.ApprovalReasons, reasons...)
		} else {
			// The administrator reviewed exactly this version; what it grants
			// is listed for transparency, not to ask again.
			for _, note := range policyRiskNotes(doc, nil, len(spec.Secrets) > 0) {
				plan.Notices = append(plan.Notices, "approved profile version grants: "+note)
			}
		}
	}
	if spec.Approval == "required" {
		plan.ApprovalReasons = append(plan.ApprovalReasons, "the spec requires approval")
	}
	for _, m := range spec.Mounts {
		// Every mount brings host data into the sandbox: it must come from a
		// root the target's administrator listed, and a second human
		// approves it, a snapshot as much as a live folder.
		if !hostproto.MountUnderRoots(m.Source, target.MountRoots) {
			return r, fail(422, "mount_root_not_allowed", "Mount "+m.Name+": "+m.Source+" is not inside a host folder target "+target.Name+" allows (mount roots: "+joinOr(target.MountRoots)+
				"). An administrator lists the folders launches may mount with POST /targets/{id}/mount-roots.")
		}
		switch m.Mode {
		case "read-write":
			if !contains(target.Capabilities, hostproto.CapabilityLiveMounts) {
				return r, fail(422, "capability_missing", "A read-write mount needs a target that advertises live-mounts.")
			}
			plan.ApprovalReasons = append(plan.ApprovalReasons, "read-write host folder "+m.Name+" ("+m.Source+")")
		case "snapshot":
			if !contains(target.Capabilities, hostproto.CapabilitySnapshots) {
				return r, fail(422, "capability_missing", "A snapshot mount needs a target that advertises snapshot-mounts.")
			}
			plan.ApprovalReasons = append(plan.ApprovalReasons, "snapshot of host folder "+m.Name+" ("+m.Source+")")
		case "read-only":
			if !contains(target.Capabilities, hostproto.CapabilityLiveMounts) {
				return r, fail(422, "capability_missing", "A live read-only host folder needs a target that advertises live-mounts; use snapshot otherwise.")
			}
			plan.ApprovalReasons = append(plan.ApprovalReasons, "live host folder "+m.Name+" ("+m.Source+")")
		}
		mode := "read-only"
		if m.Mode == "read-write" {
			mode = "read-write"
		}
		res, err := access.Apply(doc, access.Edit{Action: access.ActionMount, Values: []string{m.Name}, Mode: mode})
		if err != nil {
			return r, fail(422, "mount_conflict", "Mount "+m.Name+": "+err.Error())
		}
		doc = res.Document
		plan.Mounts = append(plan.Mounts, hostproto.LaunchMount{Name: m.Name, Source: m.Source, Mode: m.Mode, Path: access.MountRoot + "/" + m.Name})
	}
	if len(spec.Secrets) > 0 {
		if r.profile == nil {
			return r, fail(422, "secret_scope", "Brokered secrets need a stored profile; an inline access document cannot reference secrets.")
		}
		plan.ApprovalReasons = append(plan.ApprovalReasons, "brokered secrets "+joinRefs(spec.Secrets))
	}
	var endpoint *PlanBroker
	if len(spec.Secrets) > 0 {
		b := brokerEndpoint(launchID)
		endpoint = &b
	}
	for _, sec := range spec.Secrets {
		stored, err := scanSecret(tx.QueryRow("SELECT "+secretColumns+" FROM secrets WHERE target_id=? AND name=? AND state='stored'", target.ID, sec.Ref))
		if err != nil {
			return r, fail(422, "secret_unavailable", "Secret "+sec.Ref+" is not stored on the launch target.")
		}
		if err = secretInScope(tx, stored.ID, r.profile.Name, requester); err != nil {
			return r, err
		}
		if len(stored.Rules) == 0 {
			return r, fail(422, "secret_rules_missing", "Secret "+sec.Ref+" has no broker rules, so it allows nothing (deny by default). Recreate it with explicit rules, "+
				`for example [{"methods":["POST"],"path":"/v1/messages","match":"exact"}], or with the wildcard [{"methods":["*"],"path":"/"}] to allow every method and path of its upstreams.`)
		}
		ps := PlanSecret{Ref: sec.Ref, SecretID: stored.ID, Env: sec.Expose.Env, Upstreams: stored.Upstreams, Header: stored.Header, Scheme: stored.Scheme,
			Username: stored.Username, Rules: stored.Rules, Wildcard: stored.Wildcard, ExtraHeaders: stored.ExtraHeaders,
			BaseURL: brokerBaseURL(endpoint, sec.Ref), ValueFingerprint: stored.ValueFingerprint}
		if stored.Wildcard {
			plan.Notices = append(plan.Notices, "WARNING: secret "+sec.Ref+" uses wildcard rules: the broker forwards every method on every path of "+joinList(stored.Upstreams)+" with the credential")
			plan.ApprovalReasons = append(plan.ApprovalReasons, "secret "+sec.Ref+" has wildcard broker rules")
		}
		plan.Secrets = append(plan.Secrets, ps)
	}
	if !contains(target.Capabilities, hostproto.CapabilityBrokeredSecrets) && len(spec.Secrets) > 0 {
		return r, fail(422, "capability_missing", "Brokered secrets need a target that advertises brokered-secrets (a host agent with the credential broker installed).")
	}
	if len(doc.Web.Rules) > 0 {
		plan.ApprovalReasons = append(plan.ApprovalReasons, "public web access")
	}
	// The launch document carries the mode and lifetime, so the kernel policy
	// itself expires at the launch lifetime.
	if doc.Broker != nil {
		return r, fail(422, "invalid_policy", "A broker endpoint is assigned by the service for a launch with secrets; an access document cannot name one.")
	}
	if doc, err = doc.ForLaunch(spec.Mode, spec.LifetimeSeconds); err != nil {
		return r, fail(422, "invalid_policy", "The effective policy is invalid: "+err.Error())
	}
	if endpoint != nil {
		// The broker takes the guard's single exact private endpoint; the
		// taskboard exception is not part of a launch with secrets.
		if doc, err = doc.WithBroker(endpoint.Address, endpoint.Port); err != nil {
			return r, fail(422, "invalid_policy", "The broker endpoint is invalid: "+err.Error())
		}
		plan.Broker = endpoint
		plan.Notices = append(plan.Notices, "the agent reaches its secrets only through the broker at "+endpoint.Address+":"+itoa(endpoint.Port)+"; the taskboard TCP endpoint is not allowed in this launch")
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return r, err
	}
	r.policy, r.raw = doc, raw
	plan.PolicyDigest = digest(raw)
	plan.Permissions = summarize(doc)
	plan.Approval = "auto"
	if len(plan.ApprovalReasons) > 0 {
		plan.Approval = "required"
	}
	plan.Notices = append(plan.Notices, "kernel_verified is false: this enforcement has not been verified on a BPF LSM kernel")
	if !contains(target.Capabilities, hostproto.CapabilityBPFLSM) {
		plan.Notices = append(plan.Notices, "the target does not advertise bpf-lsm; the host fails closed if it cannot enforce the policy")
	}
	sort.Strings(plan.ApprovalReasons)
	r.plan = plan
	return r, nil
}

// PlanLaunch validates and resolves a spec without creating anything. The
// plan request itself is audited.
func (s *Store) PlanLaunch(op Operation, raw []byte) (any, error) {
	op.Action, op.Resource, op.Reason = "launch.planned", "launch-plan", "Resolve a launch plan without creating a launch"
	spec, canonical, specDigest, verr := ValidateLaunchSpec(raw)
	return s.Mutation(op, "launch:write", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if verr != nil {
			return nil, verr
		}
		// A dry run has no launch id; its broker endpoint (and so its policy
		// digest) is an example: the created launch gets its own.
		r, err := s.resolveLaunch(tx, spec, canonical, specDigest, operation.Actor.Subject, "dry-run:"+specDigest)
		if err != nil {
			return nil, err
		}
		if r.plan.Broker != nil {
			r.plan.Notices = append(r.plan.Notices, "a dry run shows an example broker endpoint; the created launch is assigned its own, so its policy digest differs")
		}
		r.plan.ExpiresAt = s.now().Add(time.Duration(spec.LifetimeSeconds) * time.Second).UTC().Format(time.RFC3339)
		return map[string]any{"dry_run": true, "plan": r.plan, "spec": json.RawMessage(canonical), "policy": json.RawMessage(r.raw)}, nil
	})
}

// CreateLaunch validates a spec, resolves its plan, records the launch and,
// when no approval is needed, queues it.
func (s *Store) CreateLaunch(op Operation, raw []byte) (any, error) {
	op.Action, op.Resource, op.Reason = "launch.created", "launch", "Create a launch from a spec"
	spec, canonical, specDigest, verr := ValidateLaunchSpec(raw)
	return s.Mutation(op, "launch:write", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if verr != nil {
			return nil, verr
		}
		var live int
		if err := tx.QueryRow("SELECT count(*) FROM launches WHERE state NOT IN ('stopped','expired','failed','rejected','cancelled')").Scan(&live); err != nil {
			return nil, err
		}
		if live >= 256 {
			return nil, fail(409, "launch_limit", "Too many launches are active.")
		}
		launchID := newID()
		r, err := s.resolveLaunch(tx, spec, canonical, specDigest, operation.Actor.Subject, launchID)
		if err != nil {
			return nil, err
		}
		if _, err = tx.Exec("INSERT OR IGNORE INTO launch_specs VALUES(?,?,?)", specDigest, string(canonical), stamp()); err != nil {
			return nil, err
		}
		var stored string
		if err = tx.QueryRow("SELECT canonical FROM launch_specs WHERE digest=?", specDigest).Scan(&stored); err != nil || stored != string(canonical) {
			return nil, fail(503, "spec_corrupt", "The stored launch spec differs from its digest.")
		}
		versionID := ""
		if r.version != nil {
			versionID = r.version.ID
		}
		approval := r.plan.Approval == "required"
		l := launchRow{Launch: Launch{ID: launchID, Name: spec.Name, SpecDigest: specDigest, TargetID: r.target.ID, ProfileVersionID: versionID, PolicyDigest: r.plan.PolicyDigest, Mode: spec.Mode, LifetimeSeconds: spec.LifetimeSeconds, ApprovalRequired: approval, State: StateRequested, RequestedBy: operation.Actor.Subject, Created: stamp(), Revision: 1}}
		l.Updated = l.Created
		l.policy, l.plan = string(r.raw), jsonText(r.plan)
		if _, err = tx.Exec("INSERT INTO launches VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'','','','','','',0,?,?,'',0,'','',0,0,0,1)",
			l.ID, l.Name, l.SpecDigest, l.TargetID, l.ProfileVersionID, l.policy, l.PolicyDigest, l.plan, l.Mode, l.LifetimeSeconds, l.ApprovalRequired, l.State, l.RequestedBy, l.Created, l.Updated); err != nil {
			return nil, err
		}
		if _, err = tx.Exec("INSERT INTO launch_events VALUES(?,1,?,'state','',?,?,?,?)", l.ID, l.Created, StateRequested, operation.Actor.Subject, "Launch requested", jsonText(map[string]string{"spec_digest": specDigest, "policy_digest": l.PolicyDigest})); err != nil {
			return nil, err
		}
		if _, err = tx.Exec("UPDATE launches SET event_seq=1 WHERE id=?", l.ID); err != nil {
			return nil, err
		}
		l.eventSeq = 1
		operation.Resource, operation.Run, operation.Version = "launch:"+l.ID, l.ID, versionID
		if approval {
			if err = s.transitionLaunch(tx, &l, transition{To: StateApprovalPending, Reason: "Approval required: " + joinReasons(r.plan.ApprovalReasons), Actor: operation.Actor, Op: operation}); err != nil {
				return nil, err
			}
		} else {
			if err = s.transitionLaunch(tx, &l, transition{To: StateApproved, Reason: "Automatic approval: the profile, the spec and the role permit it", Actor: operation.Actor, Op: operation}); err != nil {
				return nil, err
			}
			if err = s.queueLaunch(tx, &l, r.plan, canonical, operation.Actor, operation); err != nil {
				return nil, err
			}
		}
		out, err := launchFrom(tx, l.ID)
		if err != nil {
			return nil, err
		}
		plan := r.plan
		plan.ExpiresAt = out.ExpiresAt
		return map[string]any{"launch": out.Launch, "plan": plan}, nil
	})
}

func joinReasons(reasons []string) string {
	out := ""
	for i, r := range reasons {
		if i > 0 {
			out += "; "
		}
		out += r
	}
	return out
}

// queueLaunch starts the lifetime clock and queues the host jobs.
func (s *Store) queueLaunch(tx *sql.Tx, l *launchRow, plan LaunchPlan, canonical []byte, actor Actor, op *Operation) error {
	target, err := s.targetBy(tx, l.TargetID)
	if err != nil || target.State != "active" {
		return fail(409, "target_unavailable", "The launch target is no longer enrolled and active.")
	}
	for _, sec := range plan.Secrets {
		var state string
		if err = tx.QueryRow("SELECT state FROM secrets WHERE id=?", sec.SecretID).Scan(&state); err != nil || state != "stored" {
			return fail(409, "secret_unavailable", "Secret "+sec.Ref+" is no longer stored on the target.")
		}
		profile, _ := plan.Profile["name"].(string)
		if err = secretInScope(tx, sec.SecretID, profile, l.RequestedBy); err != nil {
			return err
		}
	}
	now := s.now()
	expires := now.Add(time.Duration(l.LifetimeSeconds) * time.Second)
	if _, err = tx.Exec("UPDATE launches SET queued_at=?,expires_at=? WHERE id=?", stamp(), expires.UnixMilli(), l.ID); err != nil {
		return err
	}
	l.expiresMS = expires.UnixMilli()
	for _, m := range plan.Mounts {
		if m.Mode != "snapshot" {
			continue
		}
		if _, err = s.enqueueJob(tx, jobSpec{Type: hostproto.JobSnapshotMount, TargetID: l.TargetID, Launch: l, Payload: hostproto.SnapshotMountPayload{Name: m.Name, Source: m.Source, MaxBytes: hostproto.SnapshotMaxBytes, MaxEntries: hostproto.SnapshotMaxEntries}, Deadline: expires, Reason: "Copy a read-only snapshot for a launch", Actor: actor}, op); err != nil {
			return err
		}
	}
	// The launch job carries exactly the approved plan's injection rules.
	secrets := []hostproto.LaunchSecret{}
	for _, sec := range plan.Secrets {
		ls := hostproto.LaunchSecret{Ref: sec.Ref, SecretID: sec.SecretID, Env: sec.Env, Upstreams: sec.Upstreams, Header: sec.Header,
			Scheme: sec.Scheme, Username: sec.Username, Rules: sec.Rules}
		if len(sec.ExtraHeaders) > 0 {
			ls.ExtraHeaders = sec.ExtraHeaders
		}
		secrets = append(secrets, ls)
	}
	payload := hostproto.LaunchPayload{Spec: canonical, Policy: json.RawMessage(l.policy), ExpiresAtMS: expires.UnixMilli(), HeartbeatSeconds: target.HeartbeatSeconds, Mounts: plan.Mounts, Secrets: secrets}
	if _, err = s.enqueueJob(tx, jobSpec{Type: hostproto.JobLaunch, TargetID: l.TargetID, Launch: l, Payload: payload, Deadline: expires.Add(resultGrace), Reason: "Start a launch", Actor: actor}, op); err != nil {
		return err
	}
	return s.transitionLaunch(tx, l, transition{To: StateQueued, Reason: "Queued for the target", Actor: actor, Op: op, Data: map[string]string{"expires_at": time.UnixMilli(l.expiresMS).UTC().Format(time.RFC3339)}})
}

// DecisionInput approves or rejects a launch.
type DecisionInput struct {
	Reason string `json:"reason"`
}

// DecideLaunch approves or rejects a pending launch. The requester never
// decides their own launch, whichever credential they use.
func (s *Store) DecideLaunch(op Operation, id string, approve bool, in DecisionInput) (any, error) {
	op.Action, op.Resource, op.Run, op.Reason = "launch.rejected", "launch:"+id, id, safeReason(in.Reason)
	if approve {
		op.Action = "launch.approved"
	}
	return s.Mutation(op, "launch:approve", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		l, err := launchFrom(tx, id)
		if err != nil {
			return nil, err
		}
		if l.RequestedBy == operation.Actor.Subject {
			return nil, fail(403, "self_approval", "A different human must decide this launch.")
		}
		if l.State != StateApprovalPending {
			return nil, fail(409, "not_pending", "The launch is not waiting for approval.")
		}
		operation.Version = l.ProfileVersionID
		operation.Before = map[string]string{"state": l.State}
		if _, err = tx.Exec("UPDATE launches SET decided_by=?,decision_reason=? WHERE id=?", operation.Actor.Subject, in.Reason, l.ID); err != nil {
			return nil, err
		}
		l.DecidedBy, l.DecisionReason = operation.Actor.Subject, in.Reason
		if !approve {
			if err = s.transitionLaunch(tx, &l, transition{To: StateRejected, Reason: in.Reason, EvidenceMissing: MissingNotStarted, Actor: operation.Actor, Op: operation}); err != nil {
				return nil, err
			}
			return launchFrom(tx, l.ID)
		}
		var plan LaunchPlan
		if err = json.Unmarshal([]byte(l.plan), &plan); err != nil {
			return nil, err
		}
		var canonical string
		if err = tx.QueryRow("SELECT canonical FROM launch_specs WHERE digest=?", l.SpecDigest).Scan(&canonical); err != nil || digest([]byte(canonical)) != l.SpecDigest {
			return nil, fail(503, "spec_corrupt", "The stored launch spec differs from its digest.")
		}
		if digest([]byte(l.policy)) != l.PolicyDigest {
			return nil, fail(503, "policy_corrupt", "The stored launch policy differs from its digest.")
		}
		if err = s.transitionLaunch(tx, &l, transition{To: StateApproved, Reason: in.Reason, Actor: operation.Actor, Op: operation}); err != nil {
			return nil, err
		}
		if err = s.queueLaunch(tx, &l, plan, []byte(canonical), operation.Actor, operation); err != nil {
			return nil, err
		}
		return launchFrom(tx, l.ID)
	})
}

// StopLaunch requests a stop. It is idempotent: stopping a launch that is
// already stopping or terminal returns it unchanged.
func (s *Store) StopLaunch(op Operation, id string, in DecisionInput) (any, error) {
	op.Action, op.Resource, op.Run, op.Reason = "launch.stop.requested", "launch:"+id, id, safeReason(in.Reason)
	return s.Mutation(op, "launch:write", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		l, err := launchFrom(tx, id)
		if err != nil {
			return nil, err
		}
		operation.Version = l.ProfileVersionID
		operation.Before = map[string]string{"state": l.State}
		if err = s.stopLocked(tx, &l, in.Reason, "operator-stop", operation.Actor, operation); err != nil {
			return nil, err
		}
		return launchFrom(tx, l.ID)
	})
}

// stopLocked moves a launch toward a stop: launches that never reached the
// host are cancelled, the others move to stopping with a queued stop job.
func (s *Store) stopLocked(tx *sql.Tx, l *launchRow, reason, code string, actor Actor, op *Operation) error {
	switch l.State {
	case StateStopping, StateStopped, StateExpired, StateFailed, StateRejected, StateCancelled:
		return nil
	case StateRequested, StateApprovalPending, StateApproved:
		return s.transitionLaunch(tx, l, transition{To: StateCancelled, Reason: reason, EvidenceMissing: MissingNotStarted, Actor: actor, Op: op})
	case StateQueued:
		delivered, err := launchJobDelivered(tx, l.ID)
		if err != nil {
			return err
		}
		if !delivered {
			if _, err = tx.Exec("UPDATE jobs SET state='cancelled',envelope='',completed=?,revision=revision+1 WHERE launch_id=? AND state='queued'", stamp(), l.ID); err != nil {
				return err
			}
			return s.transitionLaunch(tx, l, transition{To: StateCancelled, Reason: reason, EvidenceMissing: MissingNotStarted, Actor: actor, Op: op})
		}
	}
	if err := s.transitionLaunch(tx, l, transition{To: StateStopping, Reason: reason, Actor: actor, Op: op}); err != nil {
		return err
	}
	return s.queueStop(tx, l, code, actor, op)
}

func (s *Store) queueStop(tx *sql.Tx, l *launchRow, code string, actor Actor, op *Operation) error {
	var pending int
	if err := tx.QueryRow("SELECT count(*) FROM jobs WHERE launch_id=? AND type='stop' AND state IN ('queued','delivered')", l.ID).Scan(&pending); err != nil {
		return err
	}
	if pending > 0 {
		return nil
	}
	_, err := s.enqueueJob(tx, jobSpec{Type: hostproto.JobStop, TargetID: l.TargetID, Launch: l, Payload: hostproto.StopPayload{Reason: code, GraceSeconds: stopGraceSeconds}, Deadline: s.now().Add(stopJobLifetime), Reason: "Stop a launch", Actor: actor}, op)
	return err
}

func launchJobDelivered(tx *sql.Tx, launchID string) (bool, error) {
	var n int
	err := tx.QueryRow("SELECT count(*) FROM jobs WHERE launch_id=? AND type IN ('launch','snapshot-mount') AND state<>'queued' AND state<>'cancelled'", launchID).Scan(&n)
	return n > 0, err
}

// LaunchQuery filters and pages GET /launches. State is a launch state,
// "active" (not terminal) or "ended" (terminal); Target is a target id or
// name; Name matches a substring of the launch name; Requester is a human
// subject. Pages are newest first by (created, id), which never changes for
// a launch, so a cursor resumes exactly after the last launch it returned. A
// cursor only says where a page starts; the filters and the caller's access
// apply to every page, so an altered cursor can skip launches but never show
// one the filters exclude.
type LaunchQuery struct {
	State, Target, Name, Requester string
	Limit                          int
	Cursor                         string
}

const (
	defaultLaunchPage = 100
	maxLaunchPage     = 200
	maxCursorBytes    = 512
)

var launchNameFilter = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

// ParseLaunchQuery reads and bounds the launch list filters.
func ParseLaunchQuery(q url.Values, a Actor) (LaunchQuery, error) {
	out := LaunchQuery{Limit: defaultLaunchPage}
	for k, v := range q {
		if len(v) > 1 {
			return out, fail(422, "invalid_filter", "Give each filter at most once: "+k+".")
		}
		switch k {
		case "state", "target", "name", "requester", "mine", "limit", "cursor":
		default:
			return out, fail(422, "invalid_filter", "Unknown launch filter "+strconv.Quote(k)+"; use state, target, name, requester, mine, limit or cursor.")
		}
	}
	out.State, out.Target, out.Name, out.Requester, out.Cursor = q.Get("state"), q.Get("target"), q.Get("name"), q.Get("requester"), q.Get("cursor")
	if out.State != "" && out.State != "active" && out.State != "ended" && !TerminalState(out.State) && LaunchTransitions[out.State] == nil {
		return out, fail(422, "invalid_filter", "Unknown launch state; use a launch state, active or ended.")
	}
	if out.Target != "" && !hostproto.NamePattern.MatchString(out.Target) && !hexID.MatchString(out.Target) {
		return out, fail(422, "invalid_filter", "target is a target name or id.")
	}
	if out.Name != "" && !launchNameFilter.MatchString(out.Name) {
		return out, fail(422, "invalid_filter", "name is 1 to 40 of a-z, 0-9 and -.")
	}
	if out.Requester != "" && !safeMeta.MatchString(out.Requester) {
		return out, fail(422, "invalid_filter", "requester is a subject such as local:alice.")
	}
	switch q.Get("mine") {
	case "", "0", "false":
	case "1", "true":
		if out.Requester != "" && out.Requester != a.Subject {
			return out, fail(422, "invalid_filter", "Use mine or requester, not both.")
		}
		out.Requester = a.Subject
	default:
		return out, fail(422, "invalid_filter", "mine is true or false.")
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxLaunchPage {
			return out, fail(422, "invalid_filter", "limit is 1 to 200.")
		}
		out.Limit = n
	}
	if len(out.Cursor) > maxCursorBytes {
		return out, fail(422, "invalid_cursor", "The cursor is not one this service issued.")
	}
	return out, nil
}

var hexID = regexp.MustCompile(`^[a-f0-9]{32}$`)

type launchCursor struct {
	Version int    `json:"v"`
	Created string `json:"c"`
	ID      string `json:"i"`
	Filter  string `json:"f"`
}

// filterKey binds a cursor to the filters it was issued for.
func (q LaunchQuery) filterKey(targetID string) string {
	return digest([]byte(strings.Join([]string{q.State, targetID, q.Name, q.Requester}, "\x00")))[:16]
}

// LaunchPage lists one page of launches, newest first, without their plans
// and receipts. next_cursor is present when more launches match.
func (s *Store) LaunchPage(q LaunchQuery) (map[string]any, error) {
	where, args := []string{}, []any{}
	targetID := ""
	if q.Target != "" {
		t, err := s.targetBy(s.DB, q.Target)
		if err != nil {
			return nil, err
		}
		targetID = t.ID
		where, args = append(where, "target_id=?"), append(args, t.ID)
	}
	switch q.State {
	case "":
	case "active":
		where = append(where, "state NOT IN ('stopped','expired','failed','rejected','cancelled')")
	case "ended":
		where = append(where, "state IN ('stopped','expired','failed','rejected','cancelled')")
	default:
		where, args = append(where, "state=?"), append(args, q.State)
	}
	if q.Name != "" {
		where, args = append(where, "instr(name,?)>0"), append(args, q.Name)
	}
	if q.Requester != "" {
		where, args = append(where, "requested_by=?"), append(args, q.Requester)
	}
	key := q.filterKey(targetID)
	if q.Cursor != "" {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(q.Cursor)
		var c launchCursor
		canonical := func() bool { again, _ := json.Marshal(c); return string(again) == string(raw) }
		if err != nil || json.Unmarshal(raw, &c) != nil || !canonical() || c.Version != 1 || c.Filter != key || !hexID.MatchString(c.ID) || len(c.Created) != len(stamp()) {
			return nil, fail(422, "invalid_cursor", "The cursor is not one this service issued for these filters; start again without it.")
		}
		where, args = append(where, "(created<? OR (created=? AND id<?))"), append(args, c.Created, c.Created, c.ID)
	}
	query := "SELECT " + launchColumns + " FROM launches"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY created DESC, id DESC LIMIT ?"
	args = append(args, q.Limit+1)
	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Launch{}
	for rows.Next() {
		l, err := scanLaunch(rows)
		if err != nil {
			return nil, err
		}
		l.Plan, l.Receipt = nil, nil
		out = append(out, l.Launch)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	page := map[string]any{"limit": q.Limit}
	if len(out) > q.Limit {
		out = out[:q.Limit]
		last := out[len(out)-1]
		raw, _ := json.Marshal(launchCursor{Version: 1, Created: last.Created, ID: last.ID, Filter: key})
		page["next_cursor"] = base64.RawURLEncoding.EncodeToString(raw)
	}
	page["items"] = out
	return page, nil
}

// expiringWindow is how soon a running launch's expiry counts as soon.
const expiringWindow = 30 * time.Minute

// LaunchSummary is GET /launches/summary: launch counts by state for every
// launch, and the few launches that need this actor's attention (waiting for
// a decision by someone other than their requester, or expiring soon).
func (s *Store) LaunchSummary(a Actor) (map[string]any, error) {
	counts := map[string]int{}
	for _, state := range launchStateOrder {
		counts[state] = 0
	}
	rows, err := s.DB.Query("SELECT state,count(*) FROM launches GROUP BY state")
	if err != nil {
		return nil, err
	}
	total, active := 0, 0
	for rows.Next() {
		var state string
		var n int
		if err = rows.Scan(&state, &n); err != nil {
			rows.Close()
			return nil, err
		}
		counts[state] = n
		total += n
		if !TerminalState(state) {
			active += n
		}
	}
	rows.Close()
	list := func(query string, args ...any) ([]Launch, error) {
		rows, err := s.DB.Query("SELECT "+launchColumns+" FROM launches WHERE "+query+" LIMIT 8", args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []Launch{}
		for rows.Next() {
			l, err := scanLaunch(rows)
			if err != nil {
				return nil, err
			}
			l.Plan, l.Receipt = nil, nil
			out = append(out, l.Launch)
		}
		return out, rows.Err()
	}
	awaiting := []Launch{}
	var awaitingCount int
	if a.Can("launch:approve") {
		if err = s.DB.QueryRow("SELECT count(*) FROM launches WHERE state='approval_pending' AND requested_by<>?", a.Subject).Scan(&awaitingCount); err != nil {
			return nil, err
		}
		if awaiting, err = list("state='approval_pending' AND requested_by<>? ORDER BY created", a.Subject); err != nil {
			return nil, err
		}
	}
	soon := s.now().Add(expiringWindow).UnixMilli()
	var expiringCount int
	if err = s.DB.QueryRow("SELECT count(*) FROM launches WHERE state NOT IN ('stopped','expired','failed','rejected','cancelled') AND expires_at>0 AND expires_at<=?", soon).Scan(&expiringCount); err != nil {
		return nil, err
	}
	expiring, err := list("state NOT IN ('stopped','expired','failed','rejected','cancelled') AND expires_at>0 AND expires_at<=? ORDER BY expires_at", soon)
	if err != nil {
		return nil, err
	}
	return map[string]any{"counts": counts, "total": total, "active": active,
		"awaiting_your_decision": map[string]any{"count": awaitingCount, "items": awaiting},
		"expiring_soon":          map[string]any{"count": expiringCount, "window_seconds": int(expiringWindow / time.Second), "items": expiring}}, nil
}

// launchStateOrder lists every launch state in state machine order.
var launchStateOrder = []string{StateRequested, StateApprovalPending, StateApproved, StateQueued, StateProvisioning, StateRunning, StateStopping, StateStopped, StateExpired, StateFailed, StateRejected, StateCancelled}

// LaunchDetail returns one launch with its spec, plan, policy and receipt.
func (s *Store) LaunchDetail(id string) (Launch, error) {
	l, err := launchFrom(s.DB, id)
	if err != nil {
		return Launch{}, err
	}
	var canonical string
	if err = s.DB.QueryRow("SELECT canonical FROM launch_specs WHERE digest=?", l.SpecDigest).Scan(&canonical); err != nil {
		return Launch{}, err
	}
	l.Spec, l.Policy = json.RawMessage(canonical), json.RawMessage(l.policy)
	return l.Launch, nil
}

// LaunchEvent is one ordered launch event.
type LaunchEvent struct {
	Seq    int             `json:"seq"`
	Time   string          `json:"time"`
	Kind   string          `json:"kind"`
	From   string          `json:"from_state,omitempty"`
	To     string          `json:"to_state,omitempty"`
	Actor  string          `json:"actor"`
	Reason string          `json:"reason"`
	Data   json.RawMessage `json:"data"`
}

// LaunchEvents returns events after a sequence number.
func (s *Store) LaunchEvents(id string, after, limit int) ([]LaunchEvent, error) {
	if _, err := launchFrom(s.DB, id); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 500 {
		limit = 200
	}
	rows, err := s.DB.Query("SELECT seq,time,kind,from_state,to_state,actor,reason,data FROM launch_events WHERE launch_id=? AND seq>? ORDER BY seq LIMIT ?", id, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LaunchEvent{}
	for rows.Next() {
		var e LaunchEvent
		var data string
		if err = rows.Scan(&e.Seq, &e.Time, &e.Kind, &e.From, &e.To, &e.Actor, &e.Reason, &data); err != nil {
			return nil, err
		}
		e.Data = json.RawMessage(data)
		out = append(out, e)
	}
	return out, rows.Err()
}

// LogLine is one bounded line of agent output.
type LogLine struct {
	Seq    int    `json:"seq"`
	Time   string `json:"time"`
	Stream string `json:"stream"`
	Text   string `json:"text"`
}

// LaunchLogs returns output after a sequence number.
func (s *Store) LaunchLogs(id string, after, limit int) (map[string]any, error) {
	l, err := launchFrom(s.DB, id)
	if err != nil {
		return nil, err
	}
	if limit < 1 || limit > 1000 {
		limit = 500
	}
	rows, err := s.DB.Query("SELECT seq,time,stream,text FROM launch_logs WHERE launch_id=? AND seq>? ORDER BY seq LIMIT ?", id, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []LogLine{}
	for rows.Next() {
		var line LogLine
		var ms int64
		if err = rows.Scan(&line.Seq, &ms, &line.Stream, &line.Text); err != nil {
			return nil, err
		}
		line.Time = time.UnixMilli(ms).UTC().Format(time.RFC3339Nano)
		items = append(items, line)
	}
	return map[string]any{"items": items, "bytes": l.logBytes, "limit_bytes": maxLaunchLogBytes, "truncated": l.logBytes >= maxLaunchLogBytes || l.logSeq >= maxLaunchLogLines}, rows.Err()
}

func joinList(values []string) string {
	out := ""
	for i, v := range values {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}

func joinRefs(secrets []hostproto.SpecSecret) string {
	out := ""
	for i, sec := range secrets {
		if i > 0 {
			out += ", "
		}
		out += sec.Ref
	}
	return out
}

// secretInScope checks that a secret may be used by this profile and by
// this requester.
func secretInScope(tx *sql.Tx, secretID, profile, requester string) error {
	var profiles, launchers string
	if err := tx.QueryRow("SELECT allowed_profiles,allowed_launchers FROM secrets WHERE id=?", secretID).Scan(&profiles, &launchers); err != nil {
		return fail(422, "secret_unavailable", "The secret is not stored on the launch target.")
	}
	var p, l []string
	json.Unmarshal([]byte(profiles), &p)
	json.Unmarshal([]byte(launchers), &l)
	if profile == "" || !contains(p, profile) {
		return fail(403, "secret_scope", "The secret is not scoped to this profile.")
	}
	if !contains(l, requester) {
		return fail(403, "secret_scope", "The secret is not scoped to this launcher.")
	}
	return nil
}
