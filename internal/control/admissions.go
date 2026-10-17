// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/audit"
	"alloyium.local/kernel-poc/internal/grant"
)

type AdmitInput struct {
	RequestID  string `json:"request_id"`
	RunID      string `json:"run_id"`
	Node       string `json:"node"`
	Boot       string `json:"boot"`
	Domain     string `json:"cgroup"`
	Workspace  string `json:"workspace"`
	DeadlineNS string `json:"deadline_ns"`
	Reason     string `json:"reason"`
}
type Evidence struct {
	Grant    string          `json:"grant"`
	Events   string          `json:"events"`
	Terminal json.RawMessage `json:"terminal"`
}
type WorkloadAdmission struct {
	AdmitInput
	JobDigest string `json:"job_digest"`
}

func (s *Store) AdmitWorkload(op Operation, in WorkloadAdmission) (any, error) {
	if !s.CustomerPolicy || len(in.JobDigest) != 64 {
		return nil, fail(422, "invalid_workload_digest", "A customer admission requires the exact workload SHA256 digest.")
	}
	if _, err := hex.DecodeString(in.JobDigest); err != nil {
		return nil, fail(422, "invalid_workload_digest", "Use a hexadecimal workload SHA256 digest.")
	}
	return s.admit(op, in.AdmitInput, in.JobDigest)
}

type IngestInput struct {
	AdmissionID string   `json:"admission_id"`
	Evidence    Evidence `json:"evidence"`
	Reason      string   `json:"reason"`
}

func (s *Store) Admit(op Operation, in AdmitInput) (any, error) {
	return s.admit(op, in, "")
}
func (s *Store) admit(op Operation, in AdmitInput, workloadDigest string) (any, error) {
	op.Action = "grant.issued"
	op.Resource = in.RequestID
	op.Run = in.RunID
	op.Reason = safeReason(in.Reason)
	op.Revalidate = func(tx *sql.Tx) error {
		if err := s.customerEnforcementReady(); err != nil {
			return err
		}
		return requestAdmissionReady(tx, in.RequestID)
	}
	op.RevalidateCached = func(tx *sql.Tx, raw string) error {
		if err := s.customerEnforcementReady(); err != nil {
			return err
		}
		var cached Admission
		if err := json.Unmarshal([]byte(raw), &cached); err != nil {
			return err
		}
		return cachedGrantReady(tx, cached.ID, op.Actor.Subject)
	}

	return s.Mutation(op, "admission:write", false, func(tx *sql.Tx, op *Operation) (any, error) {
		if err := s.customerEnforcementReady(); err != nil {
			return nil, err
		}
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		svc, err := serviceFrom(tx, op.Actor.Subject)
		if err != nil || svc.Kind != "service" || svc.Node != in.Node {
			return nil, fail(403, "node_binding_failed", "This service cannot admit a run on that node.")
		}
		q, err := scanRequest(tx.QueryRow("SELECT * FROM requests WHERE id=?", in.RequestID))
		if err != nil {
			return nil, err
		}
		if q.State != "approved" {
			return nil, fail(409, "request_unapproved", "A human must approve the request before admission.")
		}
		if err = approvalAfterRestore(tx, q.ID); err != nil {
			return nil, err
		}
		v, err := versionFrom(tx, q.ApprovedVersion)
		if err != nil {
			return nil, err
		}
		if v.State != "published" {
			return nil, fail(409, "policy_unpublished", "The approved version is no longer published.")
		}
		agent, err := serviceFrom(tx, q.AgentID)
		if err != nil || !agent.Enabled {
			return nil, fail(403, "agent_disabled", "The requested agent is not active.")
		}
		now := time.Now().Unix()
		id := newID()
		c := grant.Claims{Issuer: grant.Issuer, Audience: grant.Audience, Deployment: "disposable-dev-poc", Node: in.Node, Boot: in.Boot, Run: in.RunID, Domain: in.Domain, Agent: q.AgentID, AgentKey: agent.PublicKey, JobDigest: grant.Digest([]byte(q.ID + "|" + q.RequestedVersion + "|" + q.ApprovedVersion)), Generation: "1", Workspace: in.Workspace, Endpoint: fmt.Sprintf("%s:%d", v.Rights.TCPAddress, v.Rights.TCPPort), DeadlineNS: in.DeadlineNS, Issued: now, Expires: now + 30, Nonce: id, PolicyVersion: v.ID, PolicyDigest: v.Digest, ReadOnly: !v.Rights.WorkspaceWrite}
		if s.CustomerPolicy {
			c.Deployment = "agentgate-community-v1"
			if workloadDigest == "" {
				return nil, fail(422, "workload_required", "Use a customer admission with the exact workload digest.")
			}
			c.JobDigest = workloadDigest
		}
		token, err := grant.Sign(c, s.Authority)
		if err != nil {
			return nil, fail(422, "invalid_enrollment", "The trusted run enrollment does not match this kernel profile.")
		}
		a := Admission{id, q.ID, q.AgentID, in.RunID, in.Node, in.Boot, in.Domain, v.ID, v.Digest, token, grant.Digest([]byte(token)), "issued", stamp(), time.Unix(c.Expires, 0).UTC().Format(time.RFC3339)}
		_, err = tx.Exec("INSERT INTO admissions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", a.ID, a.RequestID, a.AgentID, a.RunID, a.Node, a.Boot, a.Domain, a.VersionID, a.PolicyDigest, a.Token, a.GrantDigest, a.State, a.Created, a.Expires)
		if err != nil {
			return nil, fail(409, "admission_replay", "The request or run already has an admission.")
		}
		op.Resource = a.ID
		op.Version = v.ID
		return a, nil
	})
}
func (s *Store) Release(op Operation, id string, in Decision) (any, error) {
	op.Action = "grant." + in.State
	op.Resource = id
	op.Reason = safeReason(in.Reason)
	scope := "admission:release"
	human := false
	if in.State == "revoked" {
		scope = "decision:write"
		human = true
	}
	return s.Mutation(op, scope, human, func(tx *sql.Tx, op *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		if in.State != "released" && in.State != "revoked" {
			return nil, fail(422, "invalid_state", "Release or revoke the admission.")
		}
		a, err := scanAdmission(tx.QueryRow("SELECT * FROM admissions WHERE id=?", id))
		if err != nil {
			return nil, notFound(err)
		}
		if !human {
			svc, err := serviceFrom(tx, op.Actor.Subject)
			if err != nil || svc.Node != a.Node {
				return nil, fail(403, "node_binding_failed", "The admission belongs to another node.")
			}
		}
		if a.State != "admitted" && a.State != "issued" {
			return nil, fail(409, "stale_release", "The admission already has a terminal state.")
		}
		a.Token = ""
		op.Before = a
		op.Run = a.RunID
		op.Version = a.VersionID
		a.State = in.State
		_, err = tx.Exec("UPDATE admissions SET state=? WHERE id=?", a.State, a.ID)
		return a, err
	})
}
func evidenceVerdict(dir string, e Evidence, authority, node string) (string, error) {
	paths := map[string][]byte{"grant.jws": []byte(e.Grant), "events.jsonl": []byte(e.Events), "terminal.json": e.Terminal}
	for name, data := range paths {
		if len(data) == 0 && name == "terminal.json" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			return "", err
		}
	}
	verdict, err := audit.Verify(dir, grant.Trust{Authority: authority, Node: node})
	if verdict == audit.UnknownKey {
		return "", err
	}
	if verdict == audit.Tampered || verdict == audit.Incomplete {
		return verdict, nil
	}
	return verdict, err
}
func (s *Store) Ingest(op Operation, in IngestInput, spool string) (any, error) {
	op.Action = "evidence.ingested"
	op.Resource = in.AdmissionID
	op.Reason = safeReason(in.Reason)
	return s.Mutation(op, "evidence:write", false, func(tx *sql.Tx, op *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		a, err := scanAdmission(tx.QueryRow("SELECT * FROM admissions WHERE id=?", in.AdmissionID))
		if err != nil {
			return nil, notFound(err)
		}
		svc, err := serviceFrom(tx, op.Actor.Subject)
		if err != nil || svc.Kind != "service" || svc.Node != a.Node {
			return nil, fail(403, "node_binding_failed", "Evidence can enter only through the enrolled node.")
		}
		var activated int
		if err = tx.QueryRow("SELECT COUNT(*) FROM activations WHERE admission_id=?", a.ID).Scan(&activated); err != nil {
			return nil, err
		}
		if activated != 1 {
			return nil, fail(409, "not_admitted", "The node did not confirm policy installation.")
		}
		if a.Token != in.Evidence.Grant {
			return nil, fail(422, "grant_binding_failed", "Evidence references a different admitted grant.")
		}
		if err = os.MkdirAll(spool, 0700); err != nil {
			return nil, err
		}
		dir, err := os.MkdirTemp(spool, "ingest-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(dir)
		authority := b64.EncodeToString(s.Authority.Public().(ed25519.PublicKey))
		verdict, err := evidenceVerdict(dir, in.Evidence, authority, svc.PublicKey)
		if err != nil {
			return nil, err
		}
		evidence := json.RawMessage(jsonText(in.Evidence))
		r := Run{a.RunID, a.ID, a.AgentID, a.VersionID, a.PolicyDigest, verdict, digest(evidence), evidence, stamp()}
		_, err = tx.Exec("INSERT INTO runs VALUES(?,?,?,?,?,?,?,?,?)", r.ID, r.AdmissionID, r.AgentID, r.VersionID, r.PolicyDigest, r.Verifier, r.EvidenceDigest, string(r.Evidence), r.Created)
		if err != nil {
			return nil, fail(409, "evidence_replay", "The immutable run evidence already exists.")
		}
		op.Run = r.ID
		op.Version = r.VersionID
		r.Evidence = nil
		return r, nil
	})
}
func (s *Store) RunDetail(id string, actor Actor) (map[string]any, error) {
	r, err := scanRun(s.DB.QueryRow("SELECT * FROM runs WHERE id=?", id))
	if err != nil {
		return nil, notFound(err)
	}
	if actor.Kind == "agent" && r.AgentID != actor.Subject {
		return nil, fail(403, "forbidden", "This run belongs to another agent.")
	}
	a, err := scanAdmission(s.DB.QueryRow("SELECT * FROM admissions WHERE id=?", r.AdmissionID))
	if err != nil {
		return nil, err
	}
	a.Token = ""
	q, err := scanRequest(s.DB.QueryRow("SELECT * FROM requests WHERE id=?", a.RequestID))
	if err != nil {
		return nil, err
	}
	requested, err := versionFrom(s.DB, q.RequestedVersion)
	if err != nil {
		return nil, err
	}
	used, err := versionFrom(s.DB, r.VersionID)
	if err != nil {
		return nil, err
	}
	var evidence Evidence
	if err = json.Unmarshal(r.Evidence, &evidence); err != nil {
		return nil, err
	}
	entries := []audit.Entry{}
	lines := strings.Split(strings.TrimSpace(evidence.Events), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		var entry audit.Entry
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}
		entries = append(entries, entry)
		if len(entries) >= 200 {
			break
		}
	}
	r.Evidence = nil
	return map[string]any{"run": r, "admission": a, "request": q, "requested_policy": requested, "approved_policy": used, "admitted_policy": used, "events": entries, "event_limit": 200, "seal": sealSummary(evidence.Terminal)}, nil
}
func (s *Store) VerifyRun(id string, actor Actor, spool string) (map[string]string, error) {
	r, err := scanRun(s.DB.QueryRow("SELECT * FROM runs WHERE id=?", id))
	if err != nil {
		return nil, notFound(err)
	}
	if actor.Kind == "agent" && r.AgentID != actor.Subject {
		return nil, fail(403, "forbidden", "This run belongs to another agent.")
	}
	a, err := scanAdmission(s.DB.QueryRow("SELECT * FROM admissions WHERE id=?", r.AdmissionID))
	if err != nil {
		return nil, err
	}
	var node string
	if err = s.DB.QueryRow("SELECT public_key FROM services WHERE node=? AND kind='service'", a.Node).Scan(&node); err != nil {
		return nil, err
	}
	var e Evidence
	if err = json.Unmarshal(r.Evidence, &e); err != nil {
		return nil, err
	}
	if err = os.MkdirAll(spool, 0700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(spool, "verify-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	v, err := evidenceVerdict(dir, e, b64.EncodeToString(s.Authority.Public().(ed25519.PublicKey)), node)
	return map[string]string{"stored_verifier": r.Verifier, "verifier": v, "evidence_digest": r.EvidenceDigest}, err
}
func validateNodeNumber(value string) error { _, err := strconv.ParseUint(value, 10, 64); return err }

func sealSummary(data json.RawMessage) map[string]any {
	var seal audit.Seal
	valid := len(data) > 0 && json.Unmarshal(data, &seal) == nil && seal.Manifest.Version == "alloyium-audit-v1"
	out := map[string]any{"present": valid, "node_signature": valid && seal.NodeSignature != "", "authority_receipt": valid && seal.Receipt != "", "retained": "Not reported", "decisions": "Not reported", "reported_loss": "Not reported"}
	if valid {
		for name, value := range map[string]string{"retained": seal.Manifest.Count, "decisions": seal.Manifest.Decisions, "reported_loss": seal.Manifest.Lost} {
			if _, err := strconv.ParseUint(value, 10, 64); err == nil {
				out[name] = value
			} else {
				out[name] = "Invalid claim"
			}
		}
	}
	return out
}
