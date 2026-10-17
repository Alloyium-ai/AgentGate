// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"database/sql"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Filter struct {
	Cursor int64
	Limit  int
	Values url.Values
}

func ParseFilter(q url.Values) (Filter, error) {
	f := Filter{Limit: 50, Values: q}
	if v := q.Get("limit"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 1 || n > 100 {
			return f, fail(422, "invalid_limit", "Use a limit between 1 and 100.")
		}
		f.Limit = n
	}
	if v := q.Get("cursor"); v != "" {
		data, e := b64.DecodeString(v)
		if e != nil || len(data) > 20 {
			return f, fail(422, "invalid_cursor", "The cursor is invalid.")
		}
		f.Cursor, e = strconv.ParseInt(string(data), 10, 64)
		if e != nil || f.Cursor < 1 {
			return f, fail(422, "invalid_cursor", "The cursor is invalid.")
		}
	}
	return f, nil
}
func cursor(n int64) string { return b64.EncodeToString([]byte(strconv.FormatInt(n, 10))) }
func queryParts(f Filter, allowed map[string]string, timeFields ...string) (string, []any, error) {
	timeField := "time"
	if len(timeFields) > 0 {
		timeField = timeFields[0]
	}
	where := []string{"rowid>?"}
	args := []any{f.Cursor}
	for name, column := range allowed {
		if v := f.Values.Get(name); v != "" {
			if len(v) > 200 {
				return "", nil, fail(422, "invalid_filter", "A filter exceeds its limit.")
			}
			where = append(where, column+"=?")
			args = append(args, v)
		}
	}
	for _, name := range []string{"after", "before"} {
		if v := f.Values.Get(name); v != "" {
			parsed, e := time.Parse(time.RFC3339Nano, v)
			if e != nil {
				return "", nil, fail(422, "invalid_time", "Use an RFC3339 time.")
			}
			op := ">="
			if name == "before" {
				op = "<="
			}
			where = append(where, timeField+op+"?")
			args = append(args, parsed.UTC().Format("2006-01-02T15:04:05.000000000Z"))
		}
	}
	return strings.Join(where, " AND "), args, nil
}
func finishPage[T any](items []T, ids []int64, limit int) Page[T] {
	p := Page[T]{Items: items}
	if p.Items == nil {
		p.Items = []T{}
	}
	if len(items) > limit {
		p.Items = items[:limit]
		p.Next = cursor(ids[limit-1])
	}
	return p
}
func (s *Store) Policies(f Filter) (Page[Policy], error) {
	rows, err := s.DB.Query("SELECT rowid,* FROM policies WHERE rowid>? ORDER BY rowid LIMIT ?", f.Cursor, f.Limit+1)
	if err != nil {
		return Page[Policy]{}, err
	}
	defer rows.Close()
	var items []Policy
	var ids []int64
	for rows.Next() {
		var id int64
		var p Policy
		if err = rows.Scan(&id, &p.ID, &p.Name, &p.Description, &p.Created); err != nil {
			return Page[Policy]{}, err
		}
		items = append(items, p)
		ids = append(ids, id)
	}
	return finishPage(items, ids, f.Limit), rows.Err()
}
func (s *Store) Versions(policy string, f Filter) (Page[Version], error) {
	where := "policy_id=?"
	args := []any{policy}
	if f.Cursor > 0 {
		where += " AND rowid<?"
		args = append(args, f.Cursor)
	}
	args = append(args, f.Limit+1)
	rows, err := s.DB.Query("SELECT rowid,* FROM versions WHERE "+where+" ORDER BY rowid DESC LIMIT ?", args...)
	if err != nil {
		return Page[Version]{}, err
	}
	defer rows.Close()
	var items []Version
	var ids []int64
	for rows.Next() {
		var id int64
		var v Version
		var rights string
		if err = rows.Scan(&id, &v.ID, &v.PolicyID, &v.Number, &v.ParentID, &v.State, &rights, &v.Digest, &v.Revision, &v.Actor, &v.Reason, &v.Created); err != nil {
			return Page[Version]{}, err
		}
		if err = json.Unmarshal([]byte(rights), &v.Rights); err != nil {
			return Page[Version]{}, err
		}
		items = append(items, v)
		ids = append(ids, id)
	}
	return finishPage(items, ids, f.Limit), rows.Err()
}

func (s *Store) Requests(f Filter, a Actor) (Page[PolicyRequest], error) {
	where, args, err := queryParts(f, map[string]string{"agent": "agent_id", "state": "state"}, "created")
	if err != nil {
		return Page[PolicyRequest]{}, err
	}
	if a.Kind == "agent" {
		where += " AND agent_id=?"
		args = append(args, a.Subject)
	}
	args = append(args, f.Limit+1)
	rows, err := s.DB.Query("SELECT rowid,* FROM requests WHERE "+where+" ORDER BY rowid LIMIT ?", args...)
	if err != nil {
		return Page[PolicyRequest]{}, err
	}
	defer rows.Close()
	var items []PolicyRequest
	var ids []int64
	for rows.Next() {
		var id int64
		var v PolicyRequest
		if err = rows.Scan(&id, &v.ID, &v.AgentID, &v.RequestedVersion, &v.ApprovedVersion, &v.State, &v.Reason, &v.DecisionReason, &v.DecidedBy, &v.Revision, &v.Created); err != nil {
			return Page[PolicyRequest]{}, err
		}
		items = append(items, v)
		ids = append(ids, id)
	}
	return finishPage(items, ids, f.Limit), rows.Err()
}
func scanAdmission(row rowScanner) (Admission, error) {
	var a Admission
	err := row.Scan(&a.ID, &a.RequestID, &a.AgentID, &a.RunID, &a.Node, &a.Boot, &a.Domain, &a.VersionID, &a.PolicyDigest, &a.Token, &a.GrantDigest, &a.State, &a.Created, &a.Expires)
	return a, err
}
func scanRun(row rowScanner) (Run, error) {
	var r Run
	var evidence string
	err := row.Scan(&r.ID, &r.AdmissionID, &r.AgentID, &r.VersionID, &r.PolicyDigest, &r.Verifier, &r.EvidenceDigest, &evidence, &r.Created)
	r.Evidence = json.RawMessage(evidence)
	return r, err
}
func (s *Store) Runs(f Filter, a Actor) (Page[Run], error) {
	where, args, err := queryParts(f, map[string]string{"agent": "agent_id", "version": "version_id", "verifier": "verifier"}, "created")
	if err != nil {
		return Page[Run]{}, err
	}
	if a.Kind == "agent" {
		where += " AND agent_id=?"
		args = append(args, a.Subject)
	}
	args = append(args, f.Limit+1)
	rows, err := s.DB.Query("SELECT rowid,id,admission_id,agent_id,version_id,policy_digest,verifier,evidence_digest,created FROM runs WHERE "+where+" ORDER BY rowid LIMIT ?", args...)
	if err != nil {
		return Page[Run]{}, err
	}
	defer rows.Close()
	var items []Run
	var ids []int64
	for rows.Next() {
		var id int64
		var r Run
		if err = rows.Scan(&id, &r.ID, &r.AdmissionID, &r.AgentID, &r.VersionID, &r.PolicyDigest, &r.Verifier, &r.EvidenceDigest, &r.Created); err != nil {
			return Page[Run]{}, err
		}
		items = append(items, r)
		ids = append(ids, id)
	}
	return finishPage(items, ids, f.Limit), rows.Err()
}
func (s *Store) Audit(f Filter) (Page[AuditEntry], error) {
	where, args, err := queryParts(f, map[string]string{"actor": "actor", "resource": "resource", "run": "run", "action": "action", "result": "result", "version": "version"})
	if err != nil {
		return Page[AuditEntry]{}, err
	}
	args = append(args, f.Limit+1)
	rows, err := s.DB.Query("SELECT * FROM audit WHERE "+where+" ORDER BY id LIMIT ?", args...)
	if err != nil {
		return Page[AuditEntry]{}, err
	}
	defer rows.Close()
	var items []AuditEntry
	var ids []int64
	for rows.Next() {
		var v AuditEntry
		var before, after string
		if err = rows.Scan(&v.ID, &v.Time, &v.Actor, &v.ActorKind, &v.Action, &v.Resource, &v.Version, &v.Run, &before, &after, &v.Reason, &v.RequestID, &v.CorrelationID, &v.Result); err != nil {
			return Page[AuditEntry]{}, err
		}
		v.Before = json.RawMessage(before)
		v.After = json.RawMessage(after)
		items = append(items, v)
		ids = append(ids, v.ID)
	}
	return finishPage(items, ids, f.Limit), rows.Err()
}
func (s *Store) Services(f Filter) (Page[Service], error) {
	rows, err := s.DB.Query("SELECT rowid,* FROM services WHERE rowid>? ORDER BY rowid LIMIT ?", f.Cursor, f.Limit+1)
	if err != nil {
		return Page[Service]{}, err
	}
	defer rows.Close()
	items := []Service{}
	ids := []int64{}
	for rows.Next() {
		var id int64
		var v Service
		var scopes string
		if err = rows.Scan(&id, &v.Subject, &v.Kind, &v.PublicKey, &scopes, &v.Node, &v.Enabled); err != nil {
			return Page[Service]{}, err
		}
		if err = json.Unmarshal([]byte(scopes), &v.Scopes); err != nil {
			return Page[Service]{}, err
		}
		items = append(items, v)
		ids = append(ids, id)
	}
	return finishPage(items, ids, f.Limit), rows.Err()
}
func (s *Store) Overview() (map[string]any, error) {
	out := map[string]any{}
	for name, query := range map[string]string{"policies": "SELECT COUNT(*) FROM policies", "pending_requests": "SELECT COUNT(*) FROM requests WHERE state='pending'", "runs": "SELECT COUNT(*) FROM runs", "incomplete_runs": "SELECT COUNT(*) FROM runs WHERE verifier!='VALID_COMPLETE'", "audit_entries": "SELECT COUNT(*) FROM audit"} {
		var n int
		if err := s.DB.QueryRow(query).Scan(&n); err != nil {
			return nil, err
		}
		out[name] = n
	}
	return out, nil
}
func notFound(err error) error {
	if err == sql.ErrNoRows {
		return fail(404, "not_found", "The resource does not exist.")
	}
	return err
}
