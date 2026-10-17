// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

func (s *Store) admissionVisible(a Admission, actor Actor) error {
	if actor.Kind == "agent" && a.AgentID != actor.Subject {
		return fail(403, "forbidden", "The admission belongs to another agent.")
	}
	if actor.Kind == "service" {
		svc, err := serviceFrom(s.DB, actor.Subject)
		if err != nil || svc.Node != a.Node {
			return fail(403, "forbidden", "The admission belongs to another node.")
		}
	}
	return nil
}
func (s *Store) AdmissionDetail(id string, actor Actor) (Admission, error) {
	a, err := scanAdmission(s.DB.QueryRow("SELECT * FROM admissions WHERE id=?", id))
	if err != nil {
		return a, notFound(err)
	}
	if err = s.admissionVisible(a, actor); err != nil {
		return Admission{}, err
	}
	a.Token = ""
	return a, nil
}
func (s *Store) Admissions(f Filter, actor Actor) (Page[Admission], error) {
	where, args, err := queryParts(f, map[string]string{"agent": "agent_id", "state": "state", "version": "version_id"}, "created")
	if err != nil {
		return Page[Admission]{}, err
	}
	if actor.Kind == "agent" {
		where += " AND agent_id=?"
		args = append(args, actor.Subject)
	}
	if actor.Kind == "service" {
		svc, err := serviceFrom(s.DB, actor.Subject)
		if err != nil {
			return Page[Admission]{}, err
		}
		where += " AND node=?"
		args = append(args, svc.Node)
	}
	args = append(args, f.Limit+1)
	rows, err := s.DB.Query("SELECT rowid,* FROM admissions WHERE "+where+" ORDER BY rowid LIMIT ?", args...)
	if err != nil {
		return Page[Admission]{}, err
	}
	defer rows.Close()
	var items []Admission
	var ids []int64
	for rows.Next() {
		var id int64
		var a Admission
		if err = rows.Scan(&id, &a.ID, &a.RequestID, &a.AgentID, &a.RunID, &a.Node, &a.Boot, &a.Domain, &a.VersionID, &a.PolicyDigest, &a.Token, &a.GrantDigest, &a.State, &a.Created, &a.Expires); err != nil {
			return Page[Admission]{}, err
		}
		a.Token = ""
		items = append(items, a)
		ids = append(ids, id)
	}
	return finishPage(items, ids, f.Limit), rows.Err()
}
