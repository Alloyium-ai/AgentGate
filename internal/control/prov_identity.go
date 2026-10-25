// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"database/sql"
	"regexp"
	"sort"
)

// Identity links record that several subjects (accounts) belong to one
// person, for example local:alice and the OIDC identity of the same person.
// They have exactly one use: a person never decides a launch requested by
// any of their linked subjects (DecideLaunch). They grant nothing, change no
// role and are not consulted anywhere else. Administrators manage them; each
// change is audited.

// identitySubject is a subject as the service writes it: local:<username> or
// oidc:<issuer subject> (visible ASCII).
var identitySubject = regexp.MustCompile(`^(local|oidc):[!-~]{1,255}$`)

// maxLinkedSubjects bounds one person's group.
const maxLinkedSubjects = 8

// rowsQueryer is a *sql.DB or *sql.Tx.
type rowsQueryer interface {
	QueryRow(string, ...any) *sql.Row
	Query(string, ...any) (*sql.Rows, error)
}

// IdentityLink is one person: the subjects linked as the same human.
type IdentityLink struct {
	Person   string   `json:"person"`
	Subjects []string `json:"subjects"`
	LinkedBy string   `json:"linked_by"`
	LinkedAt string   `json:"linked_at"`
}

// IdentityLinkInput links two or more subjects as one person.
type IdentityLinkInput struct {
	Subjects []string `json:"subjects"`
	Reason   string   `json:"reason"`
}

// IdentityUnlinkInput removes one subject from its person.
type IdentityUnlinkInput struct {
	Subject string `json:"subject"`
	Reason  string `json:"reason"`
}

// samePerson reports whether two subjects are one account or linked.
func samePerson(q queryer, a, b string) (bool, error) {
	if a == b {
		return true, nil
	}
	var n int
	err := q.QueryRow("SELECT count(*) FROM identity_links x JOIN identity_links y ON x.person=y.person WHERE x.subject=? AND y.subject=?", a, b).Scan(&n)
	return n > 0, err
}

// IdentityLinks lists every person with linked subjects.
func (s *Store) IdentityLinks() ([]IdentityLink, error) {
	rows, err := s.DB.Query("SELECT person,subject,linked_by,created FROM identity_links ORDER BY person,subject")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IdentityLink{}
	index := map[string]int{}
	for rows.Next() {
		var person, subject, by, at string
		if err = rows.Scan(&person, &subject, &by, &at); err != nil {
			return nil, err
		}
		i, ok := index[person]
		if !ok {
			i = len(out)
			index[person] = i
			out = append(out, IdentityLink{Person: person, Subjects: []string{}, LinkedBy: by, LinkedAt: at})
		}
		out[i].Subjects = append(out[i].Subjects, subject)
		if at > out[i].LinkedAt {
			out[i].LinkedBy, out[i].LinkedAt = by, at
		}
	}
	return out, rows.Err()
}

// identityLink is one person's group; no subject means no group.
func (s *Store) identityLink(q rowsQueryer, person string) (IdentityLink, error) {
	link := IdentityLink{Person: person, Subjects: []string{}}
	rows, err := q.Query("SELECT subject,linked_by,created FROM identity_links WHERE person=? ORDER BY subject", person)
	if err != nil {
		return link, err
	}
	defer rows.Close()
	for rows.Next() {
		var subject, by, at string
		if err = rows.Scan(&subject, &by, &at); err != nil {
			return link, err
		}
		link.Subjects = append(link.Subjects, subject)
		if at > link.LinkedAt {
			link.LinkedBy, link.LinkedAt = by, at
		}
	}
	return link, rows.Err()
}

// LinkIdentities records that the given subjects are one person. Subjects
// already linked elsewhere bring their whole group along (the groups merge),
// which only widens the self-approval refusal.
func (s *Store) LinkIdentities(op Operation, in IdentityLinkInput) (any, error) {
	op.Action, op.Resource, op.Reason = "identity.linked", "identity", safeReason(in.Reason)
	return s.Mutation(op, "identities:admin", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		if len(in.Subjects) < 2 || len(in.Subjects) > maxLinkedSubjects {
			return nil, fail(422, "invalid_identity_link", "Link 2 to 8 subjects.")
		}
		seen := map[string]bool{}
		for _, subject := range in.Subjects {
			if !identitySubject.MatchString(subject) {
				return nil, fail(422, "invalid_identity_link", "A subject is local:<username> or oidc:<issuer subject>.")
			}
			if seen[subject] {
				return nil, fail(422, "invalid_identity_link", "A subject is listed twice.")
			}
			seen[subject] = true
		}
		// The person: the existing groups of the subjects, merged.
		persons := map[string]bool{}
		for _, subject := range in.Subjects {
			var person string
			err := tx.QueryRow("SELECT person FROM identity_links WHERE subject=?", subject).Scan(&person)
			if err == nil {
				persons[person] = true
			} else if err != sql.ErrNoRows {
				return nil, err
			}
		}
		members := map[string]bool{}
		for _, subject := range in.Subjects {
			members[subject] = true
		}
		var existing []string
		for person := range persons {
			existing = append(existing, person)
			link, err := s.identityLink(tx, person)
			if err != nil {
				return nil, err
			}
			for _, subject := range link.Subjects {
				members[subject] = true
			}
		}
		sort.Strings(existing)
		if len(members) > maxLinkedSubjects {
			return nil, fail(422, "invalid_identity_link", "One person links at most 8 subjects.")
		}
		person := newID()
		if len(existing) > 0 {
			person = existing[0]
		}
		before := map[string]any{"persons": existing}
		now := stamp()
		for subject := range members {
			if _, err := tx.Exec("INSERT INTO identity_links(subject,person,linked_by,reason,created) VALUES(?,?,?,?,?) ON CONFLICT(subject) DO UPDATE SET person=excluded.person",
				subject, person, operation.Actor.Subject, in.Reason, now); err != nil {
				return nil, err
			}
		}
		link, err := s.identityLink(tx, person)
		if err != nil {
			return nil, err
		}
		operation.Resource, operation.Before, operation.After = "identity:"+person, before, map[string]any{"person": person, "subjects": link.Subjects}
		return link, nil
	})
}

// UnlinkIdentity removes one subject from its person; a person left with a
// single subject is removed too. An administrator never unlinks a group that
// holds their own subject: another administrator must, so nobody narrows the
// refusal that applies to themselves.
func (s *Store) UnlinkIdentity(op Operation, in IdentityUnlinkInput) (any, error) {
	op.Action, op.Resource, op.Reason = "identity.unlinked", "identity", safeReason(in.Reason)
	subject := in.Subject
	return s.Mutation(op, "identities:admin", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		if !identitySubject.MatchString(subject) {
			return nil, fail(422, "invalid_identity_link", "A subject is local:<username> or oidc:<issuer subject>.")
		}
		var person string
		if err := tx.QueryRow("SELECT person FROM identity_links WHERE subject=?", subject).Scan(&person); err == sql.ErrNoRows {
			return nil, fail(404, "not_found", "The subject is not linked.")
		} else if err != nil {
			return nil, err
		}
		link, err := s.identityLink(tx, person)
		if err != nil {
			return nil, err
		}
		for _, member := range link.Subjects {
			if member == operation.Actor.Subject {
				return nil, fail(403, "self_unlink", "You are one of the linked subjects; another administrator must unlink them.")
			}
		}
		if _, err = tx.Exec("DELETE FROM identity_links WHERE subject=?", subject); err != nil {
			return nil, err
		}
		if len(link.Subjects) <= 2 {
			if _, err = tx.Exec("DELETE FROM identity_links WHERE person=?", person); err != nil {
				return nil, err
			}
		}
		left, err := s.identityLink(tx, person)
		if err != nil {
			return nil, err
		}
		remaining := left.Subjects
		operation.Resource = "identity:" + person
		operation.Before, operation.After = map[string]any{"subjects": link.Subjects}, map[string]any{"unlinked": subject, "subjects": remaining}
		return map[string]any{"person": person, "unlinked": subject, "subjects": remaining}, nil
	})
}
