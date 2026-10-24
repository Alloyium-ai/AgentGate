// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// Secret is secret metadata. The service never sees a value: a client seals
// the value to the target host's X25519 key (hostproto.SealSecret) and the
// service relays the ciphertext in a secret-put job, then deletes it. Only
// the SHA-256 fingerprint of the ciphertext is kept.
type Secret struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	TargetID    string   `json:"target_id"`
	Upstreams   []string `json:"upstreams"`
	Header      string   `json:"header"`
	Fingerprint string   `json:"ciphertext_sha256"`
	// AllowedProfiles names the profiles whose launches may reference this
	// secret; AllowedLaunchers names the human subjects who may request them.
	AllowedProfiles  []string `json:"allowed_profiles"`
	AllowedLaunchers []string `json:"allowed_launchers"`
	State            string   `json:"state"`
	Created          string   `json:"created_at"`
	CreatedBy        string   `json:"created_by"`
	Updated          string   `json:"updated_at"`
	Revision         int      `json:"revision"`
}

// SecretInput stores a sealed secret on one target.
type SecretInput struct {
	Name       string   `json:"name"`
	Target     string   `json:"target"`
	Upstreams  []string `json:"upstreams"`
	Header     string   `json:"header"`
	Ciphertext string   `json:"ciphertext"`
	// AllowedProfiles and AllowedLaunchers scope who may use the secret: 1 to
	// 32 profile names and 1 to 64 human subjects (for example local:alice).
	AllowedProfiles  []string `json:"allowed_profiles"`
	AllowedLaunchers []string `json:"allowed_launchers"`
	Reason           string   `json:"reason"`
}

const secretColumns = "id,name,target_id,upstreams,header,fingerprint,allowed_profiles,allowed_launchers,state,created,created_by,updated,revision"
const secretJobLifetime = time.Hour

func scanSecret(row rowScanner) (Secret, error) {
	var sec Secret
	var upstreams, profiles, launchers string
	err := row.Scan(&sec.ID, &sec.Name, &sec.TargetID, &upstreams, &sec.Header, &sec.Fingerprint, &profiles, &launchers, &sec.State, &sec.Created, &sec.CreatedBy, &sec.Updated, &sec.Revision)
	if err == nil {
		err = errors.Join(json.Unmarshal([]byte(upstreams), &sec.Upstreams), json.Unmarshal([]byte(profiles), &sec.AllowedProfiles), json.Unmarshal([]byte(launchers), &sec.AllowedLaunchers))
	}
	return sec, err
}

// Secrets lists secret metadata.
func (s *Store) Secrets() ([]Secret, error) {
	rows, err := s.DB.Query("SELECT " + secretColumns + " FROM secrets ORDER BY created DESC LIMIT 500")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Secret{}
	for rows.Next() {
		sec, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sec)
	}
	return out, rows.Err()
}

// CreateSecret records metadata and queues the sealed value for the host.
func (s *Store) CreateSecret(op Operation, in SecretInput) (any, error) {
	op.Action, op.Resource, op.Reason = "secret.created", "secret", safeReason(in.Reason)
	// The response holds no ciphertext, but a replayed body would; never
	// cache it.
	op.Idempotency = ""
	return s.Mutation(op, "secrets:admin", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		if !hostproto.NamePattern.MatchString(in.Name) || !hostproto.HeaderPattern.MatchString(in.Header) {
			return nil, fail(422, "invalid_secret", "A secret needs a name matching ^[a-z0-9][a-z0-9-]{0,39}$ and an HTTP header name.")
		}
		if len(in.Upstreams) < 1 || len(in.Upstreams) > 8 {
			return nil, fail(422, "invalid_secret", "A secret needs 1 to 8 exact upstream host names.")
		}
		seen := map[string]bool{}
		for _, u := range in.Upstreams {
			if len(u) > 253 || !hostproto.UpstreamPattern.MatchString(u) || seen[u] {
				return nil, fail(422, "invalid_secret", "Each upstream is a unique lowercase DNS host name, optionally with a port.")
			}
			seen[u] = true
		}
		if err := checkScope(in.AllowedProfiles, 32, func(v string) bool { return hostproto.NamePattern.MatchString(v) }); err != nil {
			return nil, fail(422, "invalid_secret", "allowed_profiles needs 1 to 32 unique profile names.")
		}
		if err := checkScope(in.AllowedLaunchers, 64, func(v string) bool { return safeMeta.MatchString(v) }); err != nil {
			return nil, fail(422, "invalid_secret", "allowed_launchers needs 1 to 64 unique human subjects.")
		}
		sealed, err := hostproto.DecodeSealed(in.Ciphertext)
		if err != nil {
			return nil, fail(422, "invalid_ciphertext", "Seal the value to the target's encryption key with the hostproto secret format.")
		}
		target, err := s.targetBy(tx, in.Target)
		if err != nil {
			return nil, err
		}
		if target.State != "active" {
			return nil, fail(409, "target_unavailable", "The target is not enrolled and active.")
		}
		sec := Secret{ID: newID(), Name: in.Name, TargetID: target.ID, Upstreams: in.Upstreams, Header: in.Header, Fingerprint: hostproto.SHA256Hex(sealed), AllowedProfiles: in.AllowedProfiles, AllowedLaunchers: in.AllowedLaunchers, State: "pending", Created: stamp(), CreatedBy: operation.Actor.Subject, Revision: 1}
		sec.Updated = sec.Created
		if _, err = tx.Exec("INSERT INTO secrets VALUES(?,?,?,?,?,?,?,?,'pending',?,?,?,1)", sec.ID, sec.Name, sec.TargetID, jsonText(sec.Upstreams), sec.Header, sec.Fingerprint, jsonText(sec.AllowedProfiles), jsonText(sec.AllowedLaunchers), sec.Created, sec.CreatedBy, sec.Updated); err != nil {
			return nil, fail(409, "secret_exists", "The target already holds a secret with this name; delete it first.")
		}
		payload := hostproto.SecretPutPayload{SecretID: sec.ID, Name: sec.Name, Upstreams: sec.Upstreams, Header: sec.Header, Ciphertext: hostproto.EncodeSealed(sealed), CiphertextSHA256: sec.Fingerprint}
		if _, err = s.enqueueJob(tx, jobSpec{Type: hostproto.JobSecretPut, TargetID: target.ID, SecretID: sec.ID, Payload: payload, Deadline: s.now().Add(secretJobLifetime), Reason: "Deliver a sealed secret to its host", Actor: operation.Actor}, operation); err != nil {
			return nil, err
		}
		operation.Resource = "secret:" + sec.ID
		return sec, nil
	})
}

// DeleteSecret queues removal of the value from the host. The metadata
// moves to deleted when the host confirms.
func (s *Store) DeleteSecret(op Operation, id string, in ReasonInput) (any, error) {
	op.Action, op.Resource, op.Reason = "secret.deletion.requested", "secret:"+id, safeReason(in.Reason)
	return s.Mutation(op, "secrets:admin", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		sec, err := scanSecret(tx.QueryRow("SELECT "+secretColumns+" FROM secrets WHERE id=?", id))
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fail(404, "not_found", "The secret does not exist.")
		}
		if err != nil {
			return nil, err
		}
		switch sec.State {
		case "deleting", "deleted":
			return sec, nil
		case "failed":
			if _, err = tx.Exec("UPDATE secrets SET state='deleted',updated=?,revision=revision+1 WHERE id=?", stamp(), id); err != nil {
				return nil, err
			}
			return scanSecret(tx.QueryRow("SELECT "+secretColumns+" FROM secrets WHERE id=?", id))
		}
		var users int
		if err = tx.QueryRow("SELECT count(*) FROM launches WHERE state NOT IN ('stopped','expired','failed','rejected','cancelled') AND target_id=? AND EXISTS (SELECT 1 FROM json_each(json_extract(launches.plan,'$.secrets')) WHERE json_extract(value,'$.secret_id')=?)", sec.TargetID, sec.ID).Scan(&users); err != nil {
			return nil, err
		}
		if users > 0 {
			return nil, fail(409, "secret_in_use", "Stop the launches that use this secret first.")
		}
		if _, err = tx.Exec("UPDATE jobs SET state='cancelled',envelope='',completed=?,revision=revision+1 WHERE secret_id=? AND type='secret-put' AND state='queued'", stamp(), id); err != nil {
			return nil, err
		}
		if _, err = tx.Exec("UPDATE secrets SET state='deleting',updated=?,revision=revision+1 WHERE id=?", stamp(), id); err != nil {
			return nil, err
		}
		if _, err = s.enqueueJob(tx, jobSpec{Type: hostproto.JobSecretDelete, TargetID: sec.TargetID, SecretID: sec.ID, Payload: hostproto.SecretDeletePayload{SecretID: sec.ID, Name: sec.Name}, Deadline: s.now().Add(stopJobLifetime), Reason: "Remove a secret value from its host", Actor: operation.Actor}, operation); err != nil {
			return nil, err
		}
		return scanSecret(tx.QueryRow("SELECT "+secretColumns+" FROM secrets WHERE id=?", id))
	})
}

func checkScope(values []string, max int, valid func(string) bool) error {
	if len(values) < 1 || len(values) > max {
		return errors.New("scope size")
	}
	seen := map[string]bool{}
	for _, v := range values {
		if !valid(v) || seen[v] {
			return errors.New("scope value")
		}
		seen[v] = true
	}
	return nil
}
