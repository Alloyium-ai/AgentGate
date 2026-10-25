// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"

	"alloyium.local/kernel-poc/internal/access"
	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/pocpolicy"
)

// Profile is a named, versioned access policy.
//
// RequireApproval false lets a launcher start a launch alone only when it
// uses exactly the version an administrator reviewed and approved for that:
// ApprovedVersion and ApprovedDigest (by ApprovedBy, at ApprovedAt). A launch
// of any other version, including a newer one an editor added, needs a second
// human. Only an administrator sets or clears the approved version
// (PATCH /profiles/{id}, audited as profile.approval.changed); creating a
// version never does.
type Profile struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	RequireApproval bool   `json:"require_approval"`
	ApprovedVersion int    `json:"approved_version,omitempty"`
	ApprovedDigest  string `json:"approved_digest,omitempty"`
	ApprovedBy      string `json:"approved_by,omitempty"`
	ApprovedAt      string `json:"approved_at,omitempty"`
	Created         string `json:"created_at"`
	CreatedBy       string `json:"created_by"`
	Revision        int    `json:"revision"`
	LatestVersion   int    `json:"latest_version"`
	approvedID      string
}

// ProfileVersion is one immutable, digest-addressed policy document.
type ProfileVersion struct {
	ID        string          `json:"id"`
	ProfileID string          `json:"profile_id"`
	Number    int             `json:"number"`
	ParentID  string          `json:"parent_id"`
	Document  json.RawMessage `json:"document"`
	Digest    string          `json:"digest"`
	Edits     json.RawMessage `json:"edits"`
	Actor     string          `json:"actor"`
	Reason    string          `json:"reason"`
	Created   string          `json:"created_at"`
}

// ProfileInput creates a profile from a preset, from a document, or from the
// full example when neither is given. RequireApproval defaults to true; only
// an administrator may set it to false.
type ProfileInput struct {
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Preset          string          `json:"preset"`
	Document        json.RawMessage `json:"document"`
	RequireApproval *bool           `json:"require_approval"`
	Reason          string          `json:"reason"`
}

// ProfileVersionInput adds a version whose parent must be the latest.
type ProfileVersionInput struct {
	ParentVersion int             `json:"parent_version"`
	Document      json.RawMessage `json:"document"`
	Reason        string          `json:"reason"`
}

// GrantInput applies typed edits to version n, which must be the latest.
// DryRun computes the same result without storing a version.
type GrantInput struct {
	Edits  []access.Edit `json:"edits"`
	Reason string        `json:"reason"`
	DryRun bool          `json:"dry_run,omitempty"`
}

// ProfileSettingsInput changes whether launches of a profile need approval.
// RequireApproval false approves exactly Version, whose digest the
// administrator reviewed and repeats in Digest; true clears the approval.
type ProfileSettingsInput struct {
	RequireApproval bool   `json:"require_approval"`
	Version         int    `json:"version,omitempty"`
	Digest          string `json:"digest,omitempty"`
	Reason          string `json:"reason"`
}

const maxProfileEdits = 16

var descriptionPattern = regexp.MustCompile(`^[^\x00-\x08\x0b-\x1f\x7f]{0,1000}$`)

func (s *Store) profileBy(q queryer, ref string) (Profile, error) {
	var p Profile
	scan := func(where string) error {
		return q.QueryRow("SELECT p.id,p.name,p.description,p.require_approval,p.created,p.created_by,p.revision,(SELECT coalesce(max(number),0) FROM profile_versions v WHERE v.profile_id=p.id),"+
			"p.approved_version_id,p.approved_digest,p.approved_by,p.approved_at,(SELECT coalesce(max(number),0) FROM profile_versions v WHERE v.id=p.approved_version_id AND v.profile_id=p.id) FROM profiles p WHERE "+where, ref).
			Scan(&p.ID, &p.Name, &p.Description, &p.RequireApproval, &p.Created, &p.CreatedBy, &p.Revision, &p.LatestVersion,
				&p.approvedID, &p.ApprovedDigest, &p.ApprovedBy, &p.ApprovedAt, &p.ApprovedVersion)
	}
	err := scan("p.id=?")
	if errors.Is(err, sql.ErrNoRows) {
		err = scan("p.name=?")
	}
	if errors.Is(err, sql.ErrNoRows) {
		return p, fail(404, "not_found", "The profile does not exist.")
	}
	return p, err
}

func profileVersionFrom(q queryer, profileID string, number int) (ProfileVersion, error) {
	var v ProfileVersion
	var doc, edits string
	err := q.QueryRow("SELECT id,profile_id,number,parent_id,document,digest,edits,actor,reason,created FROM profile_versions WHERE profile_id=? AND number=?", profileID, number).
		Scan(&v.ID, &v.ProfileID, &v.Number, &v.ParentID, &doc, &v.Digest, &edits, &v.Actor, &v.Reason, &v.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return v, fail(404, "not_found", "The profile version does not exist.")
	}
	v.Document, v.Edits = json.RawMessage(doc), json.RawMessage(edits)
	return v, err
}

// document re-validates a stored version and checks its digest, so a corrupt
// row never reaches a launch.
func (v ProfileVersion) document() (pocpolicy.Document, error) {
	d, err := pocpolicy.Parse(v.Document)
	if err != nil || d.Digest() != v.Digest {
		return d, fail(503, "profile_corrupt", "The stored profile version fails validation.")
	}
	return d, nil
}

// Profiles lists profiles.
func (s *Store) Profiles() ([]Profile, error) {
	rows, err := s.DB.Query("SELECT id FROM profiles ORDER BY name LIMIT 500")
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	out := []Profile{}
	for _, id := range ids {
		p, err := s.profileBy(s.DB, id)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// ProfileDetail returns one profile.
func (s *Store) ProfileDetail(ref string) (Profile, error) { return s.profileBy(s.DB, ref) }

// ProfileVersions lists the versions of a profile, newest first.
func (s *Store) ProfileVersions(ref string) ([]ProfileVersion, error) {
	p, err := s.profileBy(s.DB, ref)
	if err != nil {
		return nil, err
	}
	out := []ProfileVersion{}
	for n := p.LatestVersion; n >= 1 && len(out) < 200; n-- {
		v, err := profileVersionFrom(s.DB, p.ID, n)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// ProfileVersionDetail returns one version by number.
func (s *Store) ProfileVersionDetail(ref, number string) (ProfileVersion, error) {
	p, err := s.profileBy(s.DB, ref)
	if err != nil {
		return ProfileVersion{}, err
	}
	n, err := strconv.Atoi(number)
	if err != nil || n < 1 {
		return ProfileVersion{}, fail(404, "not_found", "The profile version does not exist.")
	}
	return profileVersionFrom(s.DB, p.ID, n)
}

func parseProfileDocument(raw json.RawMessage) (pocpolicy.Document, error) {
	d, err := pocpolicy.Parse(raw)
	if err != nil {
		return d, fail(422, "invalid_policy", "The policy document is invalid: "+err.Error())
	}
	return d, nil
}

func insertProfileVersion(tx *sql.Tx, p Profile, parentID string, d pocpolicy.Document, edits any, actor, reason string) (ProfileVersion, error) {
	raw, err := json.Marshal(d)
	if err != nil {
		return ProfileVersion{}, err
	}
	if edits == nil {
		edits = []access.Edit{}
	}
	v := ProfileVersion{ID: newID(), ProfileID: p.ID, Number: p.LatestVersion + 1, ParentID: parentID, Document: raw, Digest: d.Digest(), Edits: json.RawMessage(jsonText(edits)), Actor: actor, Reason: reason, Created: stamp()}
	if digest(raw) != v.Digest {
		return v, errors.New("profile digest differs from its canonical bytes")
	}
	_, err = tx.Exec("INSERT INTO profile_versions VALUES(?,?,?,?,?,?,?,?,?,?)", v.ID, v.ProfileID, v.Number, v.ParentID, string(raw), v.Digest, string(v.Edits), v.Actor, v.Reason, v.Created)
	return v, err
}

// CreateProfile creates a profile and its first version.
func (s *Store) CreateProfile(op Operation, in ProfileInput) (any, error) {
	op.Action, op.Resource, op.Reason = "profile.created", "profile", safeReason(in.Reason)
	// Only an administrator may create a profile that skips approval: the
	// default for a new profile is that launches need a second human.
	scope := "policy:write"
	return s.Mutation(op, scope, true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		if !hostproto.NamePattern.MatchString(in.Name) || !descriptionPattern.MatchString(in.Description) {
			return nil, fail(422, "invalid_profile", "A profile name matches ^[a-z0-9][a-z0-9-]{0,39}$ and a description is at most 1000 characters.")
		}
		requireApproval := in.RequireApproval == nil || *in.RequireApproval
		if !requireApproval && !operation.Actor.Can("profiles:admin") {
			return nil, fail(403, "approval_policy_forbidden", "Only an administrator creates a profile whose launches skip approval.")
		}
		var d pocpolicy.Document
		var err error
		switch {
		case in.Preset != "" && len(in.Document) > 0:
			return nil, fail(422, "invalid_profile", "Choose a preset or a document, not both.")
		case in.Preset != "":
			d, err = access.NewFromPreset(in.Preset)
			if err != nil {
				return nil, fail(422, "unknown_preset", err.Error())
			}
		case len(in.Document) > 0:
			if d, err = parseProfileDocument(in.Document); err != nil {
				return nil, err
			}
		default:
			if d, err = access.FullExample(); err != nil {
				return nil, err
			}
		}
		var count int
		if err = tx.QueryRow("SELECT count(*) FROM profiles").Scan(&count); err != nil {
			return nil, err
		}
		if count >= 1000 {
			return nil, fail(409, "profile_limit", "The profile limit is reached.")
		}
		p := Profile{ID: newID(), Name: in.Name, Description: in.Description, RequireApproval: requireApproval, Created: stamp(), CreatedBy: operation.Actor.Subject, Revision: 1}
		if _, err = tx.Exec("INSERT INTO profiles(id,name,description,require_approval,created,created_by,revision) VALUES(?,?,?,?,?,?,1)", p.ID, p.Name, p.Description, p.RequireApproval, p.Created, p.CreatedBy); err != nil {
			return nil, fail(409, "profile_exists", "A profile already uses this name.")
		}
		edits := []access.Edit{}
		if in.Preset != "" {
			edits = append(edits, access.Edit{Action: access.ActionPreset, Values: []string{in.Preset}})
		}
		v, err := insertProfileVersion(tx, p, "", d, edits, operation.Actor.Subject, in.Reason)
		if err != nil {
			return nil, err
		}
		p.LatestVersion = 1
		operation.Resource, operation.Version = "profile:"+p.ID, v.ID
		if !requireApproval {
			// The administrator creating a profile that skips approval reviewed
			// exactly this first version: it is the approved one, audited here.
			if err = approveProfileVersion(tx, p.ID, v, operation.Actor.Subject); err != nil {
				return nil, err
			}
			operation.After = map[string]any{"approved_version": 1, "approved_digest": v.Digest}
		}
		p, err = s.profileBy(tx, p.ID)
		if err != nil {
			return nil, err
		}
		return map[string]any{"profile": p, "version": v}, nil
	})
}

// SetProfileApproval changes whether launches of a profile need approval.
// Administrators only: relaxing it lets launchers start agents alone, and
// only with the one version the administrator names and reviewed (Version,
// whose digest must equal Digest). Requiring approval clears it.
func (s *Store) SetProfileApproval(op Operation, ref string, in ProfileSettingsInput) (any, error) {
	op.Action, op.Resource, op.Reason = "profile.approval.changed", "profile:"+ref, safeReason(in.Reason)
	return s.Mutation(op, "profiles:admin", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		p, err := s.profileBy(tx, ref)
		if err != nil {
			return nil, err
		}
		operation.Resource = "profile:" + p.ID
		operation.Before = map[string]any{"require_approval": p.RequireApproval, "approved_version": p.ApprovedVersion, "approved_digest": p.ApprovedDigest}
		if in.RequireApproval {
			if in.Version != 0 || in.Digest != "" {
				return nil, fail(422, "invalid_profile", "Requiring approval approves no version; omit version and digest.")
			}
			if _, err = tx.Exec("UPDATE profiles SET require_approval=1,approved_version_id='',approved_digest='',approved_by='',approved_at='',revision=revision+1 WHERE id=?", p.ID); err != nil {
				return nil, err
			}
			return s.profileBy(tx, p.ID)
		}
		if in.Version < 1 || !digestPattern.MatchString(in.Digest) {
			return nil, fail(422, "approved_version_required", "Letting launchers start alone approves one reviewed version: give its number as version and its SHA-256 as digest.")
		}
		v, err := profileVersionFrom(tx, p.ID, in.Version)
		if err != nil {
			return nil, err
		}
		if _, err = v.document(); err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare([]byte(v.Digest), []byte(in.Digest)) != 1 {
			return nil, fail(409, "digest_mismatch", "Version "+itoa(v.Number)+" has digest "+v.Digest+", not the one you reviewed. Review the version again.")
		}
		if _, err = tx.Exec("UPDATE profiles SET require_approval=0,revision=revision+1 WHERE id=?", p.ID); err != nil {
			return nil, err
		}
		if err = approveProfileVersion(tx, p.ID, v, operation.Actor.Subject); err != nil {
			return nil, err
		}
		operation.Version = v.ID
		return s.profileBy(tx, p.ID)
	})
}

// approveProfileVersion records v as the version launches may use without a
// second human. Callers are administrator mutations, which audit it.
func approveProfileVersion(tx *sql.Tx, profileID string, v ProfileVersion, admin string) error {
	_, err := tx.Exec("UPDATE profiles SET approved_version_id=?,approved_digest=?,approved_by=?,approved_at=? WHERE id=?", v.ID, v.Digest, admin, stamp(), profileID)
	return err
}

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// CreateProfileVersion stores a new document as the next version.
func (s *Store) CreateProfileVersion(op Operation, ref string, in ProfileVersionInput) (any, error) {
	op.Action, op.Resource, op.Reason = "profile.version.created", "profile:"+ref, safeReason(in.Reason)
	return s.Mutation(op, "policy:write", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		p, err := s.profileBy(tx, ref)
		if err != nil {
			return nil, err
		}
		if in.ParentVersion != p.LatestVersion {
			return nil, fail(409, "stale_parent", "Read the latest profile version before adding one.")
		}
		parent, err := profileVersionFrom(tx, p.ID, p.LatestVersion)
		if err != nil {
			return nil, err
		}
		d, err := parseProfileDocument(in.Document)
		if err != nil {
			return nil, err
		}
		if parent.Version() == pocpolicy.VersionV2 && d.Version != pocpolicy.VersionV2 {
			return nil, fail(422, "version_downgrade", "A version two profile cannot return to version one.")
		}
		v, err := insertProfileVersion(tx, p, parent.ID, d, []access.Edit{}, operation.Actor.Subject, in.Reason)
		operation.Resource, operation.Version = "profile:"+p.ID, v.ID
		operation.Before = map[string]any{"version": parent.Number, "digest": parent.Digest}
		return v, err
	})
}

// Version returns the stored document's version string.
func (v ProfileVersion) Version() string {
	var head struct {
		Version string `json:"version"`
	}
	json.Unmarshal(v.Document, &head)
	return head.Version
}

// ApplyGrants applies typed edits to version n and stores the result as the
// next version. An edit sequence that changes nothing creates no version. A
// dry run runs exactly the same checks and engine, stores nothing, and is
// audited as profile.grant.previewed. Both answers carry the parent and
// result digests and the structured change list.
func (s *Store) ApplyGrants(op Operation, ref, number string, in GrantInput) (any, error) {
	op.Action, op.Resource, op.Reason = "profile.grants.applied", "profile:"+ref, safeReason(in.Reason)
	if in.DryRun {
		op.Action = "profile.grant.previewed"
	}
	return s.Mutation(op, "policy:write", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		if len(in.Edits) < 1 || len(in.Edits) > maxProfileEdits {
			return nil, fail(422, "invalid_edits", "Supply 1 to 16 edits.")
		}
		p, err := s.profileBy(tx, ref)
		if err != nil {
			return nil, err
		}
		n, err := strconv.Atoi(number)
		if err != nil || n != p.LatestVersion {
			return nil, fail(409, "stale_parent", "Grants apply to the latest profile version only.")
		}
		parent, err := profileVersionFrom(tx, p.ID, n)
		if err != nil {
			return nil, err
		}
		d, err := parent.document()
		if err != nil {
			return nil, err
		}
		before := d
		messages, notices := []string{}, []string{}
		for _, edit := range in.Edits {
			r, err := access.Apply(d, edit)
			if err != nil {
				var e *access.Error
				if errors.As(err, &e) {
					status := map[string]int{access.CodeUsage: 422, access.CodeConflict: 409, access.CodeUpgrade: 422, access.CodeRejected: 422}[e.Code]
					return nil, fail(status, "grant_"+e.Code, e.Message)
				}
				return nil, err
			}
			d = r.Document
			messages = append(messages, r.Message)
			notices = append(notices, r.Notices...)
		}
		operation.Resource = "profile:" + p.ID
		operation.Before = map[string]any{"version": parent.Number, "digest": parent.Digest}
		changed := d.Digest() != parent.Digest
		out := map[string]any{"changed": changed, "from_version": parent.Number, "from_digest": parent.Digest, "digest": d.Digest(),
			"changes": PolicyChanges(&before, d), "messages": messages, "notices": notices}
		if in.DryRun {
			out["dry_run"], out["document"] = true, d
			return out, nil
		}
		if !changed {
			out["version"] = parent
			return out, nil
		}
		v, err := insertProfileVersion(tx, p, parent.ID, d, in.Edits, operation.Actor.Subject, in.Reason)
		if err != nil {
			return nil, err
		}
		operation.Version = v.ID
		out["version"] = v
		return out, nil
	})
}
