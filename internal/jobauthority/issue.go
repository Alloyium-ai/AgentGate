// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"alloyium.local/kernel-poc/internal/policy"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"reflect"
	"time"
)

type knownGrant struct{}

func (knownGrant) State(context.Context, string) (jobgrant.RevocationState, error) {
	return jobgrant.RevocationState{Known: true}, nil
}

type fixedClock struct {
	wall time.Time
	mono uint64
}

func (c fixedClock) Now() (time.Time, uint64, error) { return c.wall, c.mono, nil }
func (s *Server) issue(w http.ResponseWriter, r *http.Request, subject string, body []byte) {
	var q IssueRequest
	if lifecycle.DecodeTransport(bytes.NewReader(body), &q) != nil || q.Protocol != IssueProtocol {
		problem(w, 422, "authority_issue_invalid")
		return
	}
	b := q.Prepared.Binding
	p := s.config.Subjects[subject]
	if b.AgentID != subject || b.AgentKey != base64.RawURLEncoding.EncodeToString(p.Key) || b.Validate(false) != nil {
		problem(w, 403, "authority_binding_rejected")
		return
	}
	doc, e := s.approved(r.Context(), b.PolicyDigest, q.Document)
	if e != nil {
		problem(w, 403, "authority_document_unapproved")
		return
	}
	manifest, e := q.Manifest.Digest()
	if e != nil || manifest != b.JobDigest || manifest != q.Prepared.ManifestDigest || s.config.Enrollment.VerifyEnrollment(r.Context(), b) != nil || s.config.Enrollment.VerifyManifest(r.Context(), b, q.Manifest) != nil {
		problem(w, 403, "authority_enrollment_rejected")
		return
	}
	required, e := policy.Requirements(doc)
	if e != nil {
		problem(w, 422, "authority_document_invalid")
		return
	}
	nodeTime, e := s.config.Preparations.Verify(r.Context(), q.Prepared)
	wall, _, clockErr := s.config.Clock.Now()
	if e != nil || clockErr != nil || !validPrepared(q.Prepared, required, nodeTime, wall) {
		problem(w, 403, "authority_preparation_rejected")
		return
	}
	var header jobaudit.Header
	if lifecycle.DecodeTransport(bytes.NewReader(q.Prepared.AuditHeader), &header) != nil {
		problem(w, 422, "authority_audit_header_invalid")
		return
	}
	raw, e := jobaudit.HeaderBytes(header)
	hd, he := jobaudit.HeaderDigest(header)
	if e != nil || he != nil || !bytes.Equal(raw, q.Prepared.AuditHeader) || hd != q.Prepared.AuditHeaderDigest || !reflect.DeepEqual(header.Binding, b) || header.DocumentDigest != b.PolicyDigest || !reflect.DeepEqual(header.RequiredCapabilities, required) || header.CreatedMonoNS > nodeTime.MonoNS {
		problem(w, 403, "authority_audit_header_rejected")
		return
	}
	if !s.validStreams(header) {
		problem(w, 403, "authority_audit_streams_rejected")
		return
	}
	snapshot, e := s.config.Qualification.Current(r.Context(), b)
	if e != nil {
		problem(w, 503, "authority_qualification_unavailable")
		return
	}
	qualification, e := jobgrant.QualificationDigest(snapshot)
	if e != nil || qualification != header.QualificationDigest {
		problem(w, 403, "authority_qualification_rejected")
		return
	}
	remaining := b.DeadlineNS - nodeTime.MonoNS
	if remaining > uint64(s.config.MaxLifetime) || remaining < uint64(time.Second) {
		problem(w, 403, "authority_lifetime_rejected")
		return
	}
	expires := nodeTime.Wall.Unix() + int64(remaining/uint64(time.Second))
	if expires <= wall.Unix() {
		problem(w, 403, "authority_lifetime_rejected")
		return
	}
	claims := jobgrant.Claims{Binding: b, DocumentDigest: b.PolicyDigest, RequiredCapabilities: required, QualificationDigest: qualification, AuditHeaderDigest: hd, IssuedAt: wall.Unix(), NotBefore: wall.Unix(), ExpiresAt: expires, IssuedMonoNS: nodeTime.MonoNS, DeadlineNS: b.DeadlineNS}
	envelope, e := jobgrant.Sign(s.config.AuthorityID, s.config.KeyID, s.config.SigningKey, claims, doc)
	if e != nil {
		problem(w, 403, "authority_claims_rejected")
		return
	}
	grant, e := jobgrant.Encode(envelope)
	canonical, ce := doc.Canonical()
	if e != nil || ce != nil {
		problem(w, 503, "authority_encoding_failed")
		return
	}
	a := lifecycle.Authorization{Binding: b, Grant: grant, Document: canonical, RequiredCapabilities: required}
	verifier, e := jobgrant.NewVerifier(jobgrant.Config{Authorities: s.authorityKeys(), Enrollment: s.config.Enrollment, Qualification: s.config.Qualification, Revocation: knownGrant{}, Clock: fixedClock{wall, nodeTime.MonoNS}, MaxLifetime: s.config.MaxLifetime})
	if e != nil || verifier.Verify(r.Context(), a) != nil {
		problem(w, 403, "authority_current_trust_rejected")
		return
	}
	if s.config.Store.SaveGrant(r.Context(), a) != nil {
		problem(w, 409, "authority_grant_conflict_or_store_unavailable")
		return
	}
	response(w, IssueResponse{IssuedProtocol, a})
}
func (s *Server) authorityKeys() map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{s.config.AuthorityID + "/" + s.config.KeyID: s.config.SigningKey.Public().(ed25519.PublicKey)}
}
func (s *Server) approved(ctx context.Context, digest string, request policy.Document) (policy.Document, error) {
	d, e := s.config.Documents.Resolve(ctx, digest)
	if e != nil {
		return d, e
	}
	a, e := d.Canonical()
	if e != nil {
		return d, e
	}
	b, e := request.Canonical()
	if e != nil {
		return d, e
	}
	actual, e := d.Digest()
	if e != nil {
		return d, e
	}
	if actual != digest || !bytes.Equal(a, b) {
		return d, ErrConflict
	}
	return d, nil
}
func validPrepared(p lifecycle.PrepareResponse, required []string, n NodeTime, wall time.Time) bool {
	if p.Protocol != lifecycle.PreparedProtocol || n.MonoNS == 0 || n.Wall.Unix() < wall.Unix()-15 || n.Wall.Unix() > wall.Unix()+5 || n.MonoNS >= p.PreparationDeadlineNS || p.PreparationDeadlineNS > p.Binding.DeadlineNS || lifecycle.VerifyReadback(p.Evidence, p.Binding, "quarantined") != nil || lifecycle.RequireCapabilities(p.Evidence, required) != nil {
		return false
	}
	e := p.Evidence
	return !e.Terminated && e.Empty && e.Process == nil
}

func (s *Server) validStreams(h jobaudit.Header) bool {
	if len(h.RequiredStreams) != 7 {
		return false
	}
	registry := s.config.Registry(h.Binding)
	control := false
	for _, stream := range h.RequiredStreams {
		if stream.ArtifactDigest != h.Binding.ArtifactDigests[stream.Name] || registry[stream.Name+"/"+stream.Version] == nil {
			return false
		}
		if stream.Kind == "control" {
			if stream.Name != nodecontrol.Stream || stream.Version != nodecontrol.Version {
				return false
			}
			control = true
		}
	}
	return control
}
