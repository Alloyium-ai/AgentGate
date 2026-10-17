// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobgrant

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"time"
)

type grantStopError struct{ cause lifecycle.StopCause }

func (e grantStopError) Error() string {
	if e.cause == lifecycle.GrantExpired {
		return "the full grant is expired"
	}
	return "the full grant is revoked"
}
func (e grantStopError) LifecycleStopReason() lifecycle.StopCause { return e.cause }

func NewVerifier(c Config) (*Verifier, error) {
	if len(c.Authorities) == 0 || c.Enrollment == nil || c.Qualification == nil || c.Revocation == nil || c.Clock == nil || c.MaxLifetime <= 0 || c.MaxLifetime > 24*time.Hour {
		return nil, errors.New("full grant trust and current verification dependencies are required")
	}
	keys := map[string]ed25519.PublicKey{}
	for id, key := range c.Authorities {
		if len(key) != ed25519.PublicKeySize {
			return nil, errors.New("a pinned full grant key is invalid")
		}
		keys[id] = append(ed25519.PublicKey{}, key...)
	}
	c.Authorities = keys
	return &Verifier{config: c}, nil
}
func (v *Verifier) Verify(ctx context.Context, a lifecycle.Authorization) error {
	d, err := policy.Parse(a.Document, "json")
	if err != nil {
		return err
	}
	c, err := v.verifySignedAuthorization(a.Grant, d)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(c.Binding, a.Binding) || !reflect.DeepEqual(c.RequiredCapabilities, a.RequiredCapabilities) {
		return errors.New("the authorization differs from the full grant")
	}
	now, mono, err := v.config.Clock.Now()
	if err != nil || mono < c.IssuedMonoNS || now.Unix() < c.NotBefore || time.Duration(c.ExpiresAt-c.IssuedAt)*time.Second > v.config.MaxLifetime || c.DeadlineNS-c.IssuedMonoNS > uint64(v.config.MaxLifetime) {
		return errors.New("the full grant clock or lifetime is unavailable")
	}
	if mono >= c.DeadlineNS || now.Unix() >= c.ExpiresAt {
		return grantStopError{lifecycle.GrantExpired}
	}
	if err = v.config.Enrollment.VerifyEnrollment(ctx, c.Binding); err != nil {
		return errors.New("the full grant enrollment is unavailable")
	}
	state, err := v.config.Revocation.State(ctx, c.Binding.GrantID)
	if err != nil || !state.Known {
		return errors.New("the full grant revocation state is unavailable")
	}
	if state.Revoked {
		return grantStopError{lifecycle.GrantRevoked}
	}
	s, err := v.config.Qualification.Current(ctx, c.Binding)
	if err != nil {
		return errors.New("the full grant qualification is unavailable")
	}
	r := s.Target.Report()
	if r.Node != c.Binding.NodeID || r.Boot != c.Binding.BootID || r.PolicySchemaDigest != c.Binding.SchemaDigest || s.CompilerDigest != c.Binding.CompilerDigest || !reflect.DeepEqual(s.ArtifactDigests, c.Binding.ArtifactDigests) || now.Unix() < r.IssuedAt || now.Unix() >= r.ValidUntil {
		return errors.New("the full grant current qualification binding differs")
	}
	if v.fixture != nil {
		if v.fixture.CheckAuthorization(a) != nil || c.QualificationDigest != v.fixture.Digest() || s.Target.Digest() != v.fixture.TargetDigest() {
			return errors.New("the qualification fixture grant differs")
		}
		for _, cap := range r.Capabilities {
			if cap.State == "enforced" {
				return errors.New("the fixture cannot borrow an enforced report")
			}
		}
		return nil
	}
	for _, id := range c.RequiredCapabilities {
		cap := r.Capabilities[id]
		if cap.State != "enforced" || len(cap.Mechanisms) == 0 || !hash64.MatchString(cap.ReceiptSHA256) {
			return errors.New("a required full grant capability is unqualified")
		}
	}
	digest, err := QualificationDigest(s)
	if err != nil || digest != c.QualificationDigest {
		return errors.New("the full grant qualification digest differs")
	}
	return nil
}

var _ lifecycle.Verifier = (*Verifier)(nil)

// NewQualificationFixtureVerifier preserves signatures, enrollment and revocation.
// Only the opaque fixed-worker permit replaces the circular report prerequisite.
func NewQualificationFixtureVerifier(c Config, p *lifecycle.QualificationFixturePermit) (*Verifier, error) {
	if p == nil || p.Purpose() != lifecycle.QualificationFixturePurpose || p.Digest() == "" || c.MaxLifetime > 30*time.Second {
		return nil, errors.New("the fixture verifier requires its bounded opaque permit")
	}
	return newQualificationVerifier(c, p)
}

func newQualificationVerifier(c Config, p *lifecycle.QualificationFixturePermit) (*Verifier, error) {
	if p == nil || p.Digest() == "" || c.MaxLifetime > 30*time.Second {
		return nil, errors.New("the qualification verifier lacks its bounded permit")
	}
	verifier, err := NewVerifier(c)
	if err != nil {
		return nil, err
	}
	verifier.fixture = p
	return verifier, nil
}

func (v *Verifier) QualificationFixtureDigest() string {
	if v == nil || v.fixture == nil {
		return ""
	}
	return v.fixture.Digest()
}
