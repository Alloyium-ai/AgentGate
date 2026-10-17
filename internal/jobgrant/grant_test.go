// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobgrant

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func documentFixture() policy.Document {
	templates := []string{}
	extensions := map[string]json.RawMessage{}
	d := policy.Document{SchemaVersion: policy.Version, Profile: policy.KernelProfile, Defaults: &policy.Defaults{RegisteredOperations: "deny", UnmatchedResources: "deny", MissingManagedPolicy: "deny"}, RuntimeTemplates: &templates, Extensions: &extensions,
		Files: &policy.Files{Defaults: policy.FileDefaults{Read: "deny", Write: "deny"}, Rules: []policy.FileRule{}, ResourceUse: "recheck-and-terminate"}, Programs: &policy.Programs{Default: "deny", Rules: []policy.ProgramRule{}}, Network: &policy.Network{Default: "deny", Rules: []policy.NetworkRule{}, DNS: policy.DNS{ResolverProfile: "trusted-forwarder.v1", CNAME: "validate-chain", Expiry: "remove-expired-authorization"}}, Sockets: &policy.SocketPolicy{Default: "deny", Rules: []policy.SocketRule{}}, Identity: &policy.Identity{TrustSource: "local-enrollment", ProofOfPossession: true, JobBinding: true, NodeBinding: true, BootBinding: true, ProcessDomain: "job-cgroup", Descendants: "inherit"}, Runtime: &policy.Runtime{Profile: "managed-unprivileged.v1", UID: 65534, GID: 65534, SupplementaryGroups: []int{}, Capabilities: []string{}, NoNewPrivileges: true, Seccomp: policy.Seccomp{Profile: "explicit-allowlist-notify.v2", Architecture: "x86_64", Default: "deny", AllowSyscalls: []string{}}}, Lifecycle: &policy.Lifecycle{BaselineVersion: "baseline", DurationSeconds: 20, Release: "restore-baseline", Revoke: "terminate-job", Recovery: "pinned-generation-reconcile"}, Evidence: &policy.Evidence{Profile: "node-chain-authority-batch.v1", MaxReportedLoss: 0, BatchEvents: 500, BatchSeconds: 5}}
	d.RequiredCapabilities, _ = policy.Requirements(d)
	return d
}

type dependencies struct {
	now                                                      int64
	mono                                                     uint64
	clockErr, enrollmentErr, qualificationErr, revocationErr error
	revoked, unknown                                         bool
	snapshot                                                 Snapshot
}

func (d *dependencies) Now() (time.Time, uint64, error) {
	return time.Unix(d.now, 0), d.mono, d.clockErr
}
func (d *dependencies) VerifyEnrollment(context.Context, lifecycle.Binding) error {
	return d.enrollmentErr
}
func (d *dependencies) Current(context.Context, lifecycle.Binding) (Snapshot, error) {
	return d.snapshot, d.qualificationErr
}
func (d *dependencies) State(context.Context, string) (RevocationState, error) {
	return RevocationState{!d.unknown, d.revoked}, d.revocationErr
}

type fixture struct {
	d      policy.Document
	c      Claims
	e      Envelope
	key    ed25519.PrivateKey
	deps   *dependencies
	v      *Verifier
	a      lifecycle.Authorization
	report policy.CapabilityReport
}

func setup(t *testing.T) *fixture {
	t.Helper()
	d := documentFixture()
	digest, err := d.Digest()
	if err != nil {
		t.Fatal(err)
	}
	b := lifecycle.Binding{AgentID: "agent-one", AgentKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), JobDigest: strings.Repeat("a", 64), GrantID: "grant-one", RunID: "run-one", NodeID: "node-one", BootID: "boot-one", PolicyDigest: digest, SchemaDigest: policy.SchemaDigest(), CompilerDigest: strings.Repeat("d", 64), ArtifactDigests: map[string]string{"kernel": strings.Repeat("e", 64)}, CgroupID: 100, Generation: 1, DeadlineNS: uint64(21 * time.Second)}
	caps := map[string]policy.Capability{}
	for _, id := range d.RequiredCapabilities {
		caps[id] = policy.Capability{State: "enforced", Mechanisms: []string{"unit-only"}, ReceiptSHA256: strings.Repeat("f", 64)}
	}
	r := policy.CapabilityReport{SchemaVersion: policy.CapabilityVersion, Node: b.NodeID, Boot: b.BootID, Challenge: "challenge-one", Kernel: "6.8.0-142-generic", Architecture: "x86_64", SourceRevision: strings.Repeat("a", 40), ArtifactSHA256: strings.Repeat("b", 64), PolicySchemaDigest: policy.SchemaDigest(), InventorySHA256: strings.Repeat("c", 64), BTFSHA256: strings.Repeat("d", 64), KernelConfigSHA256: strings.Repeat("e", 64), IssuedAt: 100, ValidUntil: 200, Capabilities: caps, Probes: []policy.HookProbe{}}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	target := signedTarget(t, r, key)
	snapshot := Snapshot{target, b.CompilerDigest, b.ArtifactDigests}
	q, err := QualificationDigest(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	c := Claims{Binding: b, DocumentDigest: digest, RequiredCapabilities: d.RequiredCapabilities, QualificationDigest: q, AuditHeaderDigest: strings.Repeat("1", 64), IssuedAt: 140, NotBefore: 140, ExpiresAt: 160, IssuedMonoNS: uint64(time.Second), DeadlineNS: b.DeadlineNS}
	e, err := Sign("authority-one", "key-one", key, c, d)
	if err != nil {
		t.Fatal(err)
	}
	grant, _ := Encode(e)
	raw, _ := d.Canonical()
	deps := &dependencies{now: 150, mono: uint64(10 * time.Second), snapshot: snapshot}
	v, err := NewVerifier(Config{map[string]ed25519.PublicKey{"authority-one/key-one": key.Public().(ed25519.PublicKey)}, deps, deps, deps, deps, time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{d, c, e, key, deps, v, lifecycle.Authorization{Binding: b, Grant: grant, Document: raw, RequiredCapabilities: d.RequiredCapabilities}, r}
}
func signedTarget(t *testing.T, r policy.CapabilityReport, key ed25519.PrivateKey) policy.VerifiedTarget {
	t.Helper()
	raw, err := policy.SignReport(r, key)
	if err != nil {
		t.Fatal(err)
	}
	target, err := policy.VerifyTarget(raw, key.Public().(ed25519.PublicKey), policy.TargetBinding{Node: r.Node, Boot: r.Boot, Challenge: r.Challenge}, 150)
	if err != nil {
		t.Fatal(err)
	}
	return target
}
func TestFullGrantVerifiesExactBindingAndDistinctProtocol(t *testing.T) {
	f := setup(t)
	if err := f.v.Verify(context.Background(), f.a); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(`{"protocol":"agentgate.grant.v1"}`); err == nil {
		t.Fatal("legacy protocol passed")
	}
	encoded, _ := Encode(f.e)
	if _, err := Decode(strings.Replace(encoded, `"protocol":`, `"protocol":"duplicate","protocol":`, 1)); err == nil {
		t.Fatal("duplicate key passed")
	}
}
func TestFullGrantRejectsChangedClaimsAndDocument(t *testing.T) {
	for name, change := range map[string]func(*Claims){"policy": func(c *Claims) { c.DocumentDigest = strings.Repeat("9", 64) }, "deadline": func(c *Claims) { c.DeadlineNS++ }, "capability": func(c *Claims) { c.RequiredCapabilities = []string{} }, "header": func(c *Claims) { c.AuditHeaderDigest = "" }, "wall-length": func(c *Claims) { c.ExpiresAt++ }, "mono-length": func(c *Claims) { c.IssuedMonoNS-- }} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			c := f.c
			change(&c)
			if _, err := Sign("authority-one", "key-one", f.key, c, f.d); err == nil {
				t.Fatal("invalid claims signed")
			}
		})
	}
	f := setup(t)
	e := f.e
	e.Claims.Binding.Generation++
	encoded, _ := Encode(e)
	f.a.Grant = encoded
	if f.v.Verify(context.Background(), f.a) == nil {
		t.Fatal("tampered binding passed")
	}
	f = setup(t)
	f.a.Binding.ArtifactDigests = map[string]string{"kernel": strings.Repeat("8", 64)}
	if f.v.Verify(context.Background(), f.a) == nil {
		t.Fatal("authorization binding changed")
	}
	f = setup(t)
	f.d.Lifecycle.DurationSeconds = 19
	raw, _ := json.Marshal(f.d)
	f.a.Document = raw
	if f.v.Verify(context.Background(), f.a) == nil {
		t.Fatal("document change passed")
	}
}
func TestFullGrantClosesOnClockEnrollmentQualificationAndRevocationFailure(t *testing.T) {
	for _, name := range []string{"clock", "clock-and-expired", "before-wall", "after-wall", "before-mono", "after-mono", "before-wall-and-expired-mono", "shortened-lifetime", "enrollment", "qualification", "unknown-revocation", "unknown-and-revoked", "revoked", "revocation-outage", "outage-and-revoked", "compiler", "artifact", "expired-report", "probe"} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			d := f.deps
			switch name {
			case "clock":
				d.clockErr = errors.New("unavailable")
			case "clock-and-expired":
				d.clockErr = errors.New("unavailable")
				d.now = f.c.ExpiresAt
				d.mono = f.c.DeadlineNS
			case "before-wall":
				d.now = 139
			case "after-wall":
				d.now = 160
			case "before-mono":
				d.mono = uint64(time.Second) - 1
			case "after-mono":
				d.mono = f.c.DeadlineNS
			case "before-wall-and-expired-mono":
				d.now = f.c.NotBefore - 1
				d.mono = f.c.DeadlineNS
			case "shortened-lifetime":
				f.v.config.MaxLifetime = time.Second
			case "enrollment":
				d.enrollmentErr = errors.New("unavailable")
			case "qualification":
				d.qualificationErr = errors.New("unavailable")
			case "unknown-revocation":
				d.unknown = true
			case "unknown-and-revoked":
				d.unknown, d.revoked = true, true
			case "revoked":
				d.revoked = true
			case "revocation-outage":
				d.revocationErr = errors.New("unavailable")
			case "outage-and-revoked":
				d.revocationErr = errors.New("unavailable")
				d.revoked = true
			case "compiler":
				d.snapshot.CompilerDigest = strings.Repeat("4", 64)
			case "artifact":
				d.snapshot.ArtifactDigests = map[string]string{"kernel": strings.Repeat("4", 64)}
			case "expired-report":
				f.report.ValidUntil = 151
				d.snapshot.Target = signedTarget(t, f.report, f.key)
				d.now = 152
			case "probe":
				cap := f.report.Capabilities[f.c.RequiredCapabilities[0]]
				cap.State = "probe-only"
				f.report.Capabilities[f.c.RequiredCapabilities[0]] = cap
				d.snapshot.Target = signedTarget(t, f.report, f.key)
			}
			err := f.v.Verify(context.Background(), f.a)
			if err == nil {
				t.Fatal("unsafe dependency passed")
			}
			var stop lifecycle.LifecycleStopReason
			typed := errors.As(err, &stop)
			switch name {
			case "after-wall", "after-mono":
				if !typed || stop.LifecycleStopReason() != lifecycle.GrantExpired {
					t.Fatal("verified expiry lost its stop cause", err)
				}
			case "revoked":
				if !typed || stop.LifecycleStopReason() != lifecycle.GrantRevoked {
					t.Fatal("known revocation lost its stop cause", err)
				}
			default:
				if typed {
					t.Fatal("an unverified failure acquired a grant stop cause", err)
				}
			}
		})
	}
}
func TestStableQualificationRetainsMeasurementsAndExcludesFreshness(t *testing.T) {
	f := setup(t)
	first, _ := QualificationDigest(f.deps.snapshot)
	f.report.Challenge = "fresh-challenge"
	f.report.IssuedAt = 110
	f.report.ValidUntil = 210
	next := f.deps.snapshot
	next.Target = signedTarget(t, f.report, f.key)
	second, _ := QualificationDigest(next)
	if first != second {
		t.Fatal("freshness changed stable qualification")
	}
	f.report.BTFSHA256 = strings.Repeat("7", 64)
	next.Target = signedTarget(t, f.report, f.key)
	third, _ := QualificationDigest(next)
	if third == first {
		t.Fatal("BTF change kept qualification")
	}
	f.report.InventorySHA256 = ""
	next.Target = signedTarget(t, f.report, f.key)
	if _, err := QualificationDigest(next); err == nil {
		t.Fatal("missing target measurement passed")
	}
}
func TestFullGrantTrustCopiesKeysAndRejectsUnknownAuthority(t *testing.T) {
	f := setup(t)
	pub := f.key.Public().(ed25519.PublicKey)
	keys := map[string]ed25519.PublicKey{"authority-one/key-one": pub}
	v, err := NewVerifier(Config{keys, f.deps, f.deps, f.deps, f.deps, time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	pub[0] ^= 1
	delete(keys, "authority-one/key-one")
	if err = v.Verify(context.Background(), f.a); err != nil {
		t.Fatal("caller changed pinned trust", err)
	}
	f.e.KeyID = "other"
	if _, err = VerifySigned(f.e, v.config.Authorities, f.d); err == nil {
		t.Fatal("unknown authority passed")
	}
}
