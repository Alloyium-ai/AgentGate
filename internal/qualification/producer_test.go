// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualification

import (
	"alloyium.local/kernel-poc/internal/policy"
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type unitClock struct {
	mono      uint64
	wall      time.Time
	backwards bool
}

func (c *unitClock) Now() (time.Time, uint64, error) {
	if c.backwards {
		c.mono--
		c.wall = c.wall.Add(-time.Millisecond)
	} else {
		c.mono += uint64(time.Millisecond)
		c.wall = c.wall.Add(time.Millisecond)
	}
	return c.wall, c.mono, nil
}

type unitInspector struct {
	binding  Binding
	calls    int
	changeAt int
}

func (i *unitInspector) Snapshot(context.Context) (Binding, error) {
	i.calls++
	b := owned(i.binding)
	if i.changeAt > 0 && i.calls >= i.changeAt {
		b.ArtifactDigests["files"] = strings.Repeat("f", 64)
	}
	return b, nil
}

type unitAdapter struct {
	clock       *unitClock
	change      func(*Result)
	cover       func([]Coverage) []Coverage
	verifyError bool
	runError    bool
	panicRun    bool
}

func (a *unitAdapter) ID() string { return "explicit-unit-only" }
func (a *unitAdapter) Run(_ context.Context, r Request) (Result, error) {
	if a.panicRun {
		panic("unit adapter panic")
	}
	if a.runError {
		return Result{}, errors.New("unit run failed")
	}
	v := Result{owned(r.Binding), a.clock.mono, a.clock.mono, []byte("{\n  \"unit_fixture_only\": true\n}")}
	if a.change != nil {
		a.change(&v)
	}
	return v, nil
}
func (a *unitAdapter) Verify(r Request, v Result) ([]Coverage, error) {
	if a.verifyError {
		return nil, errors.New("unit raw verification failed")
	}
	out := []Coverage{}
	for _, c := range r.Contracts {
		out = append(out, Coverage{c.CapabilityID, c.Version, append([]string{}, c.Cases...), digestBytes(v.Raw)})
	}
	if a.cover != nil {
		out = a.cover(out)
	}
	return out, nil
}
func producerFixture(t *testing.T) (Config, *unitAdapter, *unitInspector, ed25519.PrivateKey) {
	t.Helper()
	d := candidate(t)
	contracts, e := Contracts(d)
	if e != nil {
		t.Fatal(e)
	}
	artifacts := map[string]string{"qualification": strings.Repeat("1", 64)}
	for _, c := range contracts {
		for _, name := range c.ArtifactNames {
			artifacts[name] = strings.Repeat("2", 64)
		}
	}
	b := Binding{NodeID: "unit-node", BootID: "unit-boot", Challenge: "unit-challenge", SourceRevision: strings.Repeat("3", 40), SchemaDigest: policy.SchemaDigest(), Kernel: "unit-fixture-only", Architecture: "x86_64", BTFSHA256: strings.Repeat("4", 64), KernelConfigSHA256: strings.Repeat("5", 64), InventorySHA256: strings.Repeat("6", 64), ArtifactDigests: artifacts}
	clock := &unitClock{mono: uint64(time.Second), wall: time.Unix(100, 0)}
	inspector := &unitInspector{binding: owned(b)}
	adapter := &unitAdapter{clock: clock}
	c := Config{Expected: b, Documents: []policy.Document{d}, CompilerDigest: strings.Repeat("7", 64), ValidFor: time.Minute, MaxEvidenceAge: 2 * time.Minute, Clock: clock, Inspector: inspector, Adapters: []Adapter{adapter}}
	return c, adapter, inspector, ed25519.NewKeyFromSeed(make([]byte, 32))
}
func TestProducerSignsOnlyCompleteExactPolicySet(t *testing.T) {
	c, _, _, key := producerFixture(t)
	p, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	out, e := p.Produce(context.Background(), key)
	if e != nil {
		t.Fatal(e)
	}
	if len(out.Gaps) != 0 || len(out.Envelope) == 0 || len(out.Evidence.Records) != 1 {
		t.Fatal("complete unit fixture did not sign")
	}
	target, e := policy.VerifyTarget(out.Envelope, key.Public().(ed25519.PublicKey), policy.TargetBinding{Node: c.Expected.NodeID, Boot: c.Expected.BootID, Challenge: c.Expected.Challenge}, 100)
	if e != nil {
		t.Fatal(e)
	}
	digest, _ := c.Documents[0].Digest()
	if e = target.CheckQualificationScope([]string{digest}, c.CompilerDigest, c.Expected.ArtifactDigests); e != nil {
		t.Fatal(e)
	}
	if target.Report().Qualification.EvidenceSHA256 != digestValue("AGENTGATE_QUALIFICATION_EVIDENCE_V1", out.Evidence) {
		t.Fatal("evidence digest differs")
	}
	if string(out.Evidence.Records[0].Raw) != "{\n  \"unit_fixture_only\": true\n}" {
		t.Fatal("raw receipt bytes changed")
	}
	if e = p.VerifyOutput(out, key.Public().(ed25519.PublicKey), 100); e != nil {
		t.Fatal(e)
	}
	out.Evidence.Records[0].Raw = []byte(`{"substituted":true}`)
	if p.VerifyOutput(out, key.Public().(ed25519.PublicKey), 100) == nil {
		t.Fatal("substituted publication evidence accepted")
	}
}
func TestProducerIncompleteCoverageNeverPromotesAnyCapability(t *testing.T) {
	for _, mode := range []string{"absent-adapter", "one-missing-case", "run-error", "verify-error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			c, a, _, key := producerFixture(t)
			switch mode {
			case "absent-adapter":
				c.Adapters = nil
			case "one-missing-case":
				a.cover = func(v []Coverage) []Coverage { v[0].Cases = v[0].Cases[1:]; return v }
			case "run-error":
				a.runError = true
			case "verify-error":
				a.verifyError = true
			case "panic":
				a.panicRun = true
			}
			p, e := New(c)
			if e != nil {
				t.Fatal(e)
			}
			out, e := p.Produce(context.Background(), key)
			if e == nil || len(out.Envelope) != 0 || out.Report.Qualification != nil {
				t.Fatal("partial behavior authorized a report")
			}
			for _, v := range out.Report.Capabilities {
				if v.State != "unavailable" {
					t.Fatal("partial behavior promoted a capability")
				}
			}
			if len(out.UnavailableEnvelope) == 0 {
				t.Fatal("truthful unavailable report is missing")
			}
			target, verifyErr := policy.VerifyTarget(out.UnavailableEnvelope, key.Public().(ed25519.PublicKey), policy.TargetBinding{Node: c.Expected.NodeID, Boot: c.Expected.BootID, Challenge: c.Expected.Challenge}, 100)
			if verifyErr != nil {
				t.Fatal(verifyErr)
			}
			if _, verifyErr = policy.PreviewForTarget(c.Documents[0], target, 100); verifyErr == nil {
				t.Fatal("unavailable diagnostic report admitted the policy")
			}
		})
	}
}

func TestProducerRequiresCandidateDenialAndBothInheritanceWitnesses(t *testing.T) {
	for _, missing := range []string{"ungranted-known-syscall-denied", "fork-inherits-filter", "grandchild-inherits-filter"} {
		t.Run(missing, func(t *testing.T) {
			c, a, _, key := producerFixture(t)
			a.cover = func(v []Coverage) []Coverage {
				found := false
				for i := range v {
					if v[i].CapabilityID == "runtime.explicit-syscalls.v2" {
						kept := []string{}
						for _, name := range v[i].Cases {
							if name == missing {
								found = true
								continue
							}
							kept = append(kept, name)
						}
						v[i].Cases = kept
					}
				}
				if !found {
					t.Fatal("the syscall obligation is absent")
				}
				return v
			}
			p, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			out, err := p.Produce(context.Background(), key)
			if err == nil || len(out.Envelope) != 0 || out.Report.Qualification != nil {
				t.Fatal("one side of the syscall proof qualified the report")
			}
			for _, cap := range out.Report.Capabilities {
				if cap.State != "unavailable" {
					t.Fatal("partial syscall proof promoted a capability")
				}
			}
		})
	}
}
func TestProducerRejectsSubstitutedOrAmbiguousRawEvidence(t *testing.T) {
	for _, mode := range []string{"job", "artifact", "start-time", "end-time", "duplicate-key", "two-values", "receipt-digest", "case-name", "case-repeat", "version"} {
		t.Run(mode, func(t *testing.T) {
			c, a, _, key := producerFixture(t)
			a.change = func(r *Result) {
				switch mode {
				case "job":
					r.Binding.PolicyDigest = strings.Repeat("8", 64)
				case "artifact":
					r.Binding.ArtifactDigests["files"] = strings.Repeat("8", 64)
				case "start-time":
					r.StartedMonoNS = 1
				case "end-time":
					r.FinishedMonoNS += uint64(time.Hour)
				case "duplicate-key":
					r.Raw = []byte(`{"result":1,"result":2}`)
				case "two-values":
					r.Raw = []byte(`{} {}`)
				}
			}
			a.cover = func(v []Coverage) []Coverage {
				switch mode {
				case "receipt-digest":
					v[0].ReceiptSHA256 = strings.Repeat("8", 64)
				case "case-name":
					v[0].Cases[0] = "unregistered"
				case "case-repeat":
					v[0].Cases = append(v[0].Cases, v[0].Cases[0])
				case "version":
					v[0].ContractVersion = "future"
				}
				return v
			}
			p, e := New(c)
			if e != nil {
				t.Fatal(e)
			}
			out, e := p.Produce(context.Background(), key)
			if e == nil || len(out.Envelope) != 0 {
				t.Fatal("unbound evidence signed")
			}
		})
	}
}
func TestProducerRemeasuresTargetAndArtifactSet(t *testing.T) {
	c, _, i, key := producerFixture(t)
	i.changeAt = 3
	p, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	out, e := p.Produce(context.Background(), key)
	if e == nil || len(out.Envelope) != 0 {
		t.Fatal("changed target signed")
	}
}
func TestProducerOwnsPolicyAndArtifactInputs(t *testing.T) {
	c, _, _, key := producerFixture(t)
	p, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	c.Expected.ArtifactDigests["files"] = strings.Repeat("8", 64)
	c.Documents[0].Files.Rules[0].Selector.Path = "/substituted"
	out, e := p.Produce(context.Background(), key)
	if e != nil {
		t.Fatal(e)
	}
	if reflect.DeepEqual(out.Evidence.Target, c.Expected) {
		t.Fatal("configuration alias escaped")
	}
}
func TestProducerRequiresEveryApprovedPolicy(t *testing.T) {
	c, a, _, key := producerFixture(t)
	second := owned(c.Documents[0])
	second.Files.Rules[0].Selector.Path = "/other/executable"
	c.Documents = append(c.Documents, second)
	calls := 0
	a.cover = func(v []Coverage) []Coverage {
		calls++
		if calls == 2 {
			return nil
		}
		return v
	}
	p, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	out, e := p.Produce(context.Background(), key)
	if e == nil || len(out.Gaps) == 0 || len(out.Envelope) != 0 {
		t.Fatal("one policy authorized an untested policy")
	}
}
func TestProducerRejectsClockFailureStaleEvidenceAndCancellation(t *testing.T) {
	for _, mode := range []string{"backwards", "age", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			c, a, _, key := producerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "backwards":
				a.change = func(*Result) { a.clock.backwards = true }
			case "age":
				a.change = func(*Result) {
					a.clock.mono += uint64(3 * time.Minute)
					a.clock.wall = a.clock.wall.Add(3 * time.Minute)
				}
			case "canceled":
				cancel()
			}
			p, e := New(c)
			if e != nil {
				t.Fatal(e)
			}
			out, e := p.Produce(ctx, key)
			if e == nil || len(out.Envelope) != 0 {
				t.Fatal("invalid clock or canceled run signed")
			}
		})
	}
}
