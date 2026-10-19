// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobaudit

import (
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func documentFixture() policy.Document {
	templates := []string{}
	extensions := map[string]json.RawMessage{}
	d := policy.Document{SchemaVersion: policy.Version, Profile: policy.KernelProfile, Defaults: &policy.Defaults{"deny", "deny", "deny"}, RuntimeTemplates: &templates, Extensions: &extensions,
		Files: &policy.Files{Defaults: policy.FileDefaults{"deny", "deny"}, Rules: []policy.FileRule{}, ResourceUse: "recheck-and-terminate"}, Programs: &policy.Programs{Default: "deny", Rules: []policy.ProgramRule{}}, Network: &policy.Network{Default: "deny", Rules: []policy.NetworkRule{}, DNS: policy.DNS{"trusted-forwarder.v1", "validate-chain", "remove-expired-authorization"}}, Sockets: &policy.SocketPolicy{Default: "deny", Rules: []policy.SocketRule{}}, Identity: &policy.Identity{"local-enrollment", true, true, true, true, "job-cgroup", "inherit"}, Runtime: &policy.Runtime{Profile: "managed-unprivileged.v1", UID: 65534, GID: 65534, SupplementaryGroups: []int{}, Capabilities: []string{}, NoNewPrivileges: true, Seccomp: policy.Seccomp{"explicit-allowlist-notify.v2", "x86_64", "deny", []string{}}}, Lifecycle: &policy.Lifecycle{"baseline", 20, "restore-baseline", "terminate-job", "pinned-generation-reconcile"}, Evidence: &policy.Evidence{"node-chain-authority-batch.v1", 0, 500, 5}}
	d.RequiredCapabilities, _ = policy.Requirements(d)
	return d
}

type clock struct{ now uint64 }

func (c *clock) NowNS() (uint64, error) { return c.now, nil }

type signer struct{ key ed25519.PrivateKey }

func (s signer) KeyID() string { return "node-key" }
func (s signer) Sign(_ context.Context, raw []byte) ([]byte, error) {
	return ed25519.Sign(s.key, raw), nil
}

type fixture struct {
	w                        *Writer
	config                   Config
	trust                    Trust
	grant                    jobgrant.Envelope
	authority, node, receipt ed25519.PrivateKey
	clock                    *clock
	path                     string
}

func setup(t *testing.T) *fixture { return setupWithBound(t, true) }

func setupWithBound(t *testing.T, bounded bool) *fixture {
	t.Helper()
	scratch := os.Getenv("AGENTGATE_TEST_SCRATCH")
	if scratch == "" {
		t.Skip("set an owned protected test directory")
	}
	dir, err := os.MkdirTemp(scratch, "audit-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	d := documentFixture()
	digest, err := d.Digest()
	if err != nil {
		t.Fatal(err)
	}
	b := lifecycle.Binding{AgentID: "agent-one", AgentKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), JobDigest: strings.Repeat("a", 64), GrantID: "grant-one", RunID: "run-one", NodeID: "node-one", BootID: "boot-one", PolicyDigest: digest, SchemaDigest: policy.SchemaDigest(), CompilerDigest: strings.Repeat("d", 64), ArtifactDigests: map[string]string{"kernel": strings.Repeat("e", 64)}, CgroupID: 100, Generation: 1, DeadlineNS: uint64(21 * time.Second)}
	streams := []Stream{}
	registry := Registry{}
	for _, name := range []string{"files", "peers", "sockets", "custody", "process"} {
		format := ResourceFormats()[name]
		streams = append(streams, Stream{name, "resource", format.Version, b.ArtifactDigests["kernel"]})
		size := format.Bytes
		registry[name+"/"+format.Version] = func(raw []byte) (Observation, error) {
			if len(raw) != size {
				return Observation{}, errors.New("unit layout differs")
			}
			if raw[48] > 1 {
				return Observation{}, errors.New("unit decision marker differs")
			}
			decision := raw[48] == 1
			return Observation{Decision: &decision, CgroupID: binary.LittleEndian.Uint64(raw[0:8]), Generation: binary.LittleEndian.Uint64(raw[8:16]), Sequence: binary.LittleEndian.Uint64(raw[16:24]), TimestampNS: binary.LittleEndian.Uint64(raw[24:32]), DNSLeaseRevision: binary.LittleEndian.Uint64(raw[32:40])}, nil
		}
	}
	streams = append(streams, Stream{"syscalls", "observation", "syscalls104.v1", b.ArtifactDigests["kernel"]})
	registry["syscalls/syscalls104.v1"] = func(raw []byte) (Observation, error) {
		if len(raw) != 104 {
			return Observation{}, errors.New("unit observation size differs")
		}
		return Observation{CgroupID: binary.LittleEndian.Uint64(raw[0:8]), Generation: binary.LittleEndian.Uint64(raw[8:16]), Sequence: binary.LittleEndian.Uint64(raw[16:24]), TimestampNS: binary.LittleEndian.Uint64(raw[24:32]), BindingState: binary.LittleEndian.Uint32(raw[40:44])}, nil
	}
	streams = append(streams, Stream{"lifecycle", "control", "node-control.v1", b.ArtifactDigests["kernel"]})
	registry["lifecycle/node-control.v1"] = func(raw []byte) (Observation, error) {
		var value struct {
			State       string       `json:"state"`
			GrantExpiry *GrantExpiry `json:"grant_expiry,omitempty"`
		}
		if lifecycle.DecodeTransport(bytes.NewReader(raw), &value) != nil {
			return Observation{}, errors.New("unit control differs")
		}
		return Observation{CgroupID: 100, Generation: 1, ControlPhase: value.State, GrantExpiry: value.GrantExpiry}, nil
	}
	header := Header{Protocol: HeaderProtocol, Binding: b, DocumentDigest: digest, QualificationDigest: strings.Repeat("9", 64), RequiredCapabilities: d.RequiredCapabilities, RequiredStreams: streams, CreatedMonoNS: 1}
	hd, err := HeaderDigest(header)
	if err != nil {
		t.Fatal(err)
	}
	authority := ed25519.NewKeyFromSeed(make([]byte, 32))
	node := ed25519.NewKeyFromSeed([]byte(strings.Repeat("n", 32)))
	receipt := ed25519.NewKeyFromSeed([]byte(strings.Repeat("r", 32)))
	claims := jobgrant.Claims{Binding: b, DocumentDigest: digest, RequiredCapabilities: d.RequiredCapabilities, QualificationDigest: header.QualificationDigest, AuditHeaderDigest: hd, IssuedAt: 140, NotBefore: 140, ExpiresAt: 160, IssuedMonoNS: uint64(time.Second), DeadlineNS: b.DeadlineNS}
	grant, err := jobgrant.Sign("authority", "grant-key", authority, claims, d)
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{uint64(10 * time.Second)}
	path := filepath.Join(dir, "events.jsonl")
	config := Config{Path: path, Header: header, Registry: registry, Clock: clk, Document: d, AuthorityKeys: map[string]ed25519.PublicKey{"authority/grant-key": authority.Public().(ed25519.PublicKey), "authority/receipt-key": receipt.Public().(ed25519.PublicKey)}, NodeKeys: map[string]ed25519.PublicKey{"node-one/node-key": node.Public().(ed25519.PublicKey)}, MaxRecords: 100, MaxBytes: 1 << 20}
	w, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	if err = w.AttachGrant(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	f := &fixture{w, config, Trust{config.NodeKeys, config.AuthorityKeys, registry, d}, grant, authority, node, receipt, clk, path}
	if bounded {
		f.bound(t)
		// This test decoder supplies a synthetic proof. Production uses nodecontrol's typed manifest/set validator.
		f.clock.now = uint64(1503 * time.Millisecond)
		if err = f.w.Append(context.Background(), "lifecycle", []byte(`{"state":"runtime_files_verified"}`)); err != nil {
			t.Fatal(err)
		}
		f.clock.now = uint64(10 * time.Second)
	}
	return f
}
func rawEvent(size int, sequence uint64) []byte {
	raw := make([]byte, size)
	for i, v := range []uint64{100, 1, sequence, uint64(2 * time.Second), 7} {
		binary.LittleEndian.PutUint64(raw[i*8:i*8+8], v)
	}
	return raw
}
func (f *fixture) fill(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	for _, s := range f.config.Header.RequiredStreams {
		var raw []byte
		if s.Kind == "resource" {
			raw = rawEvent(ResourceFormats()[s.Name].Bytes, 1)
		} else if s.Kind == "observation" {
			raw = rawEvent(104, 1)
		} else {
			raw = []byte(`{"state":"held"}`)
		}
		if f.w.last[s.Name] == 0 || (s.Kind == "control" && f.w.last[s.Name] == 2) {
			if err := f.w.Append(ctx, s.Name, raw); err != nil {
				t.Fatal(err)
			}
		}
		c := FinalCounters{Sequence: f.w.last[s.Name], Available: true}
		if s.Kind == "resource" {
			c.Decisions = c.Sequence
		}
		if err := f.w.FinishStream(ctx, s.Name, c); err != nil {
			t.Fatal(err)
		}
	}
}
func terminal() Terminal {
	return Terminal{State: "completed", ExitCode: 0, Empty: true, RightsRemoved: true, OutputDigest: strings.Repeat("4", 64), CountersAvailable: true}
}
func (f *fixture) seal(t *testing.T) {
	t.Helper()
	if _, err := f.w.Seal(context.Background(), terminal(), signer{f.node}); err != nil {
		t.Fatal(err)
	}
}
func (f *fixture) accept(t *testing.T) {
	t.Helper()
	r, err := SignReceipt("authority", "receipt-key", f.receipt, f.w.Export(), f.trust, 161)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.w.AttachAuthority(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}
func TestDurableMultiStreamEvidenceNeedsSeparateAuthorityReceipt(t *testing.T) {
	f := setup(t)
	f.fill(t)
	f.seal(t)
	if v := VerifyOffline(f.w.Export(), f.trust); v.State != "INCOMPLETE" || v.Reason != "authority-receipt-missing" {
		t.Fatal(v)
	}
	f.accept(t)
	bundle := f.w.Export()
	if v := VerifyOffline(bundle, f.trust); v.State != "VALID_COMPLETE" {
		t.Fatal(v)
	}
	if err := f.w.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Read(bytes.NewReader(raw))
	if err != nil || !same(bundle, restored) {
		t.Fatal("durable evidence changed", err)
	}
	if v := VerifyOffline(restored, f.trust); v.State != "VALID_COMPLETE" {
		t.Fatal(v)
	}
	if _, err = Open(f.config); err == nil {
		t.Fatal("an existing audit was overwritten")
	}
}
func TestAuditRejectsResourceGapsWrongBindingAndUnknownLayouts(t *testing.T) {
	for _, name := range []string{"gap", "domain", "generation", "deadline", "size", "unknown", "finished"} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			raw := rawEvent(216, 1)
			stream := "files"
			switch name {
			case "gap":
				binary.LittleEndian.PutUint64(raw[16:24], 2)
			case "domain":
				binary.LittleEndian.PutUint64(raw[:8], 101)
			case "generation":
				binary.LittleEndian.PutUint64(raw[8:16], 2)
			case "deadline":
				raw[48] = 1
				binary.LittleEndian.PutUint64(raw[24:32], f.config.Header.Binding.DeadlineNS)
			case "size":
				raw = raw[:215]
			case "unknown":
				stream = "missing"
			case "finished":
				if err := f.w.FinishStream(context.Background(), stream, FinalCounters{Available: true}); err != nil {
					t.Fatal(err)
				}
			}
			if name == "gap" {
				if err := f.w.Append(context.Background(), stream, raw); err != nil {
					t.Fatal(err)
				}
				if f.w.FinishStream(context.Background(), stream, FinalCounters{Sequence: 2, Decisions: 2, Available: true}) == nil {
					t.Fatal("a final sequence gap passed")
				}
				return
			}
			if f.w.Append(context.Background(), stream, raw) == nil {
				t.Fatal("unsafe resource event passed")
			}
		})
	}
}
func TestAuditCannotSealUnknownCountersLossOrIncompleteStop(t *testing.T) {
	for _, name := range []string{"unknown", "lost", "gap", "missing", "stop", "rights", "availability"} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			if name == "unknown" {
				if f.w.FinishStream(context.Background(), "files", FinalCounters{}) == nil {
					t.Fatal("unknown counters passed")
				}
			} else if name == "lost" || name == "gap" {
				c := FinalCounters{Available: true}
				if name == "lost" {
					c.Lost = 1
				} else {
					c.Sequence = 1
					c.Decisions = 1
				}
				if f.w.FinishStream(context.Background(), "files", c) == nil {
					t.Fatal("incomplete counters passed")
				}
			} else if name != "missing" {
				f.fill(t)
			}
			term := terminal()
			switch name {
			case "stop":
				term.Empty = false
			case "rights":
				term.RightsRemoved = false
			case "availability":
				term.CountersAvailable = false
			}
			if _, err := f.w.Seal(context.Background(), term, signer{f.node}); err == nil {
				t.Fatal("incomplete evidence sealed")
			}
		})
	}
}
func TestOfflineVerificationRejectsTamperUnknownKeysAndCounterSubstitution(t *testing.T) {
	f := setup(t)
	f.fill(t)
	f.seal(t)
	f.accept(t)
	original := f.w.Export()
	for _, name := range []string{"raw", "order", "counter", "terminal", "authority", "missing", "node-key", "authority-key"} {
		t.Run(name, func(t *testing.T) {
			b := clone(original)
			trust := f.trust
			trust.NodeKeys = copyKeys(trust.NodeKeys)
			trust.AuthorityKeys = copyKeys(trust.AuthorityKeys)
			switch name {
			case "raw":
				b.Events[0].Raw[0] ^= 1
			case "order":
				b.Events[0], b.Events[1] = b.Events[1], b.Events[0]
			case "counter":
				c := b.Counters["files"]
				c.Decisions++
				b.Counters["files"] = c
			case "terminal":
				b.Seal.Terminal.Empty = false
			case "authority":
				b.Authority.NodeSealDigest = strings.Repeat("0", 64)
			case "missing":
				b.Authority = nil
			case "node-key":
				delete(trust.NodeKeys, "node-one/node-key")
			case "authority-key":
				delete(trust.AuthorityKeys, "authority/receipt-key")
			}
			v := VerifyOffline(b, trust)
			if v.State == "VALID_COMPLETE" {
				t.Fatal("modified evidence verified")
			}
			if strings.HasSuffix(name, "key") && v.State != "UNKNOWN_KEY" {
				t.Fatal(v)
			}
		})
	}
}
func TestAuditRejectsMissingMandatoryStreamAndUnboundArtifact(t *testing.T) {
	f := setup(t)
	h := clone(f.config.Header)
	h.RequiredStreams = h.RequiredStreams[1:]
	if _, err := HeaderDigest(h); err == nil {
		t.Fatal("missing resource stream passed")
	}
	h = clone(f.config.Header)
	h.RequiredStreams[0].ArtifactDigest = strings.Repeat("8", 64)
	if _, err := HeaderDigest(h); err == nil {
		t.Fatal("unbound stream artifact passed")
	}
	h = clone(f.config.Header)
	h.RequiredStreams[0].Version = "unknown.v9"
	if _, err := HeaderDigest(h); err == nil {
		t.Fatal("unknown raw layout passed")
	}
}
func TestAuditRetainsDNSRevisionAndSeparatesControlCounters(t *testing.T) {
	f := setup(t)
	f.fill(t)
	b := f.w.Export()
	if b.Events[2].Observation.DNSLeaseRevision != 7 || b.Events[len(b.Events)-1].Kind != "control" || b.Events[len(b.Events)-1].Observation.DNSLeaseRevision != 0 {
		t.Fatal("resource and control evidence mixed")
	}
	if b.Counters["lifecycle"].Decisions != 0 {
		t.Fatal("control records became kernel decisions")
	}
}
func TestDurableAuditRejectsTruncationRepeatedHeaderAndPostSealEvents(t *testing.T) {
	f := setup(t)
	f.fill(t)
	f.seal(t)
	raw, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Read(bytes.NewReader(append(raw, []byte(`{"kind":`)...))); err == nil {
		t.Fatal("truncation passed")
	}
	first := bytes.SplitN(raw, []byte("\n"), 2)[0]
	if _, err = Read(bytes.NewReader(append(append([]byte{}, raw...), append(first, '\n')...))); err == nil {
		t.Fatal("repeated header passed")
	}
	if f.w.Append(context.Background(), "files", rawEvent(216, 2)) == nil {
		t.Fatal("a sealed stream changed")
	}
}
func TestAuditPathCustodyRejectsLinksAndUnprotectedParents(t *testing.T) {
	f := setup(t)
	dir := filepath.Dir(f.path)
	target := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(f.path, target); err != nil {
		t.Fatal(err)
	}
	c := f.config
	c.Path = target
	if _, err := Open(c); err == nil {
		t.Fatal("symlink destination passed")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	c.Path = filepath.Join(dir, "other.jsonl")
	if _, err := Open(c); err == nil {
		t.Fatal("a public parent passed")
	}
}

func TestMissingSyscallBindingStaysGenerationZeroAndIncomplete(t *testing.T) {
	f := setup(t)
	raw := rawEvent(104, 1)
	binary.LittleEndian.PutUint64(raw[8:16], 0)
	binary.LittleEndian.PutUint32(raw[40:44], 1)
	if err := f.w.Append(context.Background(), "syscalls", raw); err != nil {
		t.Fatal(err)
	}
	b := f.w.Export()
	if len(b.Events) != 3 || b.Events[2].Observation.Generation != 0 || b.Events[2].Observation.BindingState != 1 || !bytes.Equal(raw, b.Events[2].Raw) {
		t.Fatal("missing binding provenance changed")
	}
	for _, stream := range f.config.Header.RequiredStreams {
		if stream.Name != "syscalls" {
			var event []byte
			if stream.Kind == "resource" {
				event = rawEvent(ResourceFormats()[stream.Name].Bytes, 1)
			} else {
				event = []byte(`{"state":"held"}`)
			}
			if err := f.w.Append(context.Background(), stream.Name, event); err != nil {
				t.Fatal(err)
			}
		}
		counters := FinalCounters{Sequence: f.w.last[stream.Name], Available: true}
		if stream.Kind == "resource" {
			counters.Decisions = 1
		}
		if err := f.w.FinishStream(context.Background(), stream.Name, counters); err != nil {
			t.Fatal(err)
		}
	}
	b = f.w.Export()
	if len(b.Counters) != len(b.Header.RequiredStreams) {
		t.Fatal("the negative fixture lacks final counters")
	}
	if complete(b, terminal()) {
		t.Fatal("missing syscall binding became complete")
	}
	if _, err := f.w.Seal(context.Background(), terminal(), signer{f.node}); err == nil {
		t.Fatal("generation-zero evidence sealed complete")
	}
}
func TestRejectedRawEventPermanentlyClosesTheWriter(t *testing.T) {
	f := setup(t)
	if f.w.Append(context.Background(), "files", rawEvent(215, 1)) == nil {
		t.Fatal("bad event size passed")
	}
	if err := f.w.Append(context.Background(), "files", rawEvent(216, 1)); err == nil {
		t.Fatal("a rejected raw event was silently replaced")
	}
}

func TestNodeAndAuthorityUseSeparateSigningTrust(t *testing.T) {
	f := setup(t)
	c := f.config
	c.Path = filepath.Join(filepath.Dir(f.path), "same-key.jsonl")
	c.NodeKeys = map[string]ed25519.PublicKey{"node-one/node-key": f.authority.Public().(ed25519.PublicKey)}
	if _, err := Open(c); err == nil {
		t.Fatal("one key served both signing roles")
	}
}

func TestExpiredResourceDenialRemainsACompleteExpiredTrail(t *testing.T) {
	f := setup(t)
	raw := rawEvent(216, 1)
	binary.LittleEndian.PutUint64(raw[24:32], f.config.Header.Binding.DeadlineNS+1)
	if err := f.w.Append(context.Background(), "files", raw); err != nil {
		t.Fatal("the explicit expired denial was discarded", err)
	}
	f.fill(t)
	f.clock.now = f.config.Header.Binding.DeadlineNS + 2
	term := terminal()
	term.State = "expired"
	term.ExitCode = 137
	if _, err := f.w.Seal(context.Background(), term, signer{f.node}); err != nil {
		t.Fatal(err)
	}
	f.accept(t)
	bundle := f.w.Export()
	if v := VerifyOffline(bundle, f.trust); v.State != "VALID_COMPLETE" {
		t.Fatal(v)
	}
	event := bundle.Events[2]
	if event.Observation.Decision == nil || *event.Observation.Decision || !bytes.Equal(raw, event.Raw) {
		t.Fatal("the expired denial changed")
	}
	if complete(bundle, terminal()) {
		t.Fatal("an expired trail became a completed job")
	}
}
func TestExpiredResourceAllowAndUnknownDecisionCannotSeal(t *testing.T) {
	for _, kind := range []string{"allow", "unknown", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			raw := rawEvent(216, 1)
			binary.LittleEndian.PutUint64(raw[24:32], f.config.Header.Binding.DeadlineNS)
			if kind == "allow" {
				raw[48] = 1
			} else if kind == "malformed" {
				raw[48] = 2
			} else {
				original := f.w.config.Registry["files/files216.v1"]
				f.w.config.Registry["files/files216.v1"] = func(raw []byte) (Observation, error) { o, err := original(raw); o.Decision = nil; return o, err }
			}
			if err := f.w.Append(context.Background(), "files", raw); err == nil {
				t.Fatal("the post-deadline event lacked an explicit denial")
			}
			if _, err := f.w.Seal(context.Background(), terminal(), signer{f.node}); err == nil {
				t.Fatal("invalid expiry evidence sealed")
			}
		})
	}
}

func TestConcurrentKernelDeliveryRetainsArrivalOrderAndProvesCoverage(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	second := rawEvent(216, 2)
	first := rawEvent(216, 1)
	if err := f.w.Append(ctx, "files", second); err != nil {
		t.Fatal(err)
	}
	if err := f.w.Append(ctx, "files", first); err != nil {
		t.Fatal(err)
	}
	f.fill(t)
	b := f.w.Export()
	if b.Events[2].Observation.Sequence != 2 || b.Events[3].Observation.Sequence != 1 || !bytes.Equal(b.Events[2].Raw, second) {
		t.Fatal("the durable arrival chain changed")
	}
	f.seal(t)
	f.accept(t)
	if verdict := VerifyOffline(f.w.Export(), f.trust); verdict.State != "VALID_COMPLETE" {
		t.Fatal(verdict)
	}
}
func TestRepeatedSequenceAndObservedLossRemainIncomplete(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	raw := rawEvent(216, 1)
	if err := f.w.Append(ctx, "files", raw); err != nil {
		t.Fatal(err)
	}
	if f.w.Append(ctx, "files", raw) == nil {
		t.Fatal("a repeated raw sequence passed")
	}
	g := setup(t)
	if err := g.w.FinishStream(ctx, "syscalls", FinalCounters{Sequence: 112, Lost: 7, Available: true}); err == nil {
		t.Fatal("observed loss passed")
	}
	counters := g.w.Export().Counters["syscalls"]
	if counters.Sequence != 112 || counters.Lost != 7 || !counters.Available || counters.Decisions != 0 {
		t.Fatal("the observed loss counters were discarded")
	}
	if _, err := g.w.Seal(ctx, terminal(), signer{g.node}); err == nil {
		t.Fatal("observed loss sealed complete")
	}
}

func TestFixturePurposeChangesTheSignedHeader(t *testing.T) {
	f := setup(t)
	normal := f.config.Header
	digest, err := HeaderDigest(normal)
	if err != nil {
		t.Fatal(err)
	}
	normal.FixturePurpose = lifecycle.QualificationFixturePurpose
	fixture, err := HeaderDigest(normal)
	if err != nil || fixture == digest {
		t.Fatal("the fixture purpose did not bind the audit header")
	}
	normal.FixturePurpose = "untrusted-purpose"
	if _, err = HeaderDigest(normal); err == nil {
		t.Fatal("an unknown audit purpose passed")
	}
}

func TestZeroRightsBaselineCanPrecedeTheBoundGrant(t *testing.T) {
	f := setup(t)
	c := f.config
	c.Path = filepath.Join(filepath.Dir(f.path), "baseline.jsonl")
	w, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	f.clock.now = uint64(500 * time.Millisecond)
	if err = w.Append(context.Background(), "lifecycle", []byte(`{"state":"quarantine_readback"}`)); err != nil {
		t.Fatal(err)
	}
	if err = w.AttachGrant(context.Background(), f.grant); err != nil {
		t.Fatal(err)
	}
	if len(w.Export().Events) != 1 {
		t.Fatal("the baseline evidence changed")
	}
	if err = w.Append(context.Background(), "lifecycle", []byte(`{"state":"held"}`)); err == nil {
		t.Fatal("a launch preceded the grant expiry proof")
	}
}
