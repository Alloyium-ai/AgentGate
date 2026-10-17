// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodedns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/dnslease"
	"alloyium.local/kernel-poc/internal/dnslease/fixture"
	"alloyium.local/kernel-poc/internal/policy"
	"golang.org/x/net/dns/dnsmessage"
)

type fixtureResolver struct {
	mu        sync.Mutex
	questions []string
	fail      bool
	panicNext bool
	cancel    context.CancelFunc
	evidence  dnslease.ResolverEvidence
}

func newResolver() *fixtureResolver {
	return &fixtureResolver{evidence: dnslease.ResolverEvidence{Transport: "tls1.3", Address: "127.0.0.1:853", ServerName: "resolver.example.test", RootsSHA256: strings.Repeat("a", 64), TimeoutMS: 1000}}
}
func (r *fixtureResolver) Evidence() dnslease.ResolverEvidence {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.evidence
}
func (r *fixtureResolver) Exchange(ctx context.Context, wire []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.panicNext {
		r.panicNext = false
		panic("owned resolver panic")
	}
	var message dnsmessage.Message
	if err := message.Unpack(wire); err != nil {
		return nil, err
	}
	q := message.Questions[0]
	r.questions = append(r.questions, fmt.Sprintf("%s/%d", q.Name.String(), q.Type))
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
		return nil, context.Canceled
	}
	if r.fail {
		r.fail = false
		return nil, errors.New("owned resolver failure")
	}
	return answer(wire)
}
func answer(wire []byte) ([]byte, error) {
	var q dnsmessage.Message
	if err := q.Unpack(wire); err != nil {
		return nil, err
	}
	question := q.Questions[0]
	resource := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 4}}
	if question.Type == dnsmessage.TypeA {
		resource.Body = &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}
	} else {
		resource.Body = &dnsmessage.AAAAResource{AAAA: [16]byte{15: 1}}
	}
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired, RecursionAvailable: true}, Questions: q.Questions, Answers: []dnsmessage.Resource{resource}}
	return response.Pack()
}
func source() policy.Network {
	return policy.Network{Default: "deny", DNS: policy.DNS{ResolverProfile: "trusted-forwarder.v1", CNAME: "validate-chain", Expiry: "remove-expired-authorization"}, Rules: []policy.NetworkRule{
		{ID: "a4", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "hostname", Value: "a.example.test"}, PortFrom: 443, PortTo: 443, Effect: "allow"},
		{ID: "a4-duplicate", Family: "ipv4", Protocol: "udp", Destination: policy.Destination{Kind: "hostname", Value: "a.example.test"}, PortFrom: 444, PortTo: 444, Effect: "allow"},
		{ID: "a6", Family: "ipv6", Protocol: "tcp", Destination: policy.Destination{Kind: "hostname", Value: "a.example.test"}, PortFrom: 443, PortTo: 443, Effect: "allow"},
		{ID: "deny-z", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "hostname", Value: "z.example.test"}, PortFrom: 443, PortTo: 443, Effect: "deny"},
	}}
}
func setup(t *testing.T) (*Coordinator, *fixtureResolver, *atomic.Uint64) {
	t.Helper()
	now := &atomic.Uint64{}
	now.Store(uint64(time.Second))
	r := newResolver()
	c, err := New(Config{Binding: dnslease.Binding{JobID: "owned-node-dns", DomainID: 42, Generation: 7, DeadlineNS: uint64(30 * time.Second), PolicySHA256: strings.Repeat("b", 64)}, Network: source(), Resolver: r, Now: func() (uint64, error) { return now.Load(), nil }})
	if err != nil {
		t.Fatal(err)
	}
	c.wait = func(ctx context.Context, delay time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		now.Add(uint64(delay))
		return nil
	}
	return c, r, now
}

type publisher struct {
	c                                *Coordinator
	now                              *atomic.Uint64
	activated, stopped               int
	last                             uint64
	values                           []dnslease.Snapshot
	reason                           string
	activateErr, publishErr, stopErr error
	after                            func(dnslease.Snapshot)
	badContext                       bool
}

func (p *publisher) Activate(ctx context.Context, b dnslease.Binding, s dnslease.Snapshot) error {
	p.activated++
	if err := s.Check(b, p.c.networkDigest, p.c.evidence, 0, p.now.Load()); err != nil {
		return err
	}
	p.last = s.Revision()
	return p.activateErr
}
func (p *publisher) Publish(ctx context.Context, b dnslease.Binding, s dnslease.Snapshot) error {
	if ctx.Err() != nil {
		p.badContext = true
	}
	if err := s.Check(b, p.c.networkDigest, p.c.evidence, p.last, p.now.Load()); err != nil {
		return err
	}
	if p.publishErr != nil {
		return p.publishErr
	}
	p.last = s.Revision()
	p.values = append(p.values, s)
	if p.after != nil {
		p.after(s)
	}
	return nil
}
func (p *publisher) Stop(ctx context.Context, b dnslease.Binding, reason string) error {
	p.stopped++
	p.reason = reason
	if ctx.Err() != nil {
		p.badContext = true
	}
	if b != p.c.binding {
		return errors.New("wrong stop binding")
	}
	return p.stopErr
}
func resolve(t *testing.T, c *Coordinator) dnslease.Snapshot {
	t.Helper()
	s, err := c.ResolveAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestResolveAllDeduplicatesFamiliesAndIncludesDenyHostnames(t *testing.T) {
	c, r, _ := setup(t)
	snapshot := resolve(t, c)
	if snapshot.Plan().Count != 4 || len(snapshot.Records()) != 4 {
		t.Fatal("complete lease set missing")
	}
	want := []string{"a.example.test./1", "a.example.test./28", "z.example.test./1"}
	if fmt.Sprint(r.questions) != fmt.Sprint(want) {
		t.Fatal("wrong declared questions", r.questions)
	}
	if _, err := c.ResolveAll(context.Background()); err == nil {
		t.Fatal("initial resolution repeated")
	}
}
func TestResolveAllFailureReturnsBoundZeroSnapshotAndForbidsActivation(t *testing.T) {
	c, r, now := setup(t)
	r.fail = true
	s, err := c.ResolveAll(context.Background())
	if err == nil || s.Plan().Count != 0 {
		t.Fatal("partial set retained authorization")
	}
	if err = s.Check(c.binding, c.networkDigest, c.evidence, 0, now.Load()); err != nil {
		t.Fatal("denied snapshot lost binding", err)
	}
	p := &publisher{c: c, now: now}
	if err = c.Run(context.Background(), p, s); err == nil || p.activated != 0 || p.stopped != 1 {
		t.Fatal("incomplete initial set activated")
	}
}
func TestRefreshPublishesEachDenyAndRecoversCompleteSet(t *testing.T) {
	c, r, now := setup(t)
	initial := resolve(t, c)
	r.fail = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &publisher{c: c, now: now}
	denied, restored := false, false
	p.after = func(s dnslease.Snapshot) {
		if s.Plan().Count == 0 {
			denied = true
		}
		if denied && s.Plan().Count == 4 {
			restored = true
			cancel()
		}
	}
	err := c.Run(ctx, p, initial)
	if !errors.Is(err, context.Canceled) || !denied || !restored || p.stopped != 1 || p.badContext {
		t.Fatal("refresh custody differs", err, denied, restored, p.stopped)
	}
	if len(p.values) < 4 {
		t.Fatal("changed snapshots were skipped")
	}
	if r.questions[3] != "a.example.test./1" {
		t.Fatal("refresh changed declared questions")
	}
}
func TestCancellationDuringExchangePublishesDenyThenStops(t *testing.T) {
	c, r, now := setup(t)
	initial := resolve(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	p := &publisher{c: c, now: now}
	err := c.Run(ctx, p, initial)
	if !errors.Is(err, context.Canceled) || len(p.values) != 1 || p.values[0].Plan().Count != 0 || p.stopped != 1 || p.badContext {
		t.Fatal("cancellation left a publication or stop gap", err)
	}
}
func TestPublicationAndActivationFailuresStopDomain(t *testing.T) {
	for _, mode := range []string{"activate", "publish"} {
		t.Run(mode, func(t *testing.T) {
			c, _, now := setup(t)
			initial := resolve(t, c)
			failure := errors.New("owned map readback failure")
			p := &publisher{c: c, now: now}
			if mode == "activate" {
				p.activateErr = failure
			} else {
				p.publishErr = failure
			}
			err := c.Run(context.Background(), p, initial)
			if !errors.Is(err, failure) || p.stopped != 1 {
				t.Fatal("map failure did not stop", err)
			}
		})
	}
}
func TestClockAndWaitFailureStopWithoutRefresh(t *testing.T) {
	for _, mode := range []string{"backwards", "stalled", "wait-error", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			c, r, now := setup(t)
			initial := resolve(t, c)
			c.wait = func(context.Context, time.Duration) error {
				switch mode {
				case "backwards":
					now.Store(now.Load() - 1)
				case "wait-error":
					return errors.New("owned timer failure")
				case "deadline":
					now.Store(c.binding.DeadlineNS)
				}
				return nil
			}
			p := &publisher{c: c, now: now}
			err := c.Run(context.Background(), p, initial)
			if err == nil || p.stopped != 1 || len(r.questions) != 3 {
				t.Fatal("clock/wait failure did not stop", err)
			}
		})
	}
}

type fatalManager struct{ manager }

func (f fatalManager) Forward(context.Context, dnslease.Binding, []byte) dnslease.Outcome {
	return dnslease.Outcome{Fatal: true, Error: "lease revision exhausted; stop the domain and rebind"}
}
func TestFatalRevisionAndResolverPanicStop(t *testing.T) {
	for _, mode := range []string{"revision", "panic", "evidence"} {
		t.Run(mode, func(t *testing.T) {
			c, r, now := setup(t)
			initial := resolve(t, c)
			switch mode {
			case "revision":
				c.manager = fatalManager{c.manager}
			case "panic":
				r.panicNext = true
			case "evidence":
				r.evidence.RootsSHA256 = strings.Repeat("c", 64)
			}
			p := &publisher{c: c, now: now}
			err := c.Run(context.Background(), p, initial)
			if err == nil || p.stopped != 1 {
				t.Fatal("fatal DNS condition did not stop", err)
			}
		})
	}
}
func TestStopFailureAndForeignInitialSnapshotRemainErrors(t *testing.T) {
	c, _, now := setup(t)
	resolve(t, c)
	binding := c.binding
	binding.JobID = "foreign"
	other, newErr := New(Config{Binding: binding, Network: source(), Resolver: newResolver(), Now: func() (uint64, error) { return now.Load(), nil }})
	if newErr != nil {
		t.Fatal(newErr)
	}
	foreign := resolve(t, other)
	stopFailure := errors.New("owned stop failed")
	p := &publisher{c: c, now: now, stopErr: stopFailure}
	err := c.Run(context.Background(), p, foreign)
	if !errors.Is(err, stopFailure) || p.activated != 0 || p.stopped != 1 {
		t.Fatal("foreign snapshot or stop error accepted", err)
	}
}
func TestOwnedTLSResolverCompletesPrelaunchSet(t *testing.T) {
	server, err := fixture.Start(answer)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	tls, err := dnslease.NewTLSResolver(server.Config(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Second)
	c, err := New(Config{Binding: dnslease.Binding{JobID: "owned-tls-node-dns", DomainID: 9, Generation: 2, DeadlineNS: uint64(20 * time.Second), PolicySHA256: strings.Repeat("d", 64)}, Network: source(), Resolver: tls, Now: func() (uint64, error) { return now, nil }})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := resolve(t, c)
	if snapshot.Plan().Count != 4 || server.Queries() != 3 || snapshot.Resolver() != tls.Evidence() {
		t.Fatal("TLS prelaunch evidence differs")
	}
}
