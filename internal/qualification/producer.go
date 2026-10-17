// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualification

import (
	"alloyium.local/kernel-poc/internal/policy"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"sort"
	"time"
)

const MaxRawBytes = 8 << 20
const MaxBundleRawBytes = 64 << 20
const PairingBound = 100 * time.Millisecond

type Clock interface {
	Now() (time.Time, uint64, error)
}
type Inspector interface {
	Snapshot(context.Context) (Binding, error)
}
type Config struct {
	Expected       Binding
	Documents      []policy.Document
	CompilerDigest string
	ValidFor       time.Duration
	MaxEvidenceAge time.Duration
	Clock          Clock
	Inspector      Inspector
	Adapters       []Adapter
}
type Producer struct {
	config   Config
	requests []Request
}
type Gap struct {
	PolicyDigest string   `json:"policy_digest"`
	CapabilityID string   `json:"capability_id"`
	MissingCases []string `json:"missing_cases"`
}
type EvidenceRecord struct {
	AdapterID      string     `json:"adapter_id"`
	Request        Request    `json:"request"`
	Binding        Binding    `json:"binding"`
	StartedMonoNS  uint64     `json:"started_mono_ns,string"`
	FinishedMonoNS uint64     `json:"finished_mono_ns,string"`
	Raw            []byte     `json:"raw"` // Base64 preserves the exact bytes hashed by Coverage.
	Coverage       []Coverage `json:"coverage"`
}
type Bundle struct {
	Protocol           string           `json:"protocol"`
	Target             Binding          `json:"target"`
	StartedWallUnixNS  int64            `json:"started_wall_unix_ns,string"`
	FinishedWallUnixNS int64            `json:"finished_wall_unix_ns,string"`
	MaxEvidenceAgeNS   uint64           `json:"max_evidence_age_ns,string"`
	ValidForNS         uint64           `json:"valid_for_ns,string"`
	StartedMonoNS      uint64           `json:"started_mono_ns,string"`
	FinishedMonoNS     uint64           `json:"finished_mono_ns,string"`
	Records            []EvidenceRecord `json:"records"`
}

func (b Bundle) Digest() string { return digestValue("AGENTGATE_QUALIFICATION_EVIDENCE_V1", b) }

type Output struct {
	Report              policy.CapabilityReport `json:"report"`
	Evidence            Bundle                  `json:"evidence"`
	Gaps                []Gap                   `json:"gaps"`
	AdapterErrors       []string                `json:"adapter_errors"`
	Envelope            []byte                  `json:"envelope,omitempty"`
	UnavailableEnvelope []byte                  `json:"unavailable_envelope,omitempty"`
}

var hex64 = regexp.MustCompile(`^[a-f0-9]{64}$`)
var hex40 = regexp.MustCompile(`^[a-f0-9]{40}$`)
var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

func New(c Config) (*Producer, error) {
	if c.Clock == nil || c.Inspector == nil || !hex64.MatchString(c.CompilerDigest) || c.ValidFor < time.Second || c.ValidFor > 300*time.Second || c.MaxEvidenceAge < time.Second || c.MaxEvidenceAge > 300*time.Second || len(c.Documents) == 0 || len(c.Documents) > 64 || len(c.Adapters) > 32 {
		return nil, errors.New("qualification configuration or lifetime is invalid")
	}
	if err := validBinding(c.Expected, false); err != nil {
		return nil, err
	}
	if c.Expected.PolicyDigest != "" || !hex64.MatchString(c.Expected.ArtifactDigests["qualification"]) {
		return nil, errors.New("qualification requires the measured producer and complete policy set")
	}
	for _, d := range c.Documents {
		if _, err := d.Canonical(); err != nil {
			return nil, err
		}
	}
	c.Expected = owned(c.Expected)
	c.Documents = owned(c.Documents)
	requests := make([]Request, 0, len(c.Documents))
	seen := map[string]bool{}
	for _, d := range c.Documents {
		digest, err := d.Digest()
		if err != nil {
			return nil, err
		}
		if seen[digest] {
			return nil, errors.New("qualification policy repeats")
		}
		seen[digest] = true
		contracts, err := Contracts(d)
		if err != nil {
			return nil, err
		}
		for _, contract := range contracts {
			for _, name := range contract.ArtifactNames {
				if !hex64.MatchString(c.Expected.ArtifactDigests[name]) {
					return nil, fmt.Errorf("qualification artifact absent: %s", name)
				}
			}
		}
		b := owned(c.Expected)
		b.PolicyDigest = digest
		requests = append(requests, Request{b, d, contracts})
	}
	sort.Slice(requests, func(i, j int) bool { return requests[i].Binding.PolicyDigest < requests[j].Binding.PolicyDigest })
	c.Adapters = append([]Adapter{}, c.Adapters...)
	seen = map[string]bool{}
	for _, a := range c.Adapters {
		if a == nil || !safeID.MatchString(a.ID()) || seen[a.ID()] {
			return nil, errors.New("qualification adapter registry is invalid")
		}
		seen[a.ID()] = true
	}
	sort.Slice(c.Adapters, func(i, j int) bool { return c.Adapters[i].ID() < c.Adapters[j].ID() })
	return &Producer{c, requests}, nil
}

func validBinding(b Binding, policyRequired bool) error {
	if !safeID.MatchString(b.NodeID) || !safeID.MatchString(b.BootID) || !safeID.MatchString(b.Challenge) || !hex40.MatchString(b.SourceRevision) || b.SchemaDigest != policy.SchemaDigest() || b.Kernel == "" || b.Architecture != "x86_64" || !hex64.MatchString(b.BTFSHA256) || !hex64.MatchString(b.KernelConfigSHA256) || !hex64.MatchString(b.InventorySHA256) || policyRequired && !hex64.MatchString(b.PolicyDigest) {
		return errors.New("qualification target binding is invalid")
	}
	if _, err := policy.ArtifactSetDigest(b.ArtifactDigests); err != nil {
		return err
	}
	for name := range b.ArtifactDigests {
		if !safeID.MatchString(name) {
			return errors.New("qualification artifact name is invalid")
		}
	}
	return nil
}
func owned[T any](value T) T {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var result T
	if err = json.Unmarshal(raw, &result); err != nil {
		panic(err)
	}
	return result
}
func digestBytes(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func digestValue(domain string, value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return digestBytes(append([]byte(domain+"\n"), raw...))
}

func (p *Producer) measure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := p.config.Inspector.Snapshot(ctx)
	if err != nil {
		return err
	}
	if validBinding(b, false) != nil || !reflect.DeepEqual(b, p.config.Expected) {
		return errors.New("the current qualification target or artifact set changed")
	}
	return ctx.Err()
}
func (p *Producer) sample(previous time.Time, mono uint64) (time.Time, uint64, error) {
	w, n, e := p.config.Clock.Now()
	w = w.Round(0)
	previous = previous.Round(0)
	if e != nil || w.IsZero() || w.Unix() < 0 || n == 0 || !previous.IsZero() && (w.Before(previous) || n < mono || n-mono > math.MaxInt64) {
		return time.Time{}, 0, errors.New("qualification clock is unavailable or moved backwards")
	}
	if !previous.IsZero() {
		wall := w.Sub(previous)
		delta := time.Duration(n - mono)
		difference := wall - delta
		if difference < 0 {
			difference = -difference
		}
		if difference > PairingBound {
			return time.Time{}, 0, errors.New("qualification wall and monotonic clocks differ")
		}
	}
	return w, n, nil
}

// Produce signs only after every contract for every approved policy is complete.
// Diagnostic outputs retain all unavailable states when any obligation is missing.
type runState struct {
	out                 Output
	covered             map[string]map[string]bool
	receipts            map[string][]string
	total               int
	startWall, lastWall time.Time
	start, last         uint64
}

func (p *Producer) Produce(ctx context.Context, key ed25519.PrivateKey) (Output, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Output{}, errors.New("qualification signer is invalid")
	}
	wall, mono, err := p.sample(time.Time{}, 0)
	if err != nil {
		return Output{}, err
	}
	if err = p.measure(ctx); err != nil {
		return Output{}, err
	}
	state := runState{covered: map[string]map[string]bool{}, receipts: map[string][]string{}, startWall: wall, lastWall: wall, start: mono, last: mono}
	state.out.Evidence = Bundle{Protocol: Version, Target: owned(p.config.Expected), StartedWallUnixNS: wall.UnixNano(), MaxEvidenceAgeNS: uint64(p.config.MaxEvidenceAge), ValidForNS: uint64(p.config.ValidFor), StartedMonoNS: mono, Records: []EvidenceRecord{}}
	state.out.AdapterErrors = []string{}
	for _, request := range p.requests {
		for _, adapter := range p.config.Adapters {
			if err = p.collect(ctx, request, adapter, &state); err != nil {
				return state.out, err
			}
		}
	}
	return p.finish(ctx, &state, key)
}

func (p *Producer) collect(ctx context.Context, request Request, adapter Adapter, state *runState) error {
	if err := p.measure(ctx); err != nil {
		return err
	}
	result, runErr := runAdapter(ctx, adapter, owned(request))
	nowWall, now, err := p.sample(state.lastWall, state.last)
	if err != nil {
		return err
	}
	state.lastWall, state.last = nowWall, now
	if now-state.start > uint64(p.config.MaxEvidenceAge) {
		return errors.New("qualification behavior evidence exceeded its age bound")
	}
	if runErr != nil {
		state.out.AdapterErrors = append(state.out.AdapterErrors, adapter.ID()+": "+runErr.Error())
		return nil
	}
	if err = checkResult(request, result, state.start, now, state.total); err != nil {
		return err
	}
	result = copyResult(result)
	coverage, err := verifyAdapter(adapter, owned(request), copyResult(result))
	if err != nil {
		state.out.AdapterErrors = append(state.out.AdapterErrors, adapter.ID()+": "+err.Error())
		return nil
	}
	if err = recordCoverage(request, coverage, digestBytes(result.Raw), state.covered, state.receipts); err != nil {
		return err
	}
	state.total += len(result.Raw)
	state.out.Evidence.Records = append(state.out.Evidence.Records, EvidenceRecord{adapter.ID(), owned(request), owned(result.Binding), result.StartedMonoNS, result.FinishedMonoNS, append([]byte{}, result.Raw...), owned(coverage)})
	return nil
}

func checkResult(request Request, result Result, start, now uint64, total int) error {
	if !reflect.DeepEqual(result.Binding, request.Binding) || result.StartedMonoNS < start || result.FinishedMonoNS < result.StartedMonoNS || result.FinishedMonoNS > now || len(result.Raw) == 0 || len(result.Raw) > MaxRawBytes || total+len(result.Raw) > MaxBundleRawBytes || checkRaw(result.Raw) != nil {
		return errors.New("qualification adapter result binding, time or raw evidence differs")
	}
	return nil
}

func (p *Producer) finish(ctx context.Context, state *runState, key ed25519.PrivateKey) (Output, error) {
	if err := p.measure(ctx); err != nil {
		return state.out, err
	}
	wall, mono, err := p.sample(state.lastWall, state.last)
	if err != nil {
		return state.out, err
	}
	if mono-state.start > uint64(p.config.MaxEvidenceAge) {
		return state.out, errors.New("qualification behavior evidence is stale")
	}
	out := state.out
	out.Evidence.FinishedMonoNS = mono
	out.Evidence.FinishedWallUnixNS = wall.UnixNano()
	out.Gaps = missing(p.requests, state.covered)
	complete := len(out.Gaps) == 0 && len(out.AdapterErrors) == 0
	out.Report = p.report(wall, state.startWall, out.Evidence, state.receipts, complete)
	if out.Report.ValidUntil <= wall.Unix() {
		return out, errors.New("qualification evidence has no remaining validity")
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if !complete {
		out.UnavailableEnvelope, err = policy.SignReport(out.Report, key)
		return out, errors.Join(errors.New("qualification lacks complete required behavior evidence"), err)
	}
	out.Envelope, err = policy.SignReport(out.Report, key)
	return out, err
}

func copyResult(r Result) Result {
	r.Binding = owned(r.Binding)
	r.Raw = append(json.RawMessage{}, r.Raw...)
	return r
}

func runAdapter(ctx context.Context, a Adapter, r Request) (result Result, err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("qualification adapter panicked")
		}
	}()
	return a.Run(ctx, r)
}
func verifyAdapter(a Adapter, r Request, result Result) (coverage []Coverage, err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("qualification verifier panicked")
		}
	}()
	return a.Verify(r, result)
}

func recordCoverage(r Request, coverage []Coverage, receipt string, covered map[string]map[string]bool, receipts map[string][]string) error {
	contracts := map[string]Contract{}
	for _, c := range r.Contracts {
		contracts[c.CapabilityID] = c
	}
	ids := map[string]bool{}
	for _, v := range coverage {
		c, ok := contracts[v.CapabilityID]
		if !ok || ids[v.CapabilityID] || v.ContractVersion != c.Version || v.ReceiptSHA256 != receipt || len(v.Cases) == 0 {
			return errors.New("qualification verifier returned unbound or unknown coverage")
		}
		ids[v.CapabilityID] = true
		allowed := map[string]bool{}
		for _, name := range c.Cases {
			allowed[name] = true
		}
		seen := map[string]bool{}
		key := r.Binding.PolicyDigest + "/" + v.CapabilityID
		if covered[key] == nil {
			covered[key] = map[string]bool{}
		}
		for _, name := range v.Cases {
			if !allowed[name] || seen[name] {
				return errors.New("qualification case is unknown or repeated")
			}
			seen[name] = true
			covered[key][name] = true
		}
		receipts[v.CapabilityID] = append(receipts[v.CapabilityID], key+"/"+receipt)
	}
	return nil
}
func missing(requests []Request, covered map[string]map[string]bool) []Gap {
	gaps := []Gap{}
	for _, r := range requests {
		for _, c := range r.Contracts {
			absent := []string{}
			for _, name := range c.Cases {
				if !covered[r.Binding.PolicyDigest+"/"+c.CapabilityID][name] {
					absent = append(absent, name)
				}
			}
			if len(absent) > 0 {
				gaps = append(gaps, Gap{r.Binding.PolicyDigest, c.CapabilityID, absent})
			}
		}
	}
	return gaps
}
func (p *Producer) report(now, start time.Time, bundle Bundle, receipts map[string][]string, complete bool) policy.CapabilityReport {
	b := p.config.Expected
	validUntil := now.Add(p.config.ValidFor)
	if limit := start.Add(p.config.MaxEvidenceAge - PairingBound); limit.Before(validUntil) {
		validUntil = limit
	}
	r := policy.CapabilityReport{SchemaVersion: policy.CapabilityVersion, Node: b.NodeID, Boot: b.BootID, Challenge: b.Challenge, Kernel: b.Kernel, Architecture: b.Architecture, SourceRevision: b.SourceRevision, ArtifactSHA256: b.ArtifactDigests["qualification"], PolicySchemaDigest: b.SchemaDigest, InventorySHA256: b.InventorySHA256, BTFSHA256: b.BTFSHA256, KernelConfigSHA256: b.KernelConfigSHA256, IssuedAt: now.Unix(), ValidUntil: validUntil.Unix(), Capabilities: map[string]policy.Capability{}, Probes: []policy.HookProbe{}}
	policies := []string{}
	ids := map[string]bool{}
	for _, request := range p.requests {
		policies = append(policies, request.Binding.PolicyDigest)
		for _, c := range request.Contracts {
			ids[c.CapabilityID] = true
			state := policy.Capability{State: "unavailable", Mechanisms: []string{}}
			if complete {
				values := append([]string{}, receipts[c.CapabilityID]...)
				sort.Strings(values)
				state = policy.Capability{State: "enforced", Mechanisms: append([]string{}, c.Mechanisms...), ReceiptSHA256: digestValue("AGENTGATE_QUALIFICATION_CAPABILITY_V1", values)}
			}
			r.Capabilities[c.CapabilityID] = state
		}
	}
	if complete {
		required := []string{}
		for id := range ids {
			required = append(required, id)
		}
		sort.Strings(required)
		artifactDigest, _ := policy.ArtifactSetDigest(b.ArtifactDigests)
		r.Qualification = &policy.QualificationScope{Protocol: policy.QualificationScopeVersion, ProducerSHA256: b.ArtifactDigests["qualification"], CompilerSHA256: p.config.CompilerDigest, ArtifactsSHA256: artifactDigest, PolicyDigests: policies, RequiredCapabilities: required, ContractsSHA256: digestValue("AGENTGATE_QUALIFICATION_CONTRACTS_V1", p.requests), EvidenceSHA256: bundle.Digest()}
	}
	return r
}
