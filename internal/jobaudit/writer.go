// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobaudit

import (
	"alloyium.local/kernel-poc/internal/jobgrant"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"reflect"
	"sync"
)

var ErrIncomplete = errors.New("the full audit evidence is incomplete")

type diskRecord struct {
	Kind      string             `json:"kind"`
	Header    *Header            `json:"header,omitempty"`
	Grant     *jobgrant.Envelope `json:"grant,omitempty"`
	Event     *Event             `json:"event,omitempty"`
	Stream    string             `json:"stream,omitempty"`
	Counters  *FinalCounters     `json:"counters,omitempty"`
	Seal      *NodeSeal          `json:"node_seal,omitempty"`
	Authority *AuthorityReceipt  `json:"authority_receipt,omitempty"`
}
type Writer struct {
	mu            sync.Mutex
	config        Config
	file          *os.File
	bundle        Bundle
	last          map[string]uint64
	seen          map[string]map[uint64]bool
	chain         string
	bytes         int64
	failed        bool
	cutoff        uint64
	boundAt       uint64
	filesVerified bool
	filesAt       uint64
}

func Open(c Config) (*Writer, error) {
	digest, err := HeaderDigest(c.Header)
	if err != nil || c.Clock == nil || c.MaxRecords <= 0 || c.MaxRecords > 100000 || c.MaxBytes <= 0 || c.MaxBytes > 256<<20 {
		return nil, errors.New("the audit requires a valid header, clock and bounded storage")
	}
	if !separateTrust(c.NodeKeys, c.AuthorityKeys) {
		return nil, errors.New("node and authority signing trust must use separate keys")
	}
	for _, stream := range c.Header.RequiredStreams {
		if c.Registry[stream.Name+"/"+stream.Version] == nil {
			return nil, errors.New("a mandatory resource decoder is unavailable")
		}
	}
	c.Header = clone(c.Header)
	c.Registry = copyRegistry(c.Registry)
	c.AuthorityKeys = copyKeys(c.AuthorityKeys)
	c.NodeKeys = copyKeys(c.NodeKeys)
	raw, err := c.Document.Canonical()
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &c.Document); err != nil {
		return nil, err
	}
	file, parent, err := openProtected(c.Path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	w := &Writer{config: c, file: file, bundle: Bundle{Header: c.Header, Events: []Event{}, Counters: map[string]FinalCounters{}}, last: map[string]uint64{}, seen: map[string]map[uint64]bool{}, chain: digest}
	if err = w.persist(diskRecord{Kind: "header", Header: &c.Header}); err != nil {
		file.Close()
		return nil, err
	}
	if err = unix.Fsync(parent); err != nil {
		file.Close()
		return nil, errors.New("the audit directory entry is not durable")
	}
	return w, nil
}
func copyRegistry(in Registry) Registry {
	out := Registry{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
func (w *Writer) persist(record diskRecord) error {
	if w.failed || w.file == nil {
		return errors.New("the audit writer is unavailable")
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if int64(len(raw)) > w.config.MaxBytes-w.bytes {
		w.failed = true
		return errors.New("the audit byte limit is exhausted")
	}
	written, err := w.file.Write(raw)
	if err != nil || written != len(raw) {
		w.failed = true
		return errors.New("the audit record write is incomplete")
	}
	if err = w.file.Sync(); err != nil {
		w.failed = true
		return errors.New("the audit record is not durable")
	}
	w.bytes += int64(len(raw))
	return nil
}
func (w *Writer) AttachGrant(ctx context.Context, e jobgrant.Envelope) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.bundle.Grant != nil || w.bundle.Seal != nil {
		return errors.New("the audit grant is already fixed")
	}
	if err := grantMatches(w.bundle.Header, e, w.trust()); err != nil {
		return err
	}
	for _, event := range w.bundle.Events {
		decoded, err := w.config.Registry[event.Stream+"/"+event.Version](event.Raw)
		if err != nil || event.Kind != "control" || !preparationControl(decoded.ControlPhase) {
			return errors.New("the audit grant follows a launch or stop event")
		}
	}
	e = clone(e)
	if err := w.persist(diskRecord{Kind: "grant", Grant: &e}); err != nil {
		return err
	}
	w.bundle.Grant = &e
	return nil
}
func (w *Writer) trust() Trust {
	return Trust{w.config.NodeKeys, w.config.AuthorityKeys, w.config.Registry, w.config.Document}
}
func (w *Writer) stream(name string) (Stream, bool) {
	for _, s := range w.bundle.Header.RequiredStreams {
		if s.Name == name {
			return s, true
		}
	}
	return Stream{}, false
}
func (w *Writer) Append(ctx context.Context, name string, raw []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	s, ok := w.stream(name)
	if !ok || w.bundle.Seal != nil || len(w.bundle.Events) >= w.config.MaxRecords || len(raw) == 0 || len(raw) > 65536 {
		return errors.New("the audit event stream, state or byte bound is invalid")
	}
	if _, finished := w.bundle.Counters[name]; finished {
		return errors.New("the audit stream is already final")
	}
	var observation Observation
	var controlPhase string
	if s.Kind == "resource" || s.Kind == "observation" {
		if w.cutoff == 0 {
			return w.reject("the grant expiry bound is missing before resource activity")
		}
		if !w.filesVerified {
			return w.reject("the runtime file proof is missing before resource activity")
		}
		format := resourceFormats[name]
		if s.Kind == "observation" {
			format = observationFormat(name, s.Version)
		}
		if len(raw) != format.Bytes {
			return w.reject("the resource event byte size differs")
		}
		var err error
		observation, err = w.config.Registry[name+"/"+s.Version](append([]byte{}, raw...))
		if err != nil {
			w.failed = true
			return err
		}
		b := w.bundle.Header.Binding
		if observation.GrantExpiry != nil || observation.CgroupID != b.CgroupID || observation.Sequence == 0 || observation.Sequence > uint64(w.config.MaxRecords) || w.seen[name][observation.Sequence] || observation.TimestampNS < w.boundAt || observation.TimestampNS < w.filesAt || !validProvenance(s.Kind, observation, b.Generation, w.cutoff) {
			return w.reject("the raw resource event binding, sequence or deadline differs")
		}
	} else {
		now, err := w.config.Clock.NowNS()
		if err != nil || now < w.bundle.Header.CreatedMonoNS {
			return w.reject("the control audit clock is unavailable")
		}
		if !json.Valid(raw) {
			return w.reject("the node control event is invalid")
		}
		decoded, err := w.config.Registry[name+"/"+s.Version](append([]byte{}, raw...))
		if err != nil || decoded.Decision != nil || decoded.BindingState != 0 || decoded.DNSLeaseRevision != 0 || decoded.CgroupID != w.bundle.Header.Binding.CgroupID || decoded.Generation != w.bundle.Header.Binding.Generation {
			return w.reject("the node control event binding differs")
		}
		if decoded.GrantExpiry != nil {
			if w.cutoff != 0 || decoded.ControlPhase != "grant_expiry_bound" || validGrantExpiry(*decoded.GrantExpiry, w.bundle.Header, w.bundle.Grant, now) != nil {
				return w.reject("the grant expiry control bound differs or repeats")
			}
			for _, prior := range w.bundle.Events {
				if prior.Observation.TimestampNS > decoded.GrantExpiry.MonoSampleNS {
					return w.reject("the grant expiry samples precede prior activity")
				}
			}
		} else if w.bundle.Grant != nil && w.cutoff == 0 && !preparationControl(decoded.ControlPhase) {
			return w.reject("the grant expiry bound is missing before launch control")
		}
		if decoded.ControlPhase == "runtime_files_verified" {
			if w.bundle.Grant == nil || w.cutoff == 0 || now >= w.cutoff || w.filesVerified {
				return w.reject("the runtime file proof is unbound, expired or repeated")
			}
		} else if decoded.GrantExpiry == nil && !preparationControl(decoded.ControlPhase) && !w.filesVerified {
			return w.reject("the runtime file proof is missing before launch control")
		}
		controlPhase = decoded.ControlPhase
		observation = Observation{GrantExpiry: clone(decoded.GrantExpiry), CgroupID: w.bundle.Header.Binding.CgroupID, Generation: w.bundle.Header.Binding.Generation, Sequence: w.last[name] + 1, TimestampNS: now}
	}
	event := Event{Index: uint64(len(w.bundle.Events)) + 1, Stream: name, Kind: s.Kind, Version: s.Version, Observation: observation, Raw: append([]byte{}, raw...), PreviousDigest: w.chain}
	event.Digest = eventDigest(event)
	if err := w.persist(diskRecord{Kind: "event", Event: &event}); err != nil {
		return err
	}
	w.bundle.Events = append(w.bundle.Events, event)
	if controlPhase == "runtime_files_verified" {
		w.filesVerified = true
		w.filesAt = event.Observation.TimestampNS
	}
	if observation.GrantExpiry != nil {
		w.cutoff, w.boundAt = observation.GrantExpiry.KernelDeadlineNS, observation.TimestampNS
	}
	if w.seen[name] == nil {
		w.seen[name] = map[uint64]bool{}
	}
	w.seen[name][observation.Sequence] = true
	if observation.Sequence > w.last[name] {
		w.last[name] = observation.Sequence
	}
	w.chain = event.Digest
	return nil
}
func (w *Writer) FinishStream(ctx context.Context, name string, c FinalCounters) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	s, ok := w.stream(name)
	if !ok || w.bundle.Seal != nil {
		return errors.New("the audit stream is unknown or sealed")
	}
	if _, exists := w.bundle.Counters[name]; exists {
		return errors.New("the audit stream counters are already final")
	}
	invalid := c.Available && (c.Sequence != w.last[name] || uint64(len(w.seen[name])) != c.Sequence || c.Lost != 0 || (s.Kind == "resource" && c.Decisions != c.Sequence) || (s.Kind != "resource" && c.Decisions != 0))
	if err := w.persist(diskRecord{Kind: "counters", Stream: name, Counters: &c}); err != nil {
		return err
	}
	w.bundle.Counters[name] = c
	if invalid || !c.Available {
		w.failed = true
		return ErrIncomplete
	}
	return nil
}
func (w *Writer) Seal(ctx context.Context, t Terminal, signer Signer) (NodeSeal, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if signer == nil || w.bundle.Grant == nil || w.bundle.Seal != nil || w.failed || !w.filesVerified {
		return NodeSeal{}, ErrIncomplete
	}
	if !complete(w.bundle, t) {
		return NodeSeal{}, ErrIncomplete
	}
	now, err := w.config.Clock.NowNS()
	if err != nil || now < w.bundle.Header.CreatedMonoNS {
		return NodeSeal{}, errors.New("the node seal clock is unavailable")
	}
	s := NodeSeal{Protocol: "agentgate.full-job-node-seal.v1", NodeID: w.bundle.Header.Binding.NodeID, HeaderDigest: mustHeaderDigest(w.bundle.Header), GrantDigest: jobgrant.Digest(*w.bundle.Grant), EventsDigest: w.chain, CountersDigest: hash("AGENTGATE_JOB_AUDIT_COUNTERS_V1\n", w.bundle.Counters), Terminal: t, SealedMonoNS: now}
	id := signer.KeyID()
	if !identifier.MatchString(id) {
		return NodeSeal{}, errors.New("the node signer is unavailable")
	}
	s.KeyID = id
	signature, err := signer.Sign(ctx, sealBytes(s))
	if err != nil || signer.KeyID() != id {
		return NodeSeal{}, errors.New("the node signer identity changed")
	}
	s.Signature = base64.RawURLEncoding.EncodeToString(signature)
	if !validSignature(w.config.NodeKeys[s.NodeID+"/"+s.KeyID], sealBytes(s), s.Signature) {
		return NodeSeal{}, errors.New("the node seal differs from pinned node trust")
	}
	if err = w.persist(diskRecord{Kind: "seal", Seal: &s}); err != nil {
		return NodeSeal{}, err
	}
	w.bundle.Seal = &s
	return clone(s), nil
}
func (w *Writer) AttachAuthority(ctx context.Context, r AuthorityReceipt) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.bundle.Seal == nil || w.bundle.Authority != nil {
		return ErrIncomplete
	}
	next := clone(w.bundle)
	next.Authority = &r
	if v := VerifyOffline(next, w.trust()); v.State != "VALID_COMPLETE" {
		return errors.New("the authority receipt is invalid: " + v.Reason)
	}
	r = clone(r)
	if err := w.persist(diskRecord{Kind: "authority", Authority: &r}); err != nil {
		return err
	}
	w.bundle.Authority = &r
	return nil
}
func (w *Writer) Export() Bundle { w.mu.Lock(); defer w.mu.Unlock(); return clone(w.bundle) }
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}
func mustHeaderDigest(h Header) string { d, _ := HeaderDigest(h); return d }
func same(a, b any) bool               { return reflect.DeepEqual(a, b) }

func copyKeys(in map[string]ed25519.PublicKey) map[string]ed25519.PublicKey {
	out := map[string]ed25519.PublicKey{}
	for id, key := range in {
		out[id] = append(ed25519.PublicKey{}, key...)
	}
	return out
}

func (w *Writer) reject(message string) error { w.failed = true; return errors.New(message) }
func validProvenance(kind string, o Observation, generation, deadline uint64) bool {
	if kind == "resource" {
		return o.Generation == generation && o.BindingState == 0 && o.Decision != nil && (o.TimestampNS < deadline || !*o.Decision)
	}
	if o.Decision != nil {
		return false
	}
	switch o.BindingState {
	case 0:
		return o.Generation == generation && o.TimestampNS < deadline
	case 1:
		return o.Generation == 0
	case 2:
		return o.Generation == generation
	case 3:
		return true
	}
	return false
}
