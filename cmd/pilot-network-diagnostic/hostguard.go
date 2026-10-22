// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"sync"
	"time"

	"alloyium.local/kernel-poc/internal/fsrules"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/pocpolicy"
	"alloyium.local/kernel-poc/internal/processrules"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// The file hook reports every read and write, so the guard keeps compact,
// complete evidence instead of every record: counts per operation, a digest of
// the whole raw stream, and the first denials with their paths.
const maxDenials = 2000
const hostRingBytes = 16 << 20

type opCount struct {
	Allowed uint64 `json:"allowed"`
	Denied  uint64 `json:"denied"`
}
type denial struct {
	Sequence  uint64 `json:"sequence"`
	PID       uint32 `json:"pid"`
	Operation string `json:"operation"`
	Rule      uint32 `json:"rule"`
	Reason    uint32 `json:"reason"`
	Path      string `json:"path,omitempty"`
	Target    uint32 `json:"target_pid,omitempty"`
}
type ringEvidence struct {
	Object           string             `json:"object"`
	ObjectSHA256     string             `json:"object_sha256"`
	PlanDigest       string             `json:"plan_digest"`
	Hooks            []string           `json:"hooks"`
	Decisions        uint64             `json:"decisions"`
	Lost             uint64             `json:"lost"`
	Observed         uint64             `json:"observed"`
	RawSHA256        string             `json:"raw_sha256"`
	Operations       map[string]opCount `json:"operations"`
	Denials          []denial           `json:"denials"`
	DenialsTruncated bool               `json:"denials_truncated"`
	Complete         bool               `json:"complete"`
}

// ringTracker accumulates one ring's evidence. Only its embedded snapshot is
// ever serialized, and only after the reader goroutine has stopped.
type ringTracker struct {
	ringEvidence
	mu      sync.Mutex
	raw     hash.Hash
	size    int
	observe func(raw []byte) (operation string, allowed bool, d denial, err error)
	failure error
}
type hostEvidence struct {
	Filesystem ringEvidence `json:"filesystem"`
	Process    ringEvidence `json:"process"`
	Complete   bool         `json:"complete"`
}

type fsEvent struct {
	Sequence, Generation, Domain, MonoNS       uint64
	PID, UID, Operation, Allowed, Rule, Reason uint32
	Path                                       [160]byte
}

func fsOperationName(index uint32) string {
	names := fsrules.Operations()
	if int(index) < len(names) {
		return names[index]
	}
	return fmt.Sprintf("internal-%d", index)
}

func cString(raw []byte) string {
	if end := bytes.IndexByte(raw, 0); end >= 0 {
		raw = raw[:end]
	}
	return string(raw)
}

func newEvidence(object string, digest [32]byte, plan string, hooks []string, size int,
	observe func([]byte) (string, bool, denial, error)) *ringTracker {
	return &ringTracker{ringEvidence: ringEvidence{Object: filepath.Base(object), ObjectSHA256: hex.EncodeToString(digest[:]), PlanDigest: plan,
		Hooks: hooks, Operations: map[string]opCount{}, Denials: []denial{}}, raw: sha256.New(), size: size, observe: observe}
}

// consume records one raw event. Any malformed record makes the evidence incomplete.
func (e *ringTracker) consume(raw []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(raw) != e.size {
		e.failure = errors.New("host event ABI differs")
		return
	}
	e.Observed++
	e.raw.Write(raw)
	operation, allowed, d, err := e.observe(raw)
	if err != nil {
		e.failure = err
		return
	}
	count := e.Operations[operation]
	if allowed {
		count.Allowed++
	} else {
		count.Denied++
		if len(e.Denials) < maxDenials {
			e.Denials = append(e.Denials, d)
		} else {
			e.DenialsTruncated = true
		}
	}
	e.Operations[operation] = count
}

type hostGuard struct {
	cgroup      string
	fs, process *ringTracker
	collections []*ebpf.Collection
	links       []link.Link
	readers     []*ringbuf.Reader
	counters    []*ebpf.Map
	done        sync.WaitGroup
	stopping    chan struct{}
	pins        *guardPins
}

func loadHostObject(path string, enlarge string) ([32]byte, *ebpf.Collection, error) {
	var digest [32]byte
	raw, err := os.ReadFile(path)
	if err != nil {
		return digest, nil, err
	}
	digest = sha256.Sum256(raw)
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return digest, nil, err
	}
	if enlarge != "" {
		ring := spec.Maps[enlarge]
		if ring == nil || ring.Type != ebpf.RingBuf {
			return digest, nil, fmt.Errorf("%s lacks ring buffer %s", filepath.Base(path), enlarge)
		}
		ring.MaxEntries = hostRingBytes
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return digest, nil, fmt.Errorf("load %s: %w", filepath.Base(path), err)
	}
	return digest, collection, nil
}

// attachHost installs both host-control policies before any LSM hook attaches,
// so no instant exists where a hook sees a zero policy. The domain is empty:
// the command joins only after the guard reports ready.
func attachHost(document pocpolicy.Document, cgroup string, inode, deadline uint64, fsObject, processObject string) (_ *hostGuard, err error) {
	host := &hostGuard{cgroup: cgroup, stopping: make(chan struct{})}
	defer func() {
		if err != nil {
			host.close()
		}
	}()
	fsPlan, err := document.FilesystemPlan(inode, 1, deadline)
	if err != nil {
		return nil, err
	}
	processPlan, err := document.ProcessPlan(inode, 1, deadline)
	if err != nil {
		return nil, err
	}
	fsDigest, fsCollection, err := loadHostObject(fsObject, "events")
	if err != nil {
		return nil, err
	}
	host.collections = append(host.collections, fsCollection)
	processDigest, processCollection, err := loadHostObject(processObject, "")
	if err != nil {
		return nil, err
	}
	host.collections = append(host.collections, processCollection)

	fsRuntime := &kernel.Runtime{Collection: fsCollection, Domain: cgroup, ID: inode}
	if err = fsrules.AccessProfile().Initialize(fsRuntime); err != nil {
		return nil, err
	}
	if err = fsrules.InstallAccess(fsRuntime, fsPlan); err != nil {
		return nil, fmt.Errorf("install filesystem policy: %w", err)
	}
	processRuntime := &kernel.Runtime{Collection: processCollection, Domain: cgroup, ID: inode}
	if err = processrules.Profile().Initialize(processRuntime); err != nil {
		return nil, err
	}
	empty := func() error {
		quiet, checkErr := domainIsEmpty(cgroup)
		if checkErr != nil || !quiet {
			return errors.Join(checkErr, errors.New("host policy installation requires an empty domain"))
		}
		return nil
	}
	if err = processrules.Install(processRuntime, processPlan, empty); err != nil {
		return nil, fmt.Errorf("install process policy: %w", err)
	}

	fsHooks, processHooks := fsrules.AccessProfile().LSMPrograms, processrules.Programs()
	for _, set := range []struct {
		collection *ebpf.Collection
		names      []string
	}{{fsCollection, fsHooks}, {processCollection, processHooks}} {
		for _, name := range set.names {
			program := set.collection.Programs[name]
			if program == nil {
				return nil, fmt.Errorf("mandatory host BPF program absent: %s", name)
			}
			attached, attachErr := link.AttachLSM(link.LSMOptions{Program: program})
			if attachErr != nil {
				return nil, fmt.Errorf("attach %s: %w", name, attachErr)
			}
			host.links = append(host.links, attached)
		}
	}

	host.fs = newEvidence(fsObject, fsDigest, fsPlan.Digest(), fsHooks, binary.Size(fsEvent{}), func(raw []byte) (string, bool, denial, error) {
		var e fsEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
			return "", false, denial{}, err
		}
		name := fsOperationName(e.Operation)
		return name, e.Allowed == 1, denial{Sequence: e.Sequence, PID: e.PID, Operation: name, Rule: e.Rule, Reason: e.Reason, Path: cString(e.Path[:])}, nil
	})
	host.process = newEvidence(processObject, processDigest, processPlan.Digest(), processHooks, binary.Size(processrules.Event{}), func(raw []byte) (string, bool, denial, error) {
		var e processrules.Event
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
			return "", false, denial{}, err
		}
		name := map[uint32]string{processrules.SignalHook: "signal", processrules.PtraceHook: "ptrace", processrules.TracemeHook: "traceme"}[e.Hook]
		if name == "" {
			return "", false, denial{}, errors.New("process hook differs")
		}
		return name, e.Allowed == 1, denial{Sequence: e.Sequence, PID: e.PID, Operation: name, Reason: e.Reason, Target: e.TargetPID}, nil
	})
	for _, source := range []struct {
		collection *ebpf.Collection
		events     string
		stats      string
		evidence   *ringTracker
	}{{fsCollection, "events", "stats", host.fs}, {processCollection, "proc_events", "proc_stats", host.process}} {
		reader, readerErr := ringbuf.NewReader(source.collection.Maps[source.events])
		if readerErr != nil {
			return nil, readerErr
		}
		host.readers = append(host.readers, reader)
		host.counters = append(host.counters, source.collection.Maps[source.stats])
		host.done.Add(1)
		go host.drain(reader, source.evidence)
	}
	return host, nil
}

// drain keeps reading until stop is requested and the ring is idle.
func (h *hostGuard) drain(reader *ringbuf.Reader, evidence *ringTracker) {
	defer h.done.Done()
	for {
		reader.SetDeadline(time.Now().Add(50 * time.Millisecond))
		record, err := reader.Read()
		if err == nil {
			evidence.consume(record.RawSample)
			continue
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			select {
			case <-h.stopping:
				return
			default:
				continue
			}
		}
		evidence.mu.Lock()
		evidence.failure = err
		evidence.mu.Unlock()
		return
	}
}

// pin retains enforcement if this process exits while the domain is populated.
func (h *hostGuard) pin() error {
	dir := filepath.Join("/sys/fs/bpf", "ag-mvp-host-"+filepath.Base(h.cgroup))
	pins := &guardPins{dir: dir}
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	for index, collection := range h.collections {
		for name, item := range collection.Maps {
			if item == nil || name == "" {
				_ = pins.release()
				return errors.New("host map name differs")
			}
			if err := item.Pin(filepath.Join(dir, fmt.Sprintf("map-%d-%s", index, name))); err != nil {
				_ = pins.release()
				return fmt.Errorf("pin host map %s: %w", name, err)
			}
			pins.maps = append(pins.maps, item)
		}
	}
	for index, item := range h.links {
		if err := item.Pin(filepath.Join(dir, fmt.Sprintf("link-%d", index))); err != nil {
			_ = pins.release()
			return fmt.Errorf("pin host link %d: %w", index, err)
		}
		pins.links = append(pins.links, item)
	}
	h.pins = pins
	return nil
}

func (h *hostGuard) release() error {
	if h == nil || h.pins == nil {
		return nil
	}
	return h.pins.release()
}

// finish stops the readers once their rings are idle and reconciles counters.
func (h *hostGuard) finish() hostEvidence {
	close(h.stopping)
	h.done.Wait()
	out := hostEvidence{Complete: true}
	for index, evidence := range []*ringTracker{h.fs, h.process} {
		var counts struct{ Decisions, Lost uint64 }
		countErr := h.counters[index].Lookup(uint32(0), &counts)
		evidence.mu.Lock()
		evidence.Decisions, evidence.Lost = counts.Decisions, counts.Lost
		evidence.RawSHA256 = hex.EncodeToString(evidence.raw.Sum(nil))
		evidence.Complete = countErr == nil && evidence.failure == nil && counts.Lost == 0 && counts.Decisions == evidence.Observed
		out.Complete = out.Complete && evidence.Complete
		evidence.mu.Unlock()
	}
	out.Filesystem, out.Process = h.fs.snapshot(), h.process.snapshot()
	return out
}

func (e *ringTracker) snapshot() ringEvidence {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.ringEvidence
}

func (h *hostGuard) close() {
	if h == nil {
		return
	}
	for _, reader := range h.readers {
		_ = reader.Close()
	}
	for _, item := range h.links {
		_ = item.Close()
	}
	for _, collection := range h.collections {
		collection.Close()
	}
}
