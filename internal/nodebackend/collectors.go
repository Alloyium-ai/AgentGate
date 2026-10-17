// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/kernel"
	"context"
	"errors"
	"os"
	"sync"
	"time"
)

const maxReorder = 4096

// orderedStream retains the atomic kernel sequence. Ring arrival can differ
// between CPUs. A gap remains visible and prevents a complete terminal record.
type orderedStream struct {
	next    uint64
	pending map[uint64][]byte
}

func (s *orderedStream) accept(raw []byte, decode jobaudit.Decoder, appendRaw func([]byte) error) error {
	o, err := decode(raw)
	if err != nil {
		return err
	}
	if s.next == 0 {
		s.next = 1
		s.pending = map[uint64][]byte{}
	}
	if o.Sequence < s.next || o.Sequence == 0 {
		return errors.New("the audit sequence repeats")
	}
	if _, ok := s.pending[o.Sequence]; ok {
		return errors.New("the pending audit sequence repeats")
	}
	if len(s.pending) >= maxReorder || o.Sequence-s.next >= maxReorder {
		return errors.New("the audit reorder bound is exceeded")
	}
	s.pending[o.Sequence] = append([]byte{}, raw...)
	for {
		raw, ok := s.pending[s.next]
		if !ok {
			break
		}
		if err = appendRaw(raw); err != nil {
			return err
		}
		delete(s.pending, s.next)
		s.next++
	}
	return nil
}
func (s *orderedStream) complete(sequence uint64) error {
	next := s.next
	if next == 0 {
		next = 1
	}
	if len(s.pending) != 0 || next-1 != sequence {
		return errors.New("the final audit sequence has a gap")
	}
	return nil
}

type collector struct {
	name         string
	runtime      *kernel.Runtime
	decode       jobaudit.Decoder
	order        orderedStream
	done         chan struct{}
	mu           sync.Mutex
	err          error
	final        *jobaudit.FinalCounters
	finalErr     error
	finalWritten bool
}
type collectors struct {
	streams     []*collector
	writer      *jobaudit.Writer
	fault       chan error
	once        sync.Once
	mu          sync.Mutex
	err         error
	monitorDone chan struct{}
	finishMu    sync.Mutex
}

func newCollectors(writer *jobaudit.Writer, registry jobaudit.Registry, runtimes map[string]*kernel.Runtime) (*collectors, error) {
	c := &collectors{writer: writer, fault: make(chan error, 1), monitorDone: make(chan struct{})}
	for name, format := range jobaudit.ResourceFormats() {
		r := runtimes[name]
		decode := registry[name+"/"+format.Version]
		if r == nil || r.Reader == nil || decode == nil {
			return nil, errors.New("a mandatory resource audit reader is absent")
		}
		c.streams = append(c.streams, &collector{name: name, runtime: r, decode: decode, done: make(chan struct{})})
	}
	for name, format := range jobaudit.ObservationFormats() {
		r := runtimes[name]
		decode := registry[name+"/"+format.Version]
		if r == nil || r.Reader == nil || decode == nil {
			return nil, errors.New("a mandatory observation reader is absent")
		}
		c.streams = append(c.streams, &collector{name: name, runtime: r, decode: decode, done: make(chan struct{})})
	}
	return c, nil
}
func (c *collectors) fail(err error) {
	if err != nil {
		c.once.Do(func() { c.mu.Lock(); c.err = err; c.mu.Unlock(); c.fault <- err })
	}
}
func (c *collectors) start(ctx context.Context) {
	for _, s := range c.streams {
		go c.read(ctx, s)
	}
	go c.monitor(ctx)
}
func (c *collectors) monitor(ctx context.Context) {
	defer close(c.monitorDone)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			for _, s := range c.streams {
				v, err := s.runtime.Counters()
				if err != nil {
					c.fail(err)
					return
				}
				if v.Lost != 0 {
					c.fail(errors.New("the continuous kernel audit monitor detected loss"))
					return
				}
			}
		}
	}
}
func (c *collectors) read(ctx context.Context, s *collector) {
	defer close(s.done)
	for {
		s.runtime.Reader.SetDeadline(time.Now().Add(100 * time.Millisecond))
		record, err := s.runtime.Reader.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			if ctx.Err() != nil {
				return
			}
			counter, e := s.runtime.Counters()
			if e != nil || counter.Lost != 0 {
				if e == nil {
					e = errors.New("the kernel audit ring lost records")
				}
				c.recordFailure(s, e)
				return
			}
			continue
		}
		if err != nil {
			c.recordFailure(s, err)
			return
		}
		s.mu.Lock()
		err = s.order.accept(record.RawSample, s.decode, func(raw []byte) error { return c.writer.Append(context.Background(), s.name, raw) })
		s.mu.Unlock()
		if err != nil {
			c.recordFailure(s, err)
			return
		}
	}
}
func (c *collectors) recordFailure(s *collector, err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
	c.fail(err)
}
func (c *collectors) healthy() error { c.mu.Lock(); defer c.mu.Unlock(); return c.err }

// finish follows confirmed whole-domain termination. No task can add a record.
func (c *collectors) finish(ctx context.Context, cancel context.CancelFunc) (map[string]jobaudit.FinalCounters, error) {
	c.finishMu.Lock()
	defer c.finishMu.Unlock()
	cancel()
	out := map[string]jobaudit.FinalCounters{}
	select {
	case <-c.monitorDone:
	case <-ctx.Done():
		return out, ctx.Err()
	}
	var problems []error
	for _, s := range c.streams {
		select {
		case <-s.done:
		case <-ctx.Done():
			return out, ctx.Err()
		}
		v, err := s.finish(ctx, s.runtime.Counters, c.writer.FinishStream)
		if v != nil {
			out[s.name] = *v
		}
		if err != nil {
			problems = append(problems, err)
		}
	}
	return out, errors.Join(problems...)
}

// finish retains actual final counters before the runtime can close. A cleanup
// retry reuses those facts and never reopens a removed kernel map.
func (s *collector) finish(ctx context.Context, read func() (kernel.Counters, error), persist func(context.Context, string, jobaudit.FinalCounters) error) (*jobaudit.FinalCounters, error) {
	if s.final == nil {
		value, err := read()
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.finalErr = errors.Join(s.err, s.order.complete(value.Decisions))
		s.mu.Unlock()
		v := jobaudit.FinalCounters{Sequence: value.Decisions, Decisions: value.Decisions, Lost: value.Lost, Available: true}
		if s.name == "syscalls" {
			v.Decisions = 0
		}
		s.final = &v
	}
	if !s.finalWritten {
		err := persist(ctx, s.name, *s.final)
		if err != nil && !errors.Is(err, jobaudit.ErrIncomplete) {
			value := *s.final
			return &value, errors.Join(s.finalErr, err)
		}
		s.finalWritten = true
		s.finalErr = errors.Join(s.finalErr, err)
	}
	value := *s.final
	return &value, s.finalErr
}
