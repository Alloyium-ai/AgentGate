// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodedns

import (
	"context"
	"errors"
	"sync"
	"time"

	"alloyium.local/kernel-poc/internal/dnslease"
)

type clock struct {
	mu     sync.Mutex
	source dnslease.Clock
	last   uint64
	err    error
}

func (c *clock) now() (value uint64, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return 0, c.err
	}
	defer func() {
		if recover() != nil {
			c.err = errors.New("the trusted clock panicked")
			value = 0
			err = c.err
		}
	}()
	value, err = c.source()
	if err != nil {
		c.err = err
		return 0, err
	}
	if value < c.last {
		c.err = errors.New("the monotonic clock moved backwards")
		return 0, c.err
	}
	c.last = value
	return value, nil
}
func (c *clock) failure() error { c.mu.Lock(); defer c.mu.Unlock(); return c.err }

type resolver struct {
	mu       sync.Mutex
	source   dnslease.Resolver
	evidence dnslease.ResolverEvidence
	err      error
}

func (r *resolver) Evidence() dnslease.ResolverEvidence { return r.evidence }
func (r *resolver) Exchange(ctx context.Context, wire []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	if r.source.Evidence() != r.evidence {
		r.err = errors.New("the pinned resolver evidence changed")
		return nil, r.err
	}
	raw, err := r.source.Exchange(ctx, wire)
	if r.source.Evidence() != r.evidence {
		r.err = errors.New("the pinned resolver evidence changed")
		return nil, r.err
	}
	return raw, err
}
func (r *resolver) failure() error            { r.mu.Lock(); defer r.mu.Unlock(); return r.err }
func timeDuration(value uint64) time.Duration { return time.Duration(value) }
