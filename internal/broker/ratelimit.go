// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"sync"
	"time"
)

// tokenBucket is the per-launch request rate limit.
type tokenBucket struct {
	mu       sync.Mutex
	rate     float64 // tokens per second
	capacity float64
	tokens   float64
	last     time.Time
	now      func() time.Time
}

func newTokenBucket(perMinute, burst int, now func() time.Time) *tokenBucket {
	return &tokenBucket{rate: float64(perMinute) / 60, capacity: float64(burst), tokens: float64(burst), last: now(), now: now}
}

func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.now()
	if elapsed := t.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = t
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
