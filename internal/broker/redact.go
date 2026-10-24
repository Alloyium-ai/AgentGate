// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import "bytes"

// redactor masks credential encodings in a response stream. It is best effort:
// it catches the raw value and its base64 forms (including the Basic
// "user:value" form) even when a match spans reads, but it cannot catch an
// upstream that transforms the value in another way. The mask keeps the length,
// so a Content-Length stays valid.
//
// To keep Server-Sent Events prompt it holds back only the shortest tail that
// could still begin a match, rather than a fixed window.
type redactor struct {
	patterns []pattern
	mask     byte
	pending  []byte
	out      []byte
	count    int
}

// pattern is one masked form with its KMP failure table, used to find the
// longest stream tail that could still begin a match in linear time.
type pattern struct {
	b    []byte
	fail []int
}

func newPatterns(forms [][]byte) []pattern {
	out := make([]pattern, 0, len(forms))
	for _, b := range forms {
		f := make([]int, len(b))
		k := 0
		for i := 1; i < len(b); i++ {
			for k > 0 && b[i] != b[k] {
				k = f[k-1]
			}
			if b[i] == b[k] {
				k++
			}
			f[i] = k
		}
		out = append(out, pattern{b: b, fail: f})
	}
	return out
}

func wipePatterns(ps []pattern) {
	for _, p := range ps {
		clear(p.b)
		clear(p.fail)
	}
}

// tail returns the length of the longest suffix of text that is a proper
// prefix of the pattern.
func (p *pattern) tail(text []byte) int {
	start := len(text) - (len(p.b) - 1)
	if start < 0 {
		start = 0
	}
	k := 0
	for _, c := range text[start:] {
		for k > 0 && c != p.b[k] {
			k = p.fail[k-1]
		}
		if c == p.b[k] {
			k++
		}
		if k == len(p.b) {
			k = p.fail[k-1]
		}
	}
	return k
}

func newRedactor(patterns []pattern) *redactor {
	r := &redactor{patterns: patterns, mask: '*'}
	for _, m := range []byte("*#X~") {
		used := false
		for _, p := range patterns {
			if bytes.IndexByte(p.b, m) >= 0 {
				used = true
				break
			}
		}
		if !used {
			r.mask = m
			break
		}
	}
	return r
}

// containsCredential reports whether s holds any masked form.
func containsCredential(patterns []pattern, s string) bool {
	for _, p := range patterns {
		if len(p.b) <= len(s) && bytes.Contains([]byte(s), p.b) {
			return true
		}
	}
	return false
}

// process appends p and returns the bytes that are safe to emit now. With
// final set it flushes everything. The returned slice is reused by the next call.
func (r *redactor) process(p []byte, final bool) []byte {
	r.pending = append(r.pending, p...)
	for _, pat := range r.patterns {
		from := 0
		for {
			i := bytes.Index(r.pending[from:], pat.b)
			if i < 0 {
				break
			}
			start := from + i
			for j := start; j < start+len(pat.b); j++ {
				r.pending[j] = r.mask
			}
			r.count++
			from = start + len(pat.b)
		}
	}
	hold := 0
	if !final {
		for i := range r.patterns {
			if n := r.patterns[i].tail(r.pending); n > hold {
				hold = n
			}
		}
	}
	emit := len(r.pending) - hold
	r.out = append(r.out[:0], r.pending[:emit]...)
	n := copy(r.pending, r.pending[emit:])
	r.pending = r.pending[:n]
	return r.out
}

// release clears this stream's buffers; the shared patterns stay intact.
func (r *redactor) release() {
	clear(r.pending)
	clear(r.out)
}
