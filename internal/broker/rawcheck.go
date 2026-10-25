// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"bytes"
	"strings"
)

// headerCheck validates the raw bytes of the first request header block on a
// connection before net/http's parser acts on them. net/http stays the parser;
// this check only refuses shapes that net/http tolerates but that a strict
// intermediary must not: bare LF or CR line endings, obs-fold continuation
// lines, repeated or list-valued Content-Length, Transfer-Encoding other than
// exactly "chunked", Transfer-Encoding together with Content-Length, a missing
// or repeated Host, non-ASCII header bytes, and oversized or numerous fields.
//
// The broker serves one request per connection (keep-alives are disabled), so
// only the first header block exists; bytes after it are the body and are never
// inspected here.
type headerCheck struct {
	maxBytes, maxCount int

	line    []byte
	total   int
	lines   int
	prevCR  bool
	done    bool
	reason  string
	cl, te  int
	host    int
	request bool
}

func newHeaderCheck(maxBytes, maxCount int) *headerCheck {
	return &headerCheck{maxBytes: maxBytes, maxCount: maxCount, line: make([]byte, 0, 256)}
}

// Reasons are fixed stats keys.
const (
	reasonHeaderIncomplete = "header_incomplete"
	reasonHeaderTooLarge   = "header_too_large"
	reasonHeaderCount      = "header_count"
	reasonBareLF           = "header_bare_lf"
	reasonBareCR           = "header_bare_cr"
	reasonObsFold          = "header_obs_fold"
	reasonHeaderSyntax     = "header_syntax"
	reasonRequestLine      = "request_line"
	reasonHTTPVersion      = "http_version"
	reasonDuplicateCL      = "duplicate_content_length"
	reasonInvalidCL        = "invalid_content_length"
	reasonTEAndCL          = "transfer_encoding_and_content_length"
	reasonBadTE            = "unsupported_transfer_encoding"
	reasonHost             = "host_header"
)

func (h *headerCheck) fail(reason string) {
	h.done = true
	h.reason = reason
}

// verdict returns "" when a complete header block passed every check.
func (h *headerCheck) verdict() string {
	if !h.done {
		return reasonHeaderIncomplete
	}
	return h.reason
}

func (h *headerCheck) feed(p []byte) {
	for _, c := range p {
		if h.done {
			return
		}
		h.total++
		if h.total > h.maxBytes {
			h.fail(reasonHeaderTooLarge)
			return
		}
		if h.prevCR {
			h.prevCR = false
			if c != '\n' {
				h.fail(reasonBareCR)
				return
			}
			h.endLine()
			continue
		}
		switch c {
		case '\r':
			h.prevCR = true
		case '\n':
			h.fail(reasonBareLF)
			return
		default:
			h.line = append(h.line, c)
		}
	}
}

func (h *headerCheck) endLine() {
	line := h.line
	h.line = h.line[:0]
	if !h.request {
		h.request = true
		if r := checkRequestLine(line); r != "" {
			h.fail(r)
		}
		return
	}
	if len(line) == 0 {
		switch {
		case h.host != 1:
			h.fail(reasonHost)
		case h.te > 0 && h.cl > 0:
			h.fail(reasonTEAndCL)
		default:
			h.done = true
		}
		return
	}
	h.lines++
	if h.lines > h.maxCount {
		h.fail(reasonHeaderCount)
		return
	}
	if line[0] == ' ' || line[0] == '\t' {
		h.fail(reasonObsFold)
		return
	}
	colon := bytes.IndexByte(line, ':')
	if colon < 1 || colon > 128 {
		h.fail(reasonHeaderSyntax)
		return
	}
	name := line[:colon]
	for _, c := range name {
		if !tchar(c) {
			h.fail(reasonHeaderSyntax)
			return
		}
	}
	value := line[colon+1:]
	for _, c := range value {
		if (c < 0x20 && c != '\t') || c >= 0x7f {
			h.fail(reasonHeaderSyntax)
			return
		}
	}
	trimmed := strings.Trim(string(value), " \t")
	switch strings.ToLower(string(name)) {
	case "content-length":
		h.cl++
		if h.cl > 1 {
			h.fail(reasonDuplicateCL)
			return
		}
		if trimmed == "" || len(trimmed) > 18 || strings.Trim(trimmed, "0123456789") != "" {
			h.fail(reasonInvalidCL)
			return
		}
	case "transfer-encoding":
		h.te++
		if h.te > 1 || !strings.EqualFold(trimmed, "chunked") {
			h.fail(reasonBadTE)
			return
		}
	case "host":
		h.host++
		if h.host > 1 {
			h.fail(reasonHost)
			return
		}
	}
}

func checkRequestLine(line []byte) string {
	parts := bytes.Split(line, []byte{' '})
	if len(parts) != 3 {
		return reasonRequestLine
	}
	method, target, version := parts[0], parts[1], parts[2]
	if len(method) < 1 || len(method) > 16 || len(target) < 1 || len(target) > 8192 {
		return reasonRequestLine
	}
	for _, c := range method {
		if c < 'A' || c > 'Z' {
			return reasonRequestLine
		}
	}
	for _, c := range target {
		if c < 0x21 || c > 0x7e {
			return reasonRequestLine
		}
	}
	if string(version) != "HTTP/1.1" {
		return reasonHTTPVersion
	}
	return ""
}
