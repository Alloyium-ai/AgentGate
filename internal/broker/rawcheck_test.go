// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"strings"
	"testing"
)

func check(raw string, chunk int) string {
	h := newHeaderCheck(32<<10, 64)
	b := []byte(raw)
	for len(b) > 0 {
		n := chunk
		if n > len(b) {
			n = len(b)
		}
		h.feed(b[:n])
		b = b[n:]
	}
	return h.verdict()
}

const okHead = "POST /anthropic/v1/messages HTTP/1.1\r\nHost: 10.99.0.2:8443\r\nContent-Length: 2\r\n\r\n{}"

// smugglingCorpus maps each malformed header block to the reason it must
// produce. Every entry is a shape some HTTP parser accepts.
var smugglingCorpus = map[string]string{
	"POST / HTTP/1.1\nHost: a\r\n\r\n":                                                               reasonBareLF,
	"POST / HTTP/1.1\r\nHost: a\n\r\n":                                                               reasonBareLF,
	"POST / HTTP/1.1\r\nHost: a\r\n\n":                                                               reasonBareLF,
	"POST / HTTP/1.1\r\nHost: a\rX: b\r\n\r\n":                                                       reasonBareCR,
	"POST / HTTP/1.1\r\nHost: a\r\nX: b\r\n continued\r\n\r\n":                                       reasonObsFold,
	"POST / HTTP/1.1\r\nHost: a\r\nX: b\r\n\tcontinued\r\n\r\n":                                      reasonObsFold,
	"POST / HTTP/1.1\r\n Host: a\r\n\r\n":                                                            reasonObsFold,
	"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n":                   reasonDuplicateCL,
	"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n":                   reasonDuplicateCL,
	"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5, 5\r\n\r\n":                                     reasonInvalidCL,
	"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +5\r\n\r\n":                                       reasonInvalidCL,
	"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0x5\r\n\r\n":                                      reasonInvalidCL,
	"POST / HTTP/1.1\r\nHost: a\r\nContent-Length:\r\n\r\n":                                          reasonInvalidCL,
	"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999\r\n\r\n":                     reasonInvalidCL,
	"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n":          reasonTEAndCL,
	"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n":          reasonTEAndCL,
	"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n":                         reasonBadTE,
	"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, identity\r\n\r\n":                     reasonBadTE,
	"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\n\r\n":                              reasonBadTE,
	"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n": reasonBadTE,
	"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding : chunked\r\n\r\n":                              reasonHeaderSyntax,
	"POST / HTTP/1.1\r\nHost: a\r\nX\x00: b\r\n\r\n":                                                 reasonHeaderSyntax,
	"POST / HTTP/1.1\r\nHost: a\r\nX: b\x00c\r\n\r\n":                                                reasonHeaderSyntax,
	"POST / HTTP/1.1\r\nHost: a\r\nX: b\x7f\r\n\r\n":                                                 reasonHeaderSyntax,
	"POST / HTTP/1.1\r\nHost: a\r\nX: \xc3\xa9\r\n\r\n":                                              reasonHeaderSyntax,
	"POST / HTTP/1.1\r\nHost: a\r\n: b\r\n\r\n":                                                      reasonHeaderSyntax,
	"POST / HTTP/1.1\r\nHost: a\r\nNoColon\r\n\r\n":                                                  reasonHeaderSyntax,
	"POST / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n":                                                  reasonHost,
	"POST / HTTP/1.1\r\nX: a\r\n\r\n":                                                                reasonHost,
	"POST / HTTP/1.0\r\nHost: a\r\n\r\n":                                                             reasonHTTPVersion,
	"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n":                                                               reasonHTTPVersion,
	"GET /\r\n\r\n":                                                                                  reasonRequestLine,
	"POST  / HTTP/1.1\r\nHost: a\r\n\r\n":                                                            reasonRequestLine,
	"post / HTTP/1.1\r\nHost: a\r\n\r\n":                                                             reasonRequestLine,
	"POST /\x01 HTTP/1.1\r\nHost: a\r\n\r\n":                                                         reasonRequestLine,
	"\r\nPOST / HTTP/1.1\r\nHost: a\r\n\r\n":                                                         reasonRequestLine,
	"POST / HTTP/1.1\r\nHost: a\r\n":                                                                 reasonHeaderIncomplete,
}

func TestHeaderCheckSmugglingCorpus(t *testing.T) {
	for raw, want := range smugglingCorpus {
		for _, chunk := range []int{1, 3, 4096} {
			if got := check(raw, chunk); got != want {
				t.Errorf("%q (chunk %d): got %q want %q", raw, chunk, got, want)
			}
		}
	}
}

func TestHeaderCheckAcceptsWellFormedRequests(t *testing.T) {
	for _, raw := range []string{
		okHead,
		"GET /git/o/r.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: x\r\nUser-Agent: git/2.43\r\nGit-Protocol: version=2\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: Chunked\r\n\r\n0\r\n\r\n",
		"POST / HTTP/1.1\r\nhost: a\r\ncontent-length:  7 \r\nX-Tab:\tv\r\n\r\n",
	} {
		for _, chunk := range []int{1, 7, 4096} {
			if got := check(raw, chunk); got != "" {
				t.Errorf("%q: %s", raw, got)
			}
		}
	}
}

func TestHeaderCheckBoundsSizeAndCount(t *testing.T) {
	many := "GET / HTTP/1.1\r\nHost: a\r\n" + strings.Repeat("X-A: b\r\n", 70) + "\r\n"
	if got := check(many, 4096); got != reasonHeaderCount {
		t.Fatal(got)
	}
	big := "GET / HTTP/1.1\r\nHost: a\r\nX: " + strings.Repeat("a", 40<<10) + "\r\n\r\n"
	if got := check(big, 4096); got != reasonHeaderTooLarge {
		t.Fatal(got)
	}
	// Bytes after the header block are body bytes and are not inspected.
	body := okHead + "\nbare\rlf"
	if got := check(body, 5); got != "" {
		t.Fatal(got)
	}
}

func FuzzHeaderCheck(f *testing.F) {
	for raw := range smugglingCorpus {
		f.Add([]byte(raw))
	}
	f.Add([]byte(okHead))
	f.Fuzz(func(t *testing.T, raw []byte) {
		h := newHeaderCheck(4096, 16)
		h.feed(raw)
		if h.verdict() != "" {
			return
		}
		// An accepted block has CRLF endings only, exactly one Host and at
		// most one framing header.
		head := string(raw[:h.total])
		if strings.Count(head, "\n") != strings.Count(head, "\r\n") || strings.Count(head, "\r") != strings.Count(head, "\r\n") {
			t.Fatalf("accepted a bare line ending: %q", head)
		}
		lower := strings.ToLower(head)
		if strings.Contains(lower, "\r\ncontent-length:") && strings.Contains(lower, "\r\ntransfer-encoding:") {
			t.Fatalf("accepted both framing headers: %q", head)
		}
	})
}
