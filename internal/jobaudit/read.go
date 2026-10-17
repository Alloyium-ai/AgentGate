// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobaudit

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"bufio"
	"bytes"
	"errors"
	"io"
)

// Read reconstructs the durable log. Truncation and incomplete terminal evidence
// never become a complete bundle. VerifyOffline supplies the evidence verdict.
func Read(reader io.Reader) (Bundle, error) {
	b := Bundle{Events: []Event{}, Counters: map[string]FinalCounters{}}
	scanner := bufio.NewScanner(io.LimitReader(reader, (256<<20)+1))
	scanner.Buffer(make([]byte, 4096), 2<<20)
	count, total := 0, 0
	for scanner.Scan() {
		raw := scanner.Bytes()
		total += len(raw) + 1
		count++
		if total > 256<<20 || count > 100134 {
			return b, errors.New("the audit log exceeds its bound")
		}
		var r diskRecord
		if lifecycle.DecodeTransport(bytes.NewReader(raw), &r) != nil {
			return b, errors.New("the audit log contains an ambiguous or truncated record")
		}
		fields := 0
		for _, present := range []bool{r.Header != nil, r.Grant != nil, r.Event != nil, r.Counters != nil, r.Seal != nil, r.Authority != nil} {
			if present {
				fields++
			}
		}
		if fields != 1 || (r.Kind != "counters" && r.Stream != "") {
			return b, errors.New("the audit log record fields differ")
		}
		if count == 1 && r.Kind != "header" {
			return b, errors.New("the audit log header is missing")
		}
		if b.Authority != nil {
			return b, errors.New("the audit log continues after the authority receipt")
		}
		switch r.Kind {
		case "header":
			if count != 1 || r.Header == nil {
				return b, errors.New("the audit header repeats")
			}
			b.Header = *r.Header
		case "grant":
			if r.Grant == nil || b.Grant != nil || b.Seal != nil {
				return b, errors.New("the audit grant repeats or follows the seal")
			}
			b.Grant = r.Grant
		case "event":
			if r.Event == nil || b.Seal != nil {
				return b, errors.New("an audit event follows the seal")
			}
			if _, ok := b.Counters[r.Event.Stream]; ok {
				return b, errors.New("an audit event follows final counters")
			}
			b.Events = append(b.Events, *r.Event)
		case "counters":
			if r.Counters == nil || b.Seal != nil || r.Stream == "" {
				return b, errors.New("the audit counters are invalid")
			}
			if _, ok := b.Counters[r.Stream]; ok {
				return b, errors.New("the audit counters repeat")
			}
			b.Counters[r.Stream] = *r.Counters
		case "seal":
			if r.Seal == nil || b.Seal != nil {
				return b, errors.New("the node seal repeats")
			}
			b.Seal = r.Seal
		case "authority":
			if r.Authority == nil || b.Seal == nil {
				return b, errors.New("the authority receipt precedes the node seal")
			}
			b.Authority = r.Authority
		default:
			return b, errors.New("the audit log record version is unknown")
		}
	}
	if err := scanner.Err(); err != nil {
		return b, err
	}
	if count == 0 {
		return b, errors.New("the audit log is empty")
	}
	return b, nil
}
