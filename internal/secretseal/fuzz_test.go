// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package secretseal

import (
	"encoding/json"
	"os"
	"testing"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// FuzzEnvelopeDecode (from the second adversarial review): no input panics;
// an envelope the service's hostproto.ParseSealed accepts is accepted by the
// host's secretseal too (the host is deliberately the stricter of the two, so
// the reverse need not hold); and Encode/DecodeEnvelope round-trips. Under
// plain go test only the seeds run.
func FuzzEnvelopeDecode(f *testing.F) {
	if b, err := os.ReadFile("testdata/vector-v2.json"); err == nil {
		var v map[string]json.RawMessage
		if json.Unmarshal(b, &v) == nil {
			for _, x := range v {
				f.Add([]byte(x))
			}
		}
	}
	f.Add([]byte(`{"format":"agentgate.secretseal.v2","target_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"k","version":1,"key_id":"0000000000000000000000000000000000000000000000000000000000000000","nonce":"00000000000000000000000000000000","policy_digest":"0000000000000000000000000000000000000000000000000000000000000000","sealed":"AAAA"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := ParseEnvelope(raw)
		if _, herr := hostproto.ParseSealed(raw); herr == nil && err != nil {
			t.Fatalf("the service accepts what the host refuses: %v %q", err, raw)
		}
		if err != nil {
			return
		}
		e2, err := DecodeEnvelope(e.Encode())
		if err != nil || *e2 != *e {
			t.Fatalf("round trip: %v", err)
		}
		_, _ = ParseReceipt(raw)
	})
}

// FuzzRecordParse: no record bytes panic the store's parser, and a record it
// accepts is whole: its value reproduces its fingerprint and re-encodes to
// the same bytes.
func FuzzRecordParse(f *testing.F) {
	s := &Store{fpKey: make([]byte, 32)}
	rec := secretRecord{Format: recordFormat, TargetID: "local", Name: "k", Version: 1, Nonce: "00000000000000000000000000000000",
		PolicyDigest: "0000000000000000000000000000000000000000000000000000000000000000", UpdatedAt: "2026-10-24T12:00:00Z", Value: []byte("value-one")}
	rec.Fingerprint = s.Fingerprint("local", "k", rec.Value)
	good, _ := rec.encode()
	f.Add(good)
	tomb := rec
	tomb.Deleted, tomb.Fingerprint, tomb.Value = true, "", nil
	t2, _ := tomb.encode()
	f.Add(t2)
	f.Add([]byte("{}\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, err := s.parseRecord("k", raw)
		if err != nil {
			return
		}
		if !r.Deleted && s.Fingerprint(r.TargetID, r.Name, r.Value) != r.Fingerprint {
			t.Fatal("accepted a record whose value is not its fingerprint's")
		}
		again, err := r.encode()
		if err != nil {
			t.Fatal(err)
		}
		if r2, err := s.parseRecord("k", again); err != nil || r2.Fingerprint != r.Fingerprint || string(r2.Value) != string(r.Value) || r2.Version != r.Version {
			t.Fatalf("re-encoded record differs: %v", err)
		}
	})
}
