// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodeaudit

import (
	"encoding/binary"
	"strings"
	"testing"
)

func put32(raw []byte, offset int, value uint32) { binary.LittleEndian.PutUint32(raw[offset:], value) }
func put64(raw []byte, offset int, value uint64) { binary.LittleEndian.PutUint64(raw[offset:], value) }
func fixture(key string) []byte {
	if key == "syscalls/syscalls128.v2" {
		raw := append(fixture("syscalls/syscalls104.v1"), make([]byte, 24)...)
		put64(raw, 104, 39)
		put32(raw, 120, 2)
		put32(raw, 124, 1)
		return raw
	}
	sizes := map[string]int{"files/files216.v1": 216, "peers/peers96.v2": 96, "sockets/sockets112.v1": 112, "custody/custody64.v1": 64, "process/process80.v1": 80, "syscalls/syscalls104.v1": 104}
	raw := make([]byte, sizes[key])
	put64(raw, 0, 7)
	switch key {
	case "files/files216.v1":
		put64(raw, 8, 3)
		put64(raw, 16, 42)
		put64(raw, 24, 1000)
	case "peers/peers96.v2":
		put64(raw, 8, 3)
		put64(raw, 16, 42)
		put64(raw, 24, 43)
		put64(raw, 32, 1000)
		put32(raw, 48, 1)
		put32(raw, 88, 2)
		put32(raw, 92, 17)
	case "sockets/sockets112.v1":
		put64(raw, 8, 3)
		put64(raw, 16, 42)
		put64(raw, 24, 43)
		put64(raw, 32, 1000)
		put32(raw, 56, 16)
		put32(raw, 88, 1)
		put32(raw, 92, 17)
	case "custody/custody64.v1":
		put64(raw, 8, 42)
		put64(raw, 24, 43)
		put64(raw, 32, 3)
		put64(raw, 40, 1000)
		put32(raw, 56, 1)
	case "process/process80.v1":
		put64(raw, 8, 42)
		put64(raw, 24, 43)
		put64(raw, 32, 3)
		put64(raw, 40, 1000)
		put32(raw, 56, 1)
		put32(raw, 72, 4)
	case "syscalls/syscalls104.v1":
		put64(raw, 8, 42)
		put64(raw, 16, 43)
		put64(raw, 24, 3)
		put64(raw, 32, 1000)
		put64(raw, 40, 500)
		put64(raw, 48, 39)
		put64(raw, 56, 99)
		put32(raw, 64, 99)
		put32(raw, 68, 99)
		put32(raw, 72, 65534)
		put32(raw, 76, 1)
	}
	return raw
}
func TestCurrentAndLegacyExactRawLayouts(t *testing.T) {
	registry := Registry()
	if len(registry) != 7 {
		t.Fatal("mandatory stream count differs")
	}
	for key, decode := range registry {
		t.Run(key, func(t *testing.T) {
			raw := fixture(key)
			out, err := decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			if out.CgroupID != 42 || out.Generation != 3 || out.Sequence != 7 || out.TimestampNS != 1000 {
				t.Fatal("raw facts changed", out)
			}
			if strings.HasPrefix(key, "syscalls/") {
				if out.Decision != nil {
					t.Fatal("observer invented a decision")
				}
			} else if out.Decision == nil || *out.Decision {
				t.Fatal("raw deny lost its pointer")
			}
			if _, err = decode(raw[:len(raw)-1]); err == nil {
				t.Fatal("truncated layout accepted")
			}
		})
	}
}
func TestResourceDecisionAndMissingGenerationStayRaw(t *testing.T) {
	raw := fixture("files/files216.v1")
	put32(raw, 44, 1)
	out, err := Registry()["files/files216.v1"](raw)
	if err != nil || out.Decision == nil || !*out.Decision {
		t.Fatal("raw grant changed", err)
	}
	put64(raw, 8, 0)
	if _, err = Registry()["files/files216.v1"](raw); err == nil {
		t.Fatal("unbound grant accepted")
	}
	put32(raw, 44, 0)
	out, err = Registry()["files/files216.v1"](raw)
	if err != nil || out.Generation != 0 || out.Decision == nil || *out.Decision {
		t.Fatal("generation0 deny relabeled", err)
	}
}
func TestObserverNeverConvertsReturnIntoDecision(t *testing.T) {
	for _, result := range []uint64{99, ^uint64(0)} {
		raw := fixture("syscalls/syscalls104.v1")
		put64(raw, 56, result)
		out, err := Registry()["syscalls/syscalls104.v1"](raw)
		if err != nil || out.Decision != nil {
			t.Fatal("return value became permission", err)
		}
	}
	raw := fixture("syscalls/syscalls104.v1")
	put64(raw, 24, 0)
	put32(raw, 84, 1)
	out, err := Registry()["syscalls/syscalls104.v1"](raw)
	if err != nil || out.Generation != 0 || out.BindingState != 1 || out.Decision != nil {
		t.Fatal("missing generation changed", err)
	}
}
func TestCapturedLeaseVersionAndSequenceValidation(t *testing.T) {
	raw := fixture("peers/peers96.v2")
	decode := Registry()["peers/peers96.v2"]
	out, err := decode(raw)
	if err != nil || out.DNSLeaseRevision != 17 {
		t.Fatal("captured lease changed", err)
	}
	put32(raw, 88, 1)
	if _, err = decode(raw); err == nil {
		t.Fatal("legacy peer version accepted")
	}
	raw = fixture("peers/peers96.v2")
	put64(raw, 0, 0)
	if _, err = decode(raw); err == nil {
		t.Fatal("sequence0 accepted")
	}
	raw = fixture("peers/peers96.v2")
	put64(raw, 16, 0)
	if _, err = decode(raw); err == nil {
		t.Fatal("domain0 accepted")
	}
}
func TestUnknownSyscallOriginAndMalformedEffectsReject(t *testing.T) {
	raw := fixture("syscalls/syscalls104.v1")
	put64(raw, 48, ^uint64(0))
	put32(raw, 92, 1)
	if _, err := Registry()["syscalls/syscalls104.v1"](raw); err == nil {
		t.Fatal("unknown syscall origin accepted")
	}
	raw = fixture("files/files216.v1")
	put32(raw, 44, 2)
	if _, err := Registry()["files/files216.v1"](raw); err == nil {
		t.Fatal("nonbinary effect accepted")
	}
}
func TestRegistryHasNoMutableGlobalEntries(t *testing.T) {
	a := Registry()
	delete(a, "files/files216.v1")
	if Registry()["files/files216.v1"] == nil {
		t.Fatal("registry mutation escaped")
	}
}

func TestCoupledAnonymousEventsKeepRawOperationAndDecision(t *testing.T) {
	for _, operation := range []uint32{19, 20, 21, 22, 23} {
		raw := fixture("files/files216.v1")
		put32(raw, 40, operation)
		for _, effect := range []uint32{0, 1} {
			put32(raw, 44, effect)
			got, err := Registry()["files/files216.v1"](raw)
			if operation >= 22 && effect == 1 {
				if err == nil {
					t.Fatal("unsupported anonymous I/O became an allowance")
				}
				continue
			}
			if err != nil || got.Decision == nil || *got.Decision != (effect == 1) {
				t.Fatal(operation, effect, got, err)
			}
		}
	}
	raw := fixture("files/files216.v1")
	put32(raw, 40, 24)
	if _, err := Registry()["files/files216.v1"](raw); err == nil {
		t.Fatal("unknown anonymous operation passed")
	}
}
