// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package heldprocess

import (
	"strings"
	"testing"
)

func TestStatParsingPreservesExactStartAcrossCommandCharacters(t *testing.T) {
	fields := append([]string{"T"}, make([]string, 19)...)
	for i := 1; i < len(fields); i++ {
		fields[i] = "0"
	}
	fields[19] = "98765432101234"
	v, err := parseIdentity("123 (helper ) with space) " + strings.Join(fields, " "))
	if err != nil || v.start != 98765432101234 || v.state != "T" {
		t.Fatalf("%+v %v", v, err)
	}
	for _, raw := range []string{"", "123 helper", "123 (x) T 0", "123 (x) " + strings.Repeat("0 ", 20)} {
		if _, err := parseIdentity(raw); err == nil {
			t.Fatal("invalid stat accepted")
		}
	}
}
func TestHeldStatusRejectsPrivilegeThreadsAndMissingFilter(t *testing.T) {
	raw := "Uid: 65534 65534 65534 65534\nGid: 65534 65534 65534 65534\nCapInh: 00000000\nCapPrm: 00000000\nCapEff: 00000000\nCapAmb: 00000000\nNoNewPrivs: 1\nThreads: 1\nSeccomp: 2\n"
	if e := status(raw, true); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(raw, "Threads: 1", "Threads: 2", 1), strings.Replace(raw, "CapEff: 00000000", "CapEff: 00000001", 1), strings.Replace(raw, "Uid: 65534", "Uid: 0", 1), strings.Replace(raw, "Seccomp: 2", "Seccomp: 0", 1), strings.Replace(raw, "NoNewPrivs: 1", "NoNewPrivs: 0", 1)} {
		if status(bad, true) == nil {
			t.Fatal("unsafe held process accepted")
		}
	}
	if !barrier("0 0x3 0x0 0x1") || barrier("1 0x3 0x0") || barrier("0 0x4 0x0") {
		t.Fatal("held syscall check differs")
	}
}
