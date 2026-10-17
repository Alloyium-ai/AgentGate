//go:build childfixture

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package childwire

import (
	"os"
	"os/exec"
	"testing"
)

func TestMeasuredChildParsesOnlyBoundedExactFrames(t *testing.T) {
	binary := os.Getenv("AGENTGATE_CHILD_TEST")
	if binary == "" {
		t.Fatal("the measured child binary is required")
	}
	raw, err := Encode(manifest(), IOPaths{"/owned/input", "/owned/output", "/owned/error"})
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.CreateTemp(t.TempDir(), "owned-frame-")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	run := func(data []byte) error {
		if err := input.Truncate(0); err != nil {
			t.Fatal(err)
		}
		if _, err := input.Seek(0, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := input.Write(data); err != nil {
			t.Fatal(err)
		}
		if _, err := input.Seek(0, 0); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "--validate-frame")
		cmd.Stdin = input
		return cmd.Run()
	}
	if err = run(raw); err != nil {
		t.Fatalf("the exact frame failed: %v", err)
	}
	for i := 0; i < len(raw); i++ {
		if err = run(raw[:i]); err == nil {
			t.Fatalf("the child accepted truncation at byte%d", i)
		}
	}
	for i := 0; i < 20; i++ {
		bad := append([]byte{}, raw...)
		bad[i] = 255
		if err = run(bad); err == nil {
			t.Fatalf("the child accepted a malformed header at byte%d", i)
		}
	}
	if err = run(append(raw, 0)); err == nil {
		t.Fatal("the child accepted trailing bytes")
	}
	raw, err = EncodeNamespace(manifest(), IOPaths{"/owned/input", "/owned/output", "/owned/error"}, NamespaceIdentity{4, 998877})
	if err != nil || run(raw) != nil {
		t.Fatal("the exact namespace frame failed", err)
	}
	for i := 0; i < 40; i++ {
		if err = run(raw[:i]); err == nil {
			t.Fatalf("the child accepted a truncated namespace header at byte%d", i)
		}
	}
	for _, offset := range []int{8, 20, 24, 32} {
		bad := append([]byte{}, raw...)
		for i := offset; i < offset+4; i++ {
			bad[i] = 0
		}
		if offset == 32 {
			for i := 36; i < 40; i++ {
				bad[i] = 0
			}
		}
		if err = run(bad); err == nil {
			t.Fatalf("the child accepted a malformed namespace identity at byte%d", offset)
		}
	}
}
