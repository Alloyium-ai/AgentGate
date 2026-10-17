// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobartifacts

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func hashBytes(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }
func binding() lifecycle.Binding {
	return lifecycle.Binding{AgentID: "agent", AgentKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), JobDigest: strings.Repeat("a", 64), GrantID: "grant", RunID: "run", NodeID: "node", BootID: "boot", PolicyDigest: strings.Repeat("b", 64), SchemaDigest: strings.Repeat("c", 64), CompilerDigest: strings.Repeat("d", 64), ArtifactDigests: map[string]string{"node": strings.Repeat("e", 64)}, Generation: 1, DeadlineNS: 100}
}
func TestExecutableDigestAndParentCustody(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent")
	raw := []byte("immutable executable witness")
	if err := os.WriteFile(path, raw, 0755); err != nil {
		t.Fatal(err)
	}
	sum := hashBytes(raw)
	if err := VerifyExecutable(path, sum); err != nil {
		t.Fatal(err)
	}
	if VerifyExecutable(path, strings.Repeat("0", 64)) == nil {
		t.Fatal("the changed runtime digest was accepted")
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if VerifyExecutable(alias, sum) == nil {
		t.Fatal("an executable symlink was accepted")
	}
	if err := os.Chmod(path, 0775); err != nil {
		t.Fatal(err)
	}
	if VerifyExecutable(path, sum) == nil {
		t.Fatal("a writable executable was accepted")
	}
	os.Chmod(path, 0755)
	if err := os.Chmod(dir, 0775); err != nil {
		t.Fatal(err)
	}
	if VerifyExecutable(path, sum) == nil {
		t.Fatal("a writable artifact parent was accepted")
	}
}

func TestImmutableDataArtifactKeepsItsSeparateExecutionAndSizeChecks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "object.bpf.o")
	raw := []byte("owned object fixture")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	digest := hashBytes(raw)
	if err := VerifyDataFile(path, digest, 64); err != nil {
		t.Fatal(err)
	}
	if VerifyExecutable(path, digest) == nil {
		t.Fatal("a data artifact received executable custody")
	}
	if VerifyDataFile(path, digest, 1) == nil || VerifyDataFile(path, digest, 0) == nil {
		t.Fatal("a data artifact exceeded its declared bound")
	}
}
func TestStreamCustodyInputBindingAndOutputLimit(t *testing.T) {
	store, err := New(t.TempDir(), "node", 16)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	b := binding()
	input := []byte("actual input")
	if _, err = store.Prepare(b, hashBytes([]byte("other")), input); err == nil {
		t.Fatal("different job input was accepted")
	}
	streams, err := store.Prepare(b, hashBytes(input), input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Prepare(b, hashBytes(input), input); err == nil {
		t.Fatal("a run reused existing stream artifacts")
	}
	if err = os.WriteFile(streams.Paths.Output, []byte("result"), 0600); err != nil {
		t.Fatal(err)
	}
	output, diagnostic, err := store.Outputs(b)
	if err != nil || string(output) != "result" || len(diagnostic) != 0 {
		t.Fatalf("the owned output failed: %q %v", output, err)
	}
	if err = os.WriteFile(streams.Paths.Output, []byte(strings.Repeat("x", 17)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.Outputs(b); err == nil {
		t.Fatal("an oversized output was accepted")
	}
	os.Remove(streams.Paths.Output)
	if err = os.Symlink(streams.Paths.Input, streams.Paths.Output); err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.Outputs(b); err == nil {
		t.Fatal("an output symlink was followed")
	}
	b.NodeID = "foreign"
	if _, err = store.Paths(b); err == nil {
		t.Fatal("a foreign node selected artifacts")
	}
}
func TestOneConcurrentStreamPreparationWins(t *testing.T) {
	store, err := New(t.TempDir(), "node", 16)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for i := 0; i < 2; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); _, err := store.Prepare(binding(), hashBytes(nil), nil); results <- err }()
	}
	workers.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("preparation winners=%d", success)
	}
}
