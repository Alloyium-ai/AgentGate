// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualification

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func protectedFixture(t *testing.T) string {
	t.Helper()
	root := os.Getenv("AGENTGATE_TEST_SCRATCH")
	if root == "" {
		t.Skip("protected qualification tests require explicit owned scratch")
	}
	if os.Geteuid() != 0 {
		t.Fatal("protected qualification fixture requires UID0")
	}
	dir, err := os.MkdirTemp(root, "qualification-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}
func TestProtectedReadRejectsUnsafeCustodyAndBounds(t *testing.T) {
	dir := protectedFixture(t)
	path := filepath.Join(dir, "inventory.json")
	if err := os.WriteFile(path, []byte(`{"actual":"fixture"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if raw, err := ReadProtected(path, 1024); err != nil || string(raw) != `{"actual":"fixture"}` {
		t.Fatalf("read failed: %s %v", raw, err)
	}
	if _, err := ReadProtected(path, 2); err == nil {
		t.Fatal("oversized input accepted")
	}
	link := filepath.Join(dir, "linked")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProtected(link, 1024); err == nil {
		t.Fatal("linked input accepted")
	}
	if err := os.Chmod(path, 0660); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProtected(path, 1024); err == nil {
		t.Fatal("group-writable input accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(dir, "hard")
	if err := os.Link(path, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProtected(path, 1024); err == nil {
		t.Fatal("multiply linked input accepted")
	}
	if err := os.Remove(hard); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProtected(path, 1024); err == nil {
		t.Fatal("writable parent accepted")
	}
}
func TestLocalInspectorRequiresEveryArtifactMeasurement(t *testing.T) {
	c, _, _, _ := producerFixture(t)
	base := LocalConfig{Expected: c.Expected, InventoryFile: "/var/lib/agentgate/inventory.json", Measurements: map[string]Measurement{}}
	if _, err := NewLocalInspector(base); err == nil {
		t.Fatal("missing artifact measurements accepted")
	}
	base.Expected.ArtifactDigests = map[string]string{"qualification": strings.Repeat("1", 64), "target-probe": strings.Repeat("2", 64), "domain-root": strings.Repeat("3", 64)}
	base.Measurements = map[string]Measurement{"qualification": {Kind: "file", Path: "/opt/agentgate/qualify"}, "target-probe": {Kind: "file", Path: "/opt/agentgate/target-probe"}, "domain-root": {Kind: "cgroup-root", OwnedPrefix: "agj-fixture-", RootReceipt: strings.Repeat("4", 64)}}
	if _, err := NewLocalInspector(base); err != nil {
		t.Fatal(err)
	}
	base.Measurements["qualification"] = Measurement{Kind: "asserted-hash", Path: "/opt/agentgate/qualify"}
	if _, err := NewLocalInspector(base); err == nil {
		t.Fatal("caller-defined measurement accepted")
	}
	base.Measurements["qualification"] = Measurement{Kind: "file", Path: "/opt/agentgate/qualify"}
	base.Expected.ArtifactDigests["resolver"] = strings.Repeat("5", 64)
	base.Measurements["resolver"] = Measurement{Kind: "resolver", Path: "/var/lib/agentgate/node.json"}
	if _, err := NewLocalInspector(base); err != nil {
		t.Fatal("the protected resolver measurement was rejected", err)
	}
	base.Measurements["resolver"] = Measurement{Kind: "file", Path: "/var/lib/agentgate/node.json"}
	if _, err := NewLocalInspector(base); err == nil {
		t.Fatal("a resolver digest passed as a file hash")
	}
	base.Measurements["resolver"] = Measurement{Kind: "resolver", Path: "/tmp/node.json"}
	if _, err := NewLocalInspector(base); err == nil {
		t.Fatal("an unprotected resolver configuration passed")
	}
}
