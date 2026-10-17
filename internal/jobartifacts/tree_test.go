// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobartifacts

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func packageTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "dist"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "dist", "cli.js"), []byte("pinned package"), 0444); err != nil {
		t.Fatal(err)
	}
	return root
}
func TestTreeDigestBindsBytesModesAndLinks(t *testing.T) {
	ctx := context.Background()
	root := packageTree(t)
	same := packageTree(t)
	first, err := DigestTree(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	other, err := DigestTree(ctx, same)
	if err != nil || first != other {
		t.Fatal("mount paths changed content identity", err)
	}
	if err = VerifyTree(ctx, root, first); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(root, "dist", "cli.js")
	if err = os.Chmod(entry, 0555); err != nil {
		t.Fatal(err)
	}
	if VerifyTree(ctx, root, first) == nil {
		t.Fatal("an executable mode change kept the package identity")
	}
	_ = os.Chmod(entry, 0444)
	if err = os.Symlink("dist/cli.js", filepath.Join(root, "cli")); err != nil {
		t.Fatal(err)
	}
	linked, err := DigestTree(ctx, root)
	if err != nil || linked == first {
		t.Fatal("a contained link was not measured", err)
	}
	if err = os.WriteFile(entry, []byte("different package"), 0444); err != nil {
		t.Fatal(err)
	}
	if VerifyTree(ctx, root, linked) == nil {
		t.Fatal("changed package bytes were accepted")
	}
}
func TestTreeRejectsExternalLinksSpecialObjectsAndWritableFiles(t *testing.T) {
	for _, makeBad := range []func(string) error{func(root string) error { return os.Symlink("/etc", filepath.Join(root, "external")) }, func(root string) error { return os.Chmod(filepath.Join(root, "dist", "cli.js"), 0666) }, func(root string) error {
		return os.Link(filepath.Join(root, "dist", "cli.js"), filepath.Join(root, "hard"))
	}} {
		root := packageTree(t)
		if err := makeBad(root); err != nil {
			t.Fatal(err)
		}
		if _, err := DigestTree(context.Background(), root); err == nil {
			t.Fatal("unsafe immutable package accepted")
		}
	}
	root := packageTree(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DigestTree(ctx, root); err == nil {
		t.Fatal("canceled tree measurement succeeded")
	}
	if VerifyTree(context.Background(), root, strings.Repeat("0", 64)) == nil {
		t.Fatal("an unrelated package digest was accepted")
	}
}
