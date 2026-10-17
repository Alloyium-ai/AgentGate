// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package runtimeclosure

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pin(path, data string) File {
	sum := sha256.Sum256([]byte(data))
	return File{Path: path, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(data)), Mode: 0644, GID: 0}
}
func fixture(t *testing.T) (string, []File) {
	t.Helper()
	scratch := os.Getenv("AGENTGATE_TEST_SCRATCH")
	if scratch == "" || os.Geteuid() != 0 {
		t.Skip("the custody gate requires root and an owned private scratch directory")
	}
	root, err := os.MkdirTemp(scratch, "runtime-closure-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(root, 0700); os.RemoveAll(root) })
	files := []File{pin(filepath.Join(root, "a.so"), "alpha"), pin(filepath.Join(root, "z.so"), "zulu")}
	for i, file := range files {
		data := []string{"alpha", "zulu"}[i]
		if err = os.WriteFile(file.Path, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
		if err = os.Chmod(file.Path, 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root, files
}
func TestExplicitEmptyClosureAndCanonicalCopyIsolation(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("an omitted closure became an explicit empty closure")
	}
	empty, err := New([]File{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := empty.Verify(context.Background())
	if err != nil || m.Protocol != Version || m.Digest != empty.Digest() || m.Files == nil || len(m.Files) != 0 || m.TotalBytes != 0 {
		t.Fatal("the static empty closure differs", err)
	}
	a := pin("/opt/runtime/a.so", "alpha")
	z := pin("/opt/runtime/z.so", "zulu")
	input := []File{z, a}
	set, err := New(input)
	if err != nil {
		t.Fatal(err)
	}
	ordered, _ := New([]File{a, z})
	if set.Digest() != ordered.Digest() || len(set.Digest()) != 64 || set.Digest() == empty.Digest() {
		t.Fatal("the canonical set digest differs")
	}
	input[0].SHA256 = strings.Repeat("0", 64)
	copy := set.Files()
	copy[0].Path = "/changed"
	if set.Digest() != ordered.Digest() || set.Files()[0].Path != a.Path {
		t.Fatal("caller mutation changed the immutable set")
	}
	for _, change := range []func(*File){func(f *File) { f.Path += "-other" }, func(f *File) { f.SHA256 = strings.Repeat("a", 64) }, func(f *File) { f.Bytes++ }, func(f *File) { f.Mode = 0600 }, func(f *File) { f.GID = 1 }} {
		changed := a
		change(&changed)
		next, err := New([]File{changed, z})
		if err != nil || next.Digest() == set.Digest() {
			t.Fatal("a configured field escaped the digest", err)
		}
	}
}
func TestConfigurationBoundsAndCanonicalPaths(t *testing.T) {
	base := pin("/opt/runtime/a.so", "alpha")
	for _, test := range []struct {
		name   string
		change func(*File)
	}{
		{"relative", func(f *File) { f.Path = "relative.so" }}, {"root", func(f *File) { f.Path = "/" }}, {"tmp", func(f *File) { f.Path = "/tmp/a.so" }}, {"unclean", func(f *File) { f.Path = "/opt/runtime/../a.so" }}, {"newline", func(f *File) { f.Path = "/opt/a\n.so" }}, {"nul", func(f *File) { f.Path = "/opt/a\x00.so" }},
		{"uppercase-hash", func(f *File) { f.SHA256 = strings.ToUpper(f.SHA256) }}, {"short-hash", func(f *File) { f.SHA256 = "ab" }}, {"negative-size", func(f *File) { f.Bytes = -1 }}, {"large-file", func(f *File) { f.Bytes = MaxFileBytes + 1 }}, {"group-write", func(f *File) { f.Mode = 0664 }}, {"world-write", func(f *File) { f.Mode = 0646 }}, {"setuid", func(f *File) { f.Mode = 04755 }}, {"invalid-group", func(f *File) { f.GID = ^uint32(0) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := base
			test.change(&f)
			if _, err := New([]File{f}); !errors.Is(err, ErrConfiguration) {
				t.Fatal("invalid file configuration passed", err)
			}
		})
	}
	if _, err := New([]File{base, base}); err == nil {
		t.Fatal("duplicate paths passed")
	}
	for _, name := range []string{"count", "total"} {
		t.Run(name, func(t *testing.T) {
			files := []File{}
			count := MaxFiles + 1
			if name == "total" {
				count = 5
			}
			for i := 0; i < count; i++ {
				f := base
				f.Path = fmt.Sprintf("/opt/runtime/%03d.so", i)
				if name == "total" {
					f.Bytes = MaxFileBytes
				}
				files = append(files, f)
			}
			if _, err := New(files); err == nil {
				t.Fatal("the closure limit passed")
			}
		})
	}
	if _, err := (Set{}).Verify(context.Background()); err == nil {
		t.Fatal("the zero set measured")
	}
	set, _ := New([]File{})
	if _, err := set.Verify(nil); err == nil {
		t.Fatal("a nil context passed")
	}
}
func TestProtectedFilesReturnOnlyExactMetadata(t *testing.T) {
	_, files := fixture(t)
	set, err := New(files)
	if err != nil {
		t.Fatal(err)
	}
	m, err := set.Verify(context.Background())
	if err != nil || m.Digest != set.Digest() || m.TotalBytes != 9 || len(m.Files) != 2 {
		t.Fatal(m, err)
	}
	raw, err := json.Marshal(m)
	if err != nil || strings.Contains(string(raw), "alpha") || strings.Contains(string(raw), "zulu") {
		t.Fatal("file contents escaped the measurement", err)
	}
	m.Files[0].Path = "/caller-change"
	if set.Files()[0].Path != files[0].Path {
		t.Fatal("measurement changed the set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = set.Verify(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestCustodyRejectsWrongInodesOwnersModesAndLinks(t *testing.T) {
	for _, name := range []string{"digest", "size", "mode", "group", "owner", "hardlink", "symlink", "directory", "parent-link", "parent-write", "missing"} {
		t.Run(name, func(t *testing.T) {
			root, files := fixture(t)
			f := files[0]
			switch name {
			case "digest":
				f.SHA256 = strings.Repeat("a", 64)
			case "size":
				f.Bytes++
			case "mode":
				f.Mode = 0600
			case "group":
				f.GID = 1
			case "owner":
				if err := os.Chown(f.Path, 1000, 0); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(f.Path, filepath.Join(root, "linked")); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(f.Path, filepath.Join(root, "symbolic")); err != nil {
					t.Fatal(err)
				}
				f.Path = filepath.Join(root, "symbolic")
			case "directory":
				f.Path = root
			case "parent-link":
				actual := filepath.Join(root, "actual")
				if err := os.Mkdir(actual, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(f.Path, filepath.Join(actual, "a.so")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(actual, filepath.Join(root, "alias")); err != nil {
					t.Fatal(err)
				}
				f.Path = filepath.Join(root, "alias/a.so")
			case "parent-write":
				if err := os.Chmod(root, 0770); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(f.Path); err != nil {
					t.Fatal(err)
				}
			}
			set, err := New([]File{f})
			if err != nil {
				t.Fatal(err)
			}
			if m, err := set.Verify(context.Background()); err == nil || m.Digest != "" || m.Files != nil {
				t.Fatal("unsafe custody produced a measurement", m, err)
			}
		})
	}
}
func TestCompleteSetReadbackDetectsEarlierFileChanges(t *testing.T) {
	for _, name := range []string{"contents", "replacement", "parent-permission", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			root, files := fixture(t)
			set, _ := New(files)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hash := func(ctx context.Context, f *os.File, size int64) (string, error) {
				if f.Name() == files[1].Path {
					switch name {
					case "contents":
						if err := os.WriteFile(files[0].Path, []byte("bravo"), 0644); err != nil {
							t.Fatal(err)
						}
					case "replacement":
						if err := os.Remove(files[0].Path); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(files[0].Path, []byte("alpha"), 0644); err != nil {
							t.Fatal(err)
						}
					case "parent-permission":
						if err := os.Chmod(root, 0770); err != nil {
							t.Fatal(err)
						}
					case "cancelled":
						cancel()
					}
				}
				return hashFile(ctx, f, size)
			}
			m, err := set.verify(ctx, hash)
			if err == nil || m.Digest != "" || m.Files != nil {
				t.Fatal("a changing closure measured", m, err)
			}
			if name == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if name != "cancelled" && !errors.Is(err, ErrChanged) {
				t.Fatal(err)
			}
		})
	}
}
