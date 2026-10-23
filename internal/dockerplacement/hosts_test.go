// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dockerplacement

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTrustedHostAliasesRequireExactAddressSet(t *testing.T) {
	wanted := []HostAlias{{"example.org", netip.MustParseAddr("93.184.215.14")},
		{"example.org", netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")}}
	good := []byte("127.0.0.1 localhost\n93.184.215.14 example.org\n2606:2800:220:1:248:1893:25c8:1946 example.org # trusted\n")
	if err := aliases(good, wanted); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"missing v6":    []byte("93.184.215.14 example.org\n"),
		"extra private": append(append([]byte{}, good...), []byte("10.0.0.1 example.org\n")...),
		"changed v4":    []byte("93.184.215.15 example.org\n2606:2800:220:1:248:1893:25c8:1946 example.org\n"),
		"wrong name":    []byte("93.184.215.14 other.org\n2606:2800:220:1:248:1893:25c8:1946 example.org\n"),
		"invalid line":  append(append([]byte{}, good...), []byte("broken\n")...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := aliases(raw, wanted); err == nil {
				t.Fatal("untrusted hostname mapping passed")
			}
		})
	}
}

func TestHostAliasReadUsesMeasuredRootAndCustody(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root file custody")
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	hosts := filepath.Join(root, "etc", "hosts")
	if err := os.WriteFile(hosts, []byte("93.184.215.14 example.org\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "test target root")
	defer file.Close()
	wanted := []HostAlias{{"example.org", netip.MustParseAddr("93.184.215.14")}}
	if err := VerifyHostAliases(file, wanted); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(hosts, 0666); err != nil {
		t.Fatal(err)
	}
	if err := VerifyHostAliases(file, wanted); err == nil {
		t.Fatal("writable hosts file passed")
	}
}
