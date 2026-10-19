// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dockerplacement

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// HostAlias binds a target's ordinary hostname lookup to one trusted lease.
// The kernel endpoint map remains the authority for every connection.
type HostAlias struct {
	Name    string
	Address netip.Addr
}

func aliases(raw []byte, wanted []HostAlias) error {
	if len(wanted) == 0 || len(raw) > 64<<10 {
		return errors.New("the target hostname mapping is absent or oversized")
	}
	expected := make(map[string]map[netip.Addr]bool)
	for _, alias := range wanted {
		if alias.Name == "" || alias.Name != strings.ToLower(alias.Name) ||
			!alias.Address.IsValid() || alias.Address.Is4In6() || alias.Address.Zone() != "" {
			return errors.New("the trusted hostname lease is invalid")
		}
		if expected[alias.Name] == nil {
			expected[alias.Name] = make(map[netip.Addr]bool)
		}
		expected[alias.Name][alias.Address] = true
	}
	actual := make(map[string]map[netip.Addr]bool)
	for _, line := range strings.Split(string(raw), "\n") {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 2 {
			return errors.New("the target hosts file has an invalid entry")
		}
		address, err := netip.ParseAddr(fields[0])
		if err != nil || address.Is4In6() || address.Zone() != "" {
			return errors.New("the target hosts file has an invalid address")
		}
		for _, name := range fields[1:] {
			if expected[name] == nil {
				continue
			}
			if actual[name] == nil {
				actual[name] = make(map[netip.Addr]bool)
			}
			actual[name][address] = true
		}
	}
	for name, addresses := range expected {
		if len(actual[name]) != len(addresses) {
			return errors.New("the target hostname mapping differs from the trusted lease")
		}
		for address := range addresses {
			if !actual[name][address] {
				return errors.New("the target hostname mapping differs from the trusted lease")
			}
		}
	}
	return nil
}

// VerifyHostAliases reads the measured target root, without granting the
// workload a resolver or an address outside the signed kernel lease.
func VerifyHostAliases(root *os.File, wanted []HostAlias) error {
	if root == nil {
		return errors.New("the measured Docker root is absent")
	}
	fd, err := unix.Openat2(int(root.Fd()), "etc/hosts", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "target hosts")
	defer file.Close()
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != 0 || stat.Mode&0022 != 0 || stat.Size > 64<<10 {
		return errors.New("the target hosts file custody differs")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	if err != nil {
		return err
	}
	return aliases(raw, wanted)
}
