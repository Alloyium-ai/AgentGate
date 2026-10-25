// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"alloyium.local/kernel-poc/internal/fsrules"
	"github.com/cilium/ebpf"
)

// stdio-grant DOMAIN INODE:read|write... records the command's stdio pipes in
// the running guard's pinned file component, before the command joins the
// domain. The gateway made those pipes outside the domain; the file component
// lets the job use an inherited pipe only by a recorded inode, in its recorded
// direction (bpf/fs_access.bpf.c, special_file). It refuses a populated
// domain, a pin directory or ownership marker that differs, and a second grant.

func parseStdioPipes(args []string) ([]fsrules.StdioPipe, error) {
	pipes := []fsrules.StdioPipe{}
	for _, arg := range args {
		inode, direction, ok := strings.Cut(arg, ":")
		value, err := strconv.ParseUint(inode, 10, 64)
		if !ok || err != nil || inode != strconv.FormatUint(value, 10) {
			return nil, fmt.Errorf("stdio pipe %q is not INODE:read or INODE:write", arg)
		}
		rights := map[string]uint32{"read": fsrules.StdioRead, "write": fsrules.StdioWrite}[direction]
		if rights == 0 {
			return nil, fmt.Errorf("stdio pipe %q is not INODE:read or INODE:write", arg)
		}
		pipes = append(pipes, fsrules.StdioPipe{Inode: value, Rights: rights})
	}
	return pipes, fsrules.ValidateStdio(pipes)
}

// hostPinDir is where the guard pins the domain's host-control maps (hostGuard.pin).
func hostPinDir(domain string) string {
	return filepath.Join("/sys/fs/bpf", "ag-mvp-host-"+filepath.Base(domain))
}

func checkPinDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || stat.Uid != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("host pin directory custody differs")
	}
	return nil
}

func stdioGrantCommand(args []string) error {
	if len(args) < 3 || os.Geteuid() != 0 {
		return errors.New("usage: pilot-network-diagnostic stdio-grant DOMAIN INODE:read|write...")
	}
	domain := args[1]
	pipes, err := parseStdioPipes(args[2:])
	if err != nil {
		return err
	}
	empty, err := domainIsEmpty(domain)
	if err != nil {
		return err
	}
	if !empty {
		return errors.New("stdio pipes are recorded only before the command joins its domain")
	}
	var stat syscall.Stat_t
	if err = syscall.Stat(domain, &stat); err != nil || stat.Ino == 0 {
		return errors.Join(err, errors.New("the domain has no inode"))
	}
	dir := hostPinDir(domain)
	if err = checkPinDir(dir); err != nil {
		return err
	}
	// The file component is the guard's first host collection.
	owned, err := ebpf.LoadPinnedMap(filepath.Join(dir, "map-0-owned"), nil)
	if err != nil {
		return fmt.Errorf("the guard's file component is not pinned: %w", err)
	}
	defer owned.Close()
	var marker uint32
	if err = owned.Lookup(stat.Ino, &marker); err != nil || marker != 1 {
		return errors.New("the pinned file component does not own this domain")
	}
	stdio, err := ebpf.LoadPinnedMap(filepath.Join(dir, "map-0-stdio"), nil)
	if err != nil {
		return fmt.Errorf("the pinned file component has no stdio map: %w", err)
	}
	defer stdio.Close()
	if err = fsrules.RecordStdio(stdio, stat.Ino, pipes); err != nil {
		return err
	}
	// The domain must still be empty: nothing could have used a pipe unrecorded.
	if empty, err = domainIsEmpty(domain); err != nil || !empty {
		return errors.Join(err, errors.New("the domain was populated while its stdio was recorded"))
	}
	fmt.Printf("{\"stdio_pipes_recorded\":%d}\n", len(pipes))
	return nil
}
