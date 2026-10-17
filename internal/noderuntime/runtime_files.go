// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"debug/elf"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// The ELF interpreter must resolve to an explicitly measured file. Kernel file
// permissions still decide each loader and library read and executable mapping.
func verifyRuntimeInterpreter(executable string, files []runtimeclosure.File) error {
	fd, err := unix.Open(executable, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), executable)
	defer f.Close()
	binary, err := elf.NewFile(f)
	if err != nil {
		return errors.New("the registered runtime requires a measured native ELF executable")
	}
	if binary.Class != elf.ELFCLASS64 || binary.Machine != elf.EM_X86_64 || binary.Data != elf.ELFDATA2LSB {
		return errors.New("the runtime ELF architecture differs")
	}
	found := false
	for _, p := range binary.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		if found || p.Filesz < 2 || p.Filesz > 4096 {
			return errors.New("the runtime ELF interpreter is invalid")
		}
		found = true
		raw, e := io.ReadAll(io.LimitReader(p.Open(), 4097))
		if e != nil {
			return e
		}
		if len(raw) != int(p.Filesz) || raw[len(raw)-1] != 0 || strings.IndexByte(string(raw[:len(raw)-1]), 0) >= 0 {
			return errors.New("the runtime ELF interpreter path is invalid")
		}
		path := string(raw[:len(raw)-1])
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("the runtime ELF interpreter path is not canonical")
		}
		resolved, e := filepath.EvalSymlinks(path)
		if e != nil {
			return e
		}
		matched := false
		for _, file := range files {
			if file.Path == resolved {
				matched = true
			}
		}
		if !matched {
			return errors.New("the dynamic ELF interpreter has no explicit runtime file measurement")
		}
	}
	return nil
}
