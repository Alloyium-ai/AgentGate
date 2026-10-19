// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"debug/elf"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func openInTarget(root *os.File, path string) (*os.File, error) {
	fd, err := unix.Openat2(int(root.Fd()), path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// The ELF interpreter must resolve to a file in the measured target closure.
func verifyRuntimeInterpreterAt(root *os.File, executable string, files []runtimeclosure.File) error {
	f, err := openInTarget(root, executable)
	if err != nil {
		return err
	}
	defer f.Close()
	binary, err := elf.NewFile(f)
	if err != nil || binary.Class != elf.ELFCLASS64 || binary.Machine != elf.EM_X86_64 || binary.Data != elf.ELFDATA2LSB {
		return errors.New("the target runtime ELF architecture differs")
	}
	found := false
	for _, program := range binary.Progs {
		if program.Type != elf.PT_INTERP {
			continue
		}
		if found || program.Filesz < 2 || program.Filesz > 4096 {
			return errors.New("the target ELF interpreter is invalid")
		}
		found = true
		raw, readErr := io.ReadAll(io.LimitReader(program.Open(), 4097))
		if readErr != nil || len(raw) != int(program.Filesz) || raw[len(raw)-1] != 0 || strings.IndexByte(string(raw[:len(raw)-1]), 0) >= 0 {
			return errors.New("the target ELF interpreter path is invalid")
		}
		path := string(raw[:len(raw)-1])
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("the target ELF interpreter path is not canonical")
		}
		interpreter, openErr := openInTarget(root, path)
		if openErr != nil {
			return openErr
		}
		var expected unix.Stat_t
		openErr = unix.Fstat(int(interpreter.Fd()), &expected)
		_ = interpreter.Close()
		if openErr != nil {
			return openErr
		}
		matched := false
		for _, measured := range files {
			candidate, candidateErr := openInTarget(root, measured.Path)
			if candidateErr != nil {
				return candidateErr
			}
			var actual unix.Stat_t
			candidateErr = unix.Fstat(int(candidate.Fd()), &actual)
			_ = candidate.Close()
			if candidateErr != nil {
				return candidateErr
			}
			if actual.Dev == expected.Dev && actual.Ino == expected.Ino {
				matched = true
			}
		}
		if !matched {
			return errors.New("the target ELF interpreter has no measured runtime file")
		}
	}
	return nil
}
