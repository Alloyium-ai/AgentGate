// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package childwire encodes a signed manifest for a measured trusted child.
package childwire

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/runtimeguard"
	"bytes"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const MaxFrame = 131072
const ControlFD = 7
const NamespaceFD = 8

type IOPaths struct{ Input, Output, Error string }
type NamespaceIdentity struct{ Device, Inode uint64 }

func canonical(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && path != "/tmp" && !strings.HasPrefix(path, "/tmp/") && !strings.ContainsRune(path, 0)
}
func Encode(manifest lifecycle.Manifest, paths IOPaths) ([]byte, error) {
	return encode(manifest, paths, nil)
}
func EncodeNamespace(manifest lifecycle.Manifest, paths IOPaths, namespace NamespaceIdentity) ([]byte, error) {
	if namespace.Device == 0 || namespace.Inode == 0 {
		return nil, errors.New("the mount namespace identity is absent")
	}
	return encode(manifest, paths, &namespace)
}
func encode(manifest lifecycle.Manifest, paths IOPaths, namespace *NamespaceIdentity) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	for _, p := range []string{paths.Input, paths.Output, paths.Error} {
		if !canonical(p) {
			return nil, errors.New("canonical owned standard stream paths are required")
		}
	}
	if paths.Input == paths.Output || paths.Input == paths.Error || paths.Output == paths.Error {
		return nil, errors.New("standard stream artifacts must be distinct")
	}
	digest, err := manifest.Digest()
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	version := uint32(1)
	if namespace != nil {
		b.WriteString("AGJOB002")
		version = 2
	} else {
		b.WriteString("AGJOB001")
	}
	for _, n := range []uint32{version, uint32(len(manifest.Arguments)), uint32(len(manifest.Environment))} {
		_ = binary.Write(&b, binary.LittleEndian, n)
	}
	if namespace != nil {
		_ = binary.Write(&b, binary.LittleEndian, uint32(NamespaceFD))
		_ = binary.Write(&b, binary.LittleEndian, namespace.Device)
		_ = binary.Write(&b, binary.LittleEndian, namespace.Inode)
	}
	write := func(s string) { _ = binary.Write(&b, binary.LittleEndian, uint32(len(s))); b.WriteString(s) }
	for _, s := range []string{digest, manifest.Executable, manifest.Workspace, paths.Input, paths.Output, paths.Error} {
		write(s)
	}
	for _, s := range manifest.Arguments {
		write(s)
	}
	keys := make([]string, 0, len(manifest.Environment))
	for k := range manifest.Environment {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		write(k + "=" + manifest.Environment[k])
	}
	if b.Len() > MaxFrame {
		return nil, errors.New("trusted child declaration exceeds its byte bound")
	}
	return b.Bytes(), nil
}
func EncodeFilters(plan runtimeguard.Plan) ([]byte, error) {
	first := plan.Filters()
	var last []unix.SockFilter
	flags := uint32(0)
	if plan.RequiresExecListener() {
		var err error
		first, last, err = plan.BootstrapFilters(ControlFD)
		if err != nil {
			return nil, err
		}
		flags = 1
	}
	if len(first) == 0 || len(first) > 4096 || len(last) > 4096 {
		return nil, errors.New("trusted child filter bounds differ")
	}
	var b bytes.Buffer
	b.WriteString("AGFLT001")
	for _, n := range []uint32{flags, uint32(len(first)), uint32(len(last))} {
		_ = binary.Write(&b, binary.LittleEndian, n)
	}
	for _, part := range [][]unix.SockFilter{first, last} {
		for _, f := range part {
			_ = binary.Write(&b, binary.LittleEndian, f)
		}
	}
	return b.Bytes(), nil
}
func Seal(name string, data []byte) (*os.File, error) {
	if len(data) == 0 || len(data) > MaxFrame {
		return nil, errors.New("sealed child input exceeds its bound")
	}
	fd, err := unix.MemfdCreate(name, unix.MFD_ALLOW_SEALING|unix.MFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	if _, err = f.Write(data); err != nil {
		return nil, err
	}
	if _, err = f.Seek(0, 0); err != nil {
		return nil, err
	}
	seals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err = unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		return nil, err
	}
	actual, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || actual&seals != seals {
		return nil, errors.New("trusted child input is not sealed")
	}
	ok = true
	return f, nil
}
