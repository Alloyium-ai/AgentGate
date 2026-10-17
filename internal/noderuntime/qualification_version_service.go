// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"

	"alloyium.local/kernel-poc/internal/lifecycle"
	"golang.org/x/sys/unix"
)

func readQualificationVersionStart(file *os.File) (QualificationVersionStart, error) {
	var out QualificationVersionStart
	if file == nil || os.Geteuid() != 0 {
		return out, errors.New("the native version start requires a root sealed descriptor")
	}
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	want := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	var st unix.Stat_t
	if err != nil || seals&want != want || unix.Fstat(int(file.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Size <= 0 || st.Size > 2<<20 {
		return out, errors.New("the native version descriptor custody differs")
	}
	raw := make([]byte, st.Size)
	if _, err = file.ReadAt(raw, 0); err != nil {
		return out, err
	}
	if err = lifecycle.DecodeTransport(bytes.NewReader(raw), &out); err != nil {
		return out, err
	}
	return out, out.Validate()
}

// RunQualificationVersion exposes only a measured parent's inherited control pair.
func RunQualificationVersion(ctx context.Context) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	file := os.NewFile(3, "sealed native version start")
	defer file.Close()
	start, err := readQualificationVersionStart(file)
	if err != nil {
		return err
	}
	base := QualificationStart{Protocol: start.Protocol, NodeConfigFile: start.NodeConfigFile, Spec: lifecycle.QualificationFixtureSpec(start.Spec), Parent: start.Parent}
	return runQualificationNode(ctx, base, &start.Spec)
}
