// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"bytes"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"unsafe"
)

func readQualificationStart(f *os.File) (QualificationStart, error) {
	var out QualificationStart
	if f == nil || os.Geteuid() != 0 {
		return out, errors.New("the fixed fixture requires a root sealed descriptor")
	}
	seals, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	want := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	var st unix.Stat_t
	if err != nil || seals&want != want || unix.Fstat(int(f.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Size <= 0 || st.Size > 2<<20 {
		return out, errors.New("the fixed fixture start descriptor custody differs")
	}
	raw := make([]byte, st.Size)
	if _, err = f.ReadAt(raw, 0); err != nil {
		return out, err
	}
	if err = lifecycle.DecodeTransport(bytes.NewReader(raw), &out); err != nil {
		return out, err
	}
	return out, out.Validate()
}

func verifyQualificationParent(s QualificationStart) error {
	if s.Parent.PID != os.Getppid() {
		return errors.New("the fixed fixture parent differs")
	}
	start, err := lifecycle.ProcessStartTime(s.Parent.PID)
	if err != nil || start != s.Parent.StartTimeTicks {
		return errors.New("the fixed fixture parent identity differs")
	}
	if err = jobartifacts.VerifyProcessExecutable(s.Parent.PID, s.Spec.Binding.ArtifactDigests["qualification"]); err != nil {
		return err
	}
	start, err = lifecycle.ProcessStartTime(s.Parent.PID)
	if err != nil || start != s.Parent.StartTimeTicks || s.Parent.PID != os.Getppid() {
		return errors.New("the fixed fixture parent changed during measurement")
	}
	return nil
}

// inheritedQualificationConn accepts only an unnamed, root-created stream pair.
// SO_PEERCRED records the pair creator, which must be the measured parent.
func inheritedQualificationConn(f *os.File, parent lifecycle.DaemonIdentity) (net.Conn, error) {
	if f == nil {
		return nil, errors.New("the fixed fixture socket descriptor is absent")
	}
	fd := int(f.Fd())
	kind, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || kind != unix.SOCK_STREAM {
		return nil, errors.New("the fixed fixture socket type differs")
	}
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if !unnamedQualificationSocket(fd, unix.SYS_GETSOCKNAME) || !unnamedQualificationSocket(fd, unix.SYS_GETPEERNAME) || err != nil || cred == nil || cred.Uid != 0 || cred.Gid != 0 || int(cred.Pid) != parent.PID {
		return nil, errors.New("the fixed fixture socket creator differs")
	}
	start, err := lifecycle.ProcessStartTime(parent.PID)
	if err != nil || start != parent.StartTimeTicks {
		return nil, errors.New("the fixed fixture socket parent changed")
	}
	conn, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func unnamedQualificationSocket(fd int, operation uintptr) bool {
	var addr unix.RawSockaddrAny
	size := uint32(unix.SizeofSockaddrAny)
	_, _, errno := unix.Syscall(operation, uintptr(fd), uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)))
	return errno == 0 && size == 2 && addr.Addr.Family == unix.AF_UNIX
}

func readQualificationReply(r io.Reader, out any) error {
	raw, err := io.ReadAll(io.LimitReader(r, (2<<20)+1))
	if err != nil {
		return err
	}
	if len(raw) > 2<<20 {
		return errors.New("the fixed fixture response exceeds its bound")
	}
	return lifecycle.DecodeTransport(bytes.NewReader(raw), out)
}
