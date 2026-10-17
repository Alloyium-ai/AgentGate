// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package childwire

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

// Declaration retains the exact immutable frames handed to the measured helper.
// It describes supplied filters; syscall evidence must prove their installation.
type Declaration struct {
	Job         []byte
	Filters     []byte
	JobSeals    int
	FilterSeals int
}

func sealedFrame(f *os.File) ([]byte, int, error) {
	if f == nil {
		return nil, 0, errors.New("the sealed helper frame is absent")
	}
	seals, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	want := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	var st unix.Stat_t
	if err != nil || seals&want != want || unix.Fstat(int(f.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Size <= 0 || st.Size > MaxFrame {
		return nil, 0, errors.New("the helper frame seals or size differ")
	}
	raw := make([]byte, st.Size)
	if _, err = f.ReadAt(raw, 0); err != nil {
		return nil, 0, err
	}
	return raw, seals, nil
}
func (t *Transport) Declaration() (Declaration, error) {
	var out Declaration
	var err error
	if out.Job, out.JobSeals, err = sealedFrame(t.Job); err != nil {
		return out, err
	}
	out.Filters, out.FilterSeals, err = sealedFrame(t.Filters)
	return out, err
}
