// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"
	"unsafe"

	"alloyium.local/kernel-poc/internal/kernel"
	"golang.org/x/sys/unix"
)

func filterDigest(filters []unix.SockFilter) string {
	var raw bytes.Buffer
	_ = binary.Write(&raw, binary.LittleEndian, filters)
	return digestBytes(raw.Bytes())
}

func listenerCustody(r listenerReceipt, pid int, bindingDigest string) (fd int, received []int, err error) {
	fd = -1
	messages, err := unix.ParseSocketControlMessage(r.Control)
	if err != nil {
		return fd, received, err
	}
	var credentials *unix.Ucred
	creds := 0
	unexpected := false
	for _, message := range messages {
		switch {
		case message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_RIGHTS:
			values, e := unix.ParseUnixRights(&message)
			if e != nil {
				unexpected = true
			} else {
				received = append(received, values...)
			}
		case message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_CREDENTIALS:
			creds++
			credentials, err = unix.ParseUnixCredentials(&message)
			if err != nil {
				unexpected = true
			}
		default:
			unexpected = true
		}
	}
	if unexpected || r.Flags & ^(unix.MSG_CMSG_CLOEXEC|unix.MSG_EOR) != 0 || len(r.Data) != 72 || string(r.Data[:8]) != "AGQSN001" || string(r.Data[8:]) != bindingDigest || len(received) != 1 || creds != 1 || credentials == nil || credentials.Pid != int32(pid) || credentials.Uid != 65534 || credentials.Gid != 65534 {
		return fd, received, errors.New("the qualification listener sender, binding or descriptors differ")
	}
	return received[0], received, nil
}

func receiveListener(ctx context.Context, parent *os.File, pid int, bindingDigest string) (out *os.File, r listenerReceipt, err error) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err = ctx.Err(); err != nil {
			return nil, r, err
		}
		poll := []unix.PollFd{{Fd: int32(parent.Fd()), Events: unix.POLLIN}}
		n, e := unix.Poll(poll, 100)
		if e == unix.EINTR {
			continue
		}
		if e != nil {
			return nil, r, e
		}
		if n == 0 {
			continue
		}
		data := make([]byte, 73)
		control := make([]byte, unix.CmsgSpace(4)+unix.CmsgSpace(unix.SizeofUcred))
		count, controls, flags, _, e := unix.Recvmsg(int(parent.Fd()), data, control, unix.MSG_CMSG_CLOEXEC|unix.MSG_DONTWAIT)
		if e == unix.EINTR || e == unix.EAGAIN {
			continue
		}
		if e != nil {
			return nil, r, e
		}
		r.Data = append([]byte{}, data[:count]...)
		r.Control = append([]byte{}, control[:controls]...)
		r.Flags = flags
		fd, received, e := listenerCustody(r, pid, bindingDigest)
		defer func() {
			if err != nil {
				for _, value := range received {
					_ = unix.Close(value)
				}
			}
		}()
		if e != nil {
			return nil, r, e
		}
		r.FD = fd
		r.FDTarget, e = os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		if e != nil {
			return nil, r, e
		}
		r.FDFlags, e = unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if e != nil {
			return nil, r, e
		}
		id := uint64(0)
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_ID_VALID, uintptr(unsafe.Pointer(&id)))
		r.IDValidErrno = int(errno)
		if r.FDTarget != "anon_inode:seccomp notify" || r.FDFlags != unix.FD_CLOEXEC || errno != unix.ENOENT {
			return nil, r, errors.New("the received descriptor is not an idle protected seccomp listener")
		}
		r.ReceivedMonoNS, err = kernel.MonotonicNS()
		if err != nil {
			return nil, r, err
		}
		return os.NewFile(uintptr(fd), "qualification seccomp listener"), r, nil
	}
	return nil, r, errors.New("the measured qualification listener transfer timed out")
}
