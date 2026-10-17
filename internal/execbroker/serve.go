// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package execbroker

import (
	"alloyium.local/kernel-poc/internal/fsrules"
	"alloyium.local/kernel-poc/internal/kernel"
	"context"
	"errors"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

func ioctl(fd int, operation uintptr, value unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), operation, uintptr(value))
	if errno != 0 {
		return errno
	}
	return nil
}
func protected(path string) error {
	for {
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return err
		}
		if st.Uid != 0 || st.Mode&022 != 0 || st.Mode&unix.S_IFMT == unix.S_IFLNK {
			return errors.New("exec broker pin custody differs")
		}
		if path == "/" {
			return nil
		}
		path = filepath.Dir(path)
	}
}
func sizes() error {
	var v struct{ Notification, Response, Data uint16 }
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_GET_NOTIF_SIZES, 0, uintptr(unsafe.Pointer(&v)))
	if errno != 0 {
		return errno
	}
	if int(v.Notification) != int(unsafe.Sizeof(Notification{})) || int(v.Response) != int(unsafe.Sizeof(Response{})) || int(v.Data) != int(unsafe.Sizeof(Data{})) {
		return errors.New("the target notification ABI differs")
	}
	return nil
}

// Serve must run in an owned dedicated process. Its owner kills that process on
// cancellation, because NOTIF_RECV can block after a concurrent task cancellation.
func Serve(ctx context.Context, listener *os.File, c Config, emit func(Decision) error, ready func() error) error {
	if err := kernel.Preflight(); err != nil {
		return err
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if listener == nil || emit == nil {
		return errors.New("the listener and durable decision writer are required")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(boot)) != c.BootID {
		return errors.New("the exec broker boot differs")
	}
	if err = sizes(); err != nil {
		return err
	}
	if err = protected(c.ExecLink); err != nil {
		return err
	}
	l, err := link.LoadPinnedLink(c.ExecLink, nil)
	if err != nil {
		return err
	}
	defer l.Close()
	info, err := l.Info()
	if err != nil {
		return err
	}
	if uint32(info.Program) != c.ExecProgramID {
		return errors.New("the exec link program differs")
	}
	pins := filepath.Dir(c.ExecLink)
	state, err := ebpf.LoadPinnedMap(filepath.Join(pins, "policies"), nil)
	if err != nil {
		return err
	}
	defer state.Close()
	managed, err := ebpf.LoadPinnedMap(filepath.Join(pins, "owned"), nil)
	if err != nil {
		return err
	}
	defer managed.Close()
	installed := func() error {
		var actual fsrules.State
		var marker uint32
		if err := managed.Lookup(c.DomainID, &marker); err != nil {
			return err
		}
		if marker != 1 {
			return errors.New("the managed marker differs")
		}
		if err := state.Lookup(c.DomainID, &actual); err != nil {
			return err
		}
		if actual != c.Files {
			return errors.New("the installed file state differs")
		}
		return nil
	}
	if err = installed(); err != nil {
		return err
	}
	if ready == nil {
		return errors.New("the exec broker requires an owned readiness barrier")
	}
	if err = ready(); err != nil {
		return err
	}
	runtime := &kernel.Runtime{Domain: c.Domain, ID: c.DomainID}
	count := 0
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		_, e := kernel.MonotonicNS()
		if e != nil {
			return e
		}
		wait := []unix.PollFd{{Fd: int32(listener.Fd()), Events: unix.POLLIN}}
		n, e := unix.Poll(wait, 100)
		if e == unix.EINTR {
			continue
		}
		if e != nil {
			return e
		}
		if n == 0 {
			continue
		}
		if wait[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return observeListenerClosure(c, wait[0].Revents)
		}
		var notification Notification
		if err = ioctl(int(listener.Fd()), unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&notification)); err == unix.EINTR || err == unix.ENOENT {
			continue
		} else if err != nil {
			return err
		}
		if err = ioctl(int(listener.Fd()), unix.SECCOMP_IOCTL_NOTIF_ID_VALID, unsafe.Pointer(&notification.ID)); err == unix.ENOENT {
			continue
		} else if err != nil {
			return err
		}
		count++
		if count > 4096 {
			return errors.New("the notification bound was exceeded")
		}
		response, responseErr := responseFor(c, notification, kernel.MonotonicNS, runtime.VerifyMember, installed, emit)
		if responseErr != nil {
			return responseErr
		}
		if err = ioctl(int(listener.Fd()), unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&response)); err == unix.ENOENT {
			continue
		} else if err != nil {
			return err
		}
	}
}
