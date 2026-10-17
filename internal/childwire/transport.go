// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package childwire

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/runtimeguard"
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"time"
	"unsafe"
)

type Transport struct {
	Job, Filters, Parent, Child *os.File
	ManifestDigest              string
	ListenerRequired            bool
	Namespace                   *os.File
	NamespaceIdentity           NamespaceIdentity
}

func New(manifest lifecycle.Manifest, paths IOPaths, plan runtimeguard.Plan) (out *Transport, err error) {
	return newTransport(manifest, paths, plan, nil, NamespaceIdentity{})
}
func NewNamespace(manifest lifecycle.Manifest, paths IOPaths, plan runtimeguard.Plan, file *os.File, identity NamespaceIdentity) (out *Transport, err error) {
	if file == nil {
		return nil, errors.New("the mount namespace descriptor is absent")
	}
	return newTransport(manifest, paths, plan, file, identity)
}
func newTransport(manifest lifecycle.Manifest, paths IOPaths, plan runtimeguard.Plan, namespace *os.File, identity NamespaceIdentity) (out *Transport, err error) {
	raw, err := Encode(manifest, paths)
	if namespace != nil {
		raw, err = EncodeNamespace(manifest, paths, identity)
	}
	if err != nil {
		return nil, err
	}
	filters, err := EncodeFilters(plan)
	if err != nil {
		return nil, err
	}
	t := &Transport{ListenerRequired: plan.RequiresExecListener()}
	defer func() {
		if err != nil {
			t.Close()
		}
	}()
	if namespace != nil {
		var st unix.Stat_t
		if err = unix.Fstat(int(namespace.Fd()), &st); err != nil {
			return nil, err
		}
		kind, _, typeErr := unix.Syscall(unix.SYS_IOCTL, namespace.Fd(), unix.NS_GET_NSTYPE, 0)
		if typeErr != 0 || kind != unix.CLONE_NEWNS || uint64(st.Dev) != identity.Device || st.Ino != identity.Inode {
			return nil, errors.New("the mount namespace descriptor identity differs")
		}
		fd, duplicateErr := unix.FcntlInt(namespace.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if duplicateErr != nil {
			return nil, duplicateErr
		}
		t.Namespace = os.NewFile(uintptr(fd), "trusted mount namespace")
		t.NamespaceIdentity = identity
	}
	t.ManifestDigest, err = manifest.Digest()
	if err != nil {
		return nil, err
	}
	if t.Job, err = Seal("agentgate-job", raw); err != nil {
		return nil, err
	}
	if t.Filters, err = Seal("agentgate-filter", filters); err != nil {
		return nil, err
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	t.Parent = os.NewFile(uintptr(pair[0]), "node listener receiver")
	t.Child = os.NewFile(uintptr(pair[1]), "trusted listener sender")
	if err = unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		return nil, err
	}
	return t, nil
}
func (t *Transport) ExtraFiles() []*os.File {
	files := []*os.File{t.Job, t.Filters, t.Child}
	if t.Namespace != nil {
		files = append(files, t.Namespace)
	}
	return files
}
func (t *Transport) Close() {
	for _, f := range []*os.File{t.Job, t.Filters, t.Parent, t.Child, t.Namespace} {
		if f != nil {
			_ = f.Close()
		}
	}
}
func (t *Transport) Receive(ctx context.Context, process lifecycle.HeldProcess) (*os.File, error) {
	if !t.ListenerRequired || t.Parent == nil || process.PID <= 1 {
		return nil, errors.New("an owned exec listener is not requested")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fds := []unix.PollFd{{Fd: int32(t.Parent.Fd()), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 100)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			continue
		}
		return t.receive(process)
	}
	return nil, errors.New("trusted listener transfer timed out")
}
func (t *Transport) receive(process lifecycle.HeldProcess) (out *os.File, err error) {
	data := make([]byte, 73)
	control := make([]byte, unix.CmsgSpace(4)+unix.CmsgSpace(unix.SizeofUcred))
	n, c, flags, _, err := unix.Recvmsg(int(t.Parent.Fd()), data, control, unix.MSG_CMSG_CLOEXEC|unix.MSG_DONTWAIT)
	if err != nil {
		return nil, err
	}
	messages, err := unix.ParseSocketControlMessage(control[:c])
	if err != nil {
		return nil, err
	}
	files := []int{}
	var credentials *unix.Ucred
	creds := 0
	unexpected := false
	for _, m := range messages {
		switch {
		case m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_RIGHTS:
			values, e := unix.ParseUnixRights(&m)
			if e != nil {
				unexpected = true
			} else {
				files = append(files, values...)
			}
		case m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_CREDENTIALS:
			creds++
			credentials, err = unix.ParseUnixCredentials(&m)
			if err != nil {
				unexpected = true
			}
		default:
			unexpected = true
		}
	}
	defer func() {
		if err != nil {
			for _, fd := range files {
				unix.Close(fd)
			}
		}
	}()
	if unexpected || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 || n != 72 || string(data[:8]) != "AGLSN001" || string(data[8:n]) != t.ManifestDigest || len(files) != 1 || creds != 1 || credentials == nil || credentials.Pid != int32(process.PID) || credentials.Uid != 65534 || credentials.Gid != 65534 {
		return nil, errors.New("trusted listener sender, descriptor or manifest differs")
	}
	id := uint64(0)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(files[0]), unix.SECCOMP_IOCTL_NOTIF_ID_VALID, uintptr(unsafe.Pointer(&id)))
	if errno != unix.ENOENT {
		return nil, errors.New("received descriptor is not an idle seccomp listener")
	}
	return os.NewFile(uintptr(files[0]), "owned seccomp listener"), nil
}
