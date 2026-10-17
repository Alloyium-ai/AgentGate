// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"alloyium.local/kernel-poc/internal/enforcement"
	"alloyium.local/kernel-poc/internal/execbroker"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/qualification"
	"golang.org/x/sys/unix"
)

type ownedBroker struct {
	process           *execbroker.Process
	audit, diagnostic *os.File
	closed            bool
}

func (b *ownedBroker) waitClosure(receipt *brokerReceipt) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := b.process.Wait(ctx)
	var exited *exec.ExitError
	if !errors.As(err, &exited) {
		return errors.Join(errors.New("the broker did not supply its actual closure exit"), err)
	}
	status, ok := exited.Sys().(syscall.WaitStatus)
	if !ok {
		return errors.New("the broker closure wait status is unavailable")
	}
	receipt.ExitStatus = uint32(status)
	if !status.Exited() || status.ExitStatus() != 1 {
		return errors.New("the broker closure exit differs")
	}
	return nil
}

func (a *candidateDenial) startBroker(ctx context.Context, g *enforcement.Group, plan enforcement.Plan, request qualification.Request, actor *actorProcess, receipt *brokerReceipt) (out *ownedBroker, err error) {
	out = &ownedBroker{}
	defer func() {
		if err != nil {
			err = errors.Join(err, out.stop(receipt))
		}
	}()
	receipt.Config, err = g.ExecBrokerConfig(plan, request.Binding.BootID)
	if err != nil {
		return out, err
	}
	out.audit, err = os.CreateTemp(a.config.ScratchRoot, ".qualification-broker-audit-")
	if err != nil {
		return out, err
	}
	out.diagnostic, err = os.CreateTemp(a.config.ScratchRoot, ".qualification-broker-diagnostic-")
	if err != nil {
		return out, err
	}
	path := a.config.Artifacts["exec-broker"]
	out.process, err = execbroker.Start(ctx, path, request.Binding.ArtifactDigests["exec-broker"], actor.listener, out.audit, out.diagnostic, receipt.Config)
	if err != nil {
		return out, err
	}
	identity := out.process.Identity()
	receipt.Process, err = inspectProcess(identity.PID, path, request.Binding.ArtifactDigests["exec-broker"])
	if err != nil {
		return out, err
	}
	if receipt.Process.StartTimeTicks != identity.StartTimeTicks {
		return out, errors.New("the measured broker process identity changed")
	}
	fd := int(actor.listener.Fd())
	if err = actor.listener.Close(); err != nil {
		return out, err
	}
	actor.listener = nil
	_, closeErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	var errno syscall.Errno
	if !errors.As(closeErr, &errno) || errno != unix.EBADF {
		return out, errors.New("the manager retains its listener descriptor")
	}
	receipt.ParentListenerClosedErrno = int(errno)
	receipt.ParentListenerClosedMonoNS, err = kernel.MonotonicNS()
	if err != nil {
		return out, err
	}
	actor.brokerDone = out.process.Done()
	return out, nil
}

func collectBrokerFile(file *os.File) (raw []byte, err error) {
	if file == nil {
		return nil, nil
	}
	var opened, actual unix.Stat_t
	if err = unix.Fstat(int(file.Fd()), &opened); err != nil {
		return nil, err
	}
	if err = unix.Lstat(file.Name(), &actual); err != nil {
		return nil, err
	}
	if opened.Dev != actual.Dev || opened.Ino != actual.Ino || actual.Mode&unix.S_IFMT != unix.S_IFREG || actual.Mode&0777 != 0600 || actual.Uid != 0 || actual.Nlink != 1 {
		return nil, errors.New("the protected broker log changed")
	}
	defer func() { err = errors.Join(err, file.Close(), os.Remove(file.Name())) }()
	if _, err = file.Seek(0, 0); err != nil {
		return nil, err
	}
	raw, err = io.ReadAll(io.LimitReader(file, (2<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 2<<20 {
		return nil, errors.New("the protected broker log exceeds its bound")
	}
	return raw, nil
}

func (b *ownedBroker) stop(receipt *brokerReceipt) (err error) {
	if b == nil || b.closed {
		return nil
	}
	b.closed = true
	if b.process != nil {
		err = b.process.Close()
		if err == nil {
			receipt.StoppedMonoNS, err = kernel.MonotonicNS()
			identity := b.process.Identity()
			receipt.ProcessGoneErrno = pathErrno(fmt.Sprintf("/proc/%d", identity.PID))
			if receipt.ProcessGoneErrno != int(unix.ENOENT) {
				err = errors.Join(err, errors.New("the measured broker termination readback differs"))
			}
		}
	}
	var auditErr, diagnosticErr error
	receipt.Audit, auditErr = collectBrokerFile(b.audit)
	receipt.Diagnostic, diagnosticErr = collectBrokerFile(b.diagnostic)
	return errors.Join(err, auditErr, diagnosticErr)
}
