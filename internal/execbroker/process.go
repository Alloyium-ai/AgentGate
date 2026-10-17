// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package execbroker

import (
	"alloyium.local/kernel-poc/internal/childwire"
	"alloyium.local/kernel-poc/internal/heldprocess"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"
)

type Process struct {
	pidfd    int
	done     chan struct{}
	waitErr  error
	mu       sync.Mutex
	closed   bool
	identity ProcessIdentity
}

type ProcessIdentity struct {
	PID            int
	StartTimeTicks uint64
}

// Identity returns the immutable identity captured before the readiness barrier.
func (p *Process) Identity() ProcessIdentity { return p.identity }

func (p *Process) Done() <-chan struct{} { return p.done }
func (p *Process) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
		return p.waitErr
	}
}
func (p *Process) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	select {
	case <-p.done:
	default:
		if err := unix.PidfdSendSignal(p.pidfd, unix.SIGKILL, nil, 0); err != nil && err != unix.ESRCH {
			return err
		}
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			return errors.New("exec broker termination is unconfirmed")
		}
	}
	p.closed = true
	return unix.Close(p.pidfd)
}

// Start retains the listener in a measured process and waits for its pin readback.
// The owner must stop the whole job if Done closes before the workload exits.
func Start(ctx context.Context, executable, digest string, listener, audit, diagnostic *os.File, c Config) (out *Process, err error) {
	if err = c.Validate(); err != nil {
		return nil, err
	}
	if err = heldprocess.VerifyMeasuredArtifact(executable, digest); err != nil {
		return nil, err
	}
	if listener == nil || audit == nil || diagnostic == nil {
		return nil, errors.New("the broker listener and protected log files are required")
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	config, err := childwire.Seal("agentgate-exec-binding", raw)
	if err != nil {
		return nil, err
	}
	defer config.Close()
	ready, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer ready.Close()
	defer writer.Close()
	p := &Process{pidfd: -1, done: make(chan struct{})}
	cmd := exec.Command(executable, "--serve")
	cmd.Env = []string{}
	cmd.ExtraFiles = []*os.File{listener, config, writer}
	cmd.Stdout = audit
	cmd.Stderr = diagnostic
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, PidFD: &p.pidfd}
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if e := cmd.Start(); e != nil {
			started <- e
			return
		}
		started <- nil
		p.waitErr = cmd.Wait()
		close(p.done)
	}()
	if err = <-started; err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = p.Close()
		}
	}()
	p.identity.PID = cmd.Process.Pid
	p.identity.StartTimeTicks, err = lifecycle.ProcessStartTime(p.identity.PID)
	if err != nil {
		return nil, err
	}
	writer.Close()
	_ = ready.SetReadDeadline(time.Now().Add(5 * time.Second))
	var token [1]byte
	if _, err = ready.Read(token[:]); err != nil || token[0] != 1 {
		return nil, errors.New("the measured exec broker readiness failed")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return p, nil
}
