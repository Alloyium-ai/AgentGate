// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/noderuntime"
	"golang.org/x/sys/unix"
)

type serviceLifecycleProcess struct {
	command    *exec.Cmd
	done       chan struct{}
	mu         sync.Mutex
	result     error
	pid        int
	startTicks uint64
}

func sealedServiceLifecycleStart(start noderuntime.QualificationStart) (*os.File, error) {
	if err := start.Validate(); err != nil {
		return nil, err
	}
	raw := serviceJSON(start)
	if len(raw) > 2<<20 {
		return nil, errors.New("the fixed fixture start exceeds its bound")
	}
	fd, err := unix.MemfdCreate("agentgate-fixed-qualification-start", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "qualification-start")
	ok := false
	defer func() {
		if !ok {
			file.Close()
		}
	}()
	if _, err = file.Write(raw); err != nil {
		return nil, err
	}
	if _, err = file.Seek(0, 0); err != nil {
		return nil, err
	}
	if _, err = unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return nil, err
	}
	ok = true
	return file, nil
}
func startServiceLifecycleProcess(ctx context.Context, path, hash, root, name string, args []string, files []*os.File) (*serviceLifecycleProcess, error) {
	if name != "node" && name != "node-restarted" && name != "watchdog" {
		return nil, errors.New("the fixed fixture process role differs")
	}
	if err := jobartifacts.VerifyExecutable(path, hash); err != nil {
		return nil, err
	}
	stdout, err := os.OpenFile(filepath.Join(root, "private", name+".stdout"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	stderr, err := os.OpenFile(filepath.Join(root, "private", name+".stderr"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		stdout.Close()
		return nil, err
	}
	command := exec.Command(path, args...)
	command.Env = []string{}
	command.ExtraFiles = files
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if name == "node" || name == "node-restarted" {
		command.SysProcAttr.Pdeathsig = syscall.SIGKILL
	}
	process := &serviceLifecycleProcess{command: command, done: make(chan struct{})}
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(process.done)
		defer stdout.Close()
		defer stderr.Close()
		process.mu.Lock()
		err := command.Start()
		for _, file := range files {
			file.Close()
		}
		if err != nil {
			process.result = err
			process.mu.Unlock()
			started <- err
			return
		}
		process.pid = command.Process.Pid
		process.startTicks, err = lifecycle.ProcessStartTime(process.pid)
		process.mu.Unlock()
		started <- err
		waitErr := command.Wait()
		process.mu.Lock()
		process.result = waitErr
		process.mu.Unlock()
	}()
	select {
	case err = <-started:
		if err != nil {
			return process, err
		}
		return process, nil
	case <-ctx.Done():
		return process, ctx.Err()
	}
}
func (p *serviceLifecycleProcess) signal(signal os.Signal) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	process, pid, ticks := p.command.Process, p.pid, p.startTicks
	p.mu.Unlock()
	if process == nil {
		return nil
	}
	current, err := lifecycle.ProcessStartTime(pid)
	if err != nil {
		select {
		case <-p.done:
			return nil
		default:
			return err
		}
	}
	if current != ticks {
		return errors.New("the fixed fixture PID start time differs")
	}
	return process.Signal(signal)
}

func (p *serviceLifecycleProcess) close() error {
	if p == nil {
		return nil
	}
	select {
	case <-p.done:
		return nil
	default:
	}
	if err := p.signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	timer := time.NewTimer(6 * time.Second)
	defer timer.Stop()
	select {
	case <-p.done:
		return nil
	case <-timer.C:
	}
	if err := p.signal(syscall.SIGKILL); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-p.done:
		return nil
	case <-time.After(time.Second):
		return errors.New("the fixed fixture process cleanup is unconfirmed")
	}
}
