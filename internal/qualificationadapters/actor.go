// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"alloyium.local/kernel-poc/internal/runtimeguard"
	"golang.org/x/sys/unix"
)

type actorProcess struct {
	cmd                      *exec.Cmd
	done                     chan error
	finished                 bool
	listener                 *os.File
	listenerData             listenerReceipt
	ready                    processSnapshot
	setupSHA256, finalSHA256 string
	brokerDone               <-chan struct{}
}

func actorFilters(file *os.File, plan runtimeguard.Plan, binding string) (setupSHA, finalSHA string, err error) {
	if len(binding) != 64 {
		return "", "", errors.New("the actor requires its exact binding digest")
	}
	setup, final, err := plan.BootstrapFilters(4)
	if err != nil {
		return "", "", err
	}
	if _, err = file.Write([]byte("AGQCF002")); err != nil {
		return "", "", err
	}
	for _, count := range []uint16{uint16(len(setup)), uint16(len(final))} {
		if err = binary.Write(file, binary.LittleEndian, count); err != nil {
			return "", "", err
		}
	}
	if _, err = file.Write([]byte(binding)); err != nil {
		return "", "", err
	}
	for _, filters := range [][]unix.SockFilter{setup, final} {
		if err = binary.Write(file, binary.LittleEndian, filters); err != nil {
			return "", "", err
		}
	}
	_, err = file.Seek(0, 0)
	return filterDigest(setup), filterDigest(final), err
}

func (a *candidateDenial) startActor(ctx context.Context, path, workerHash string, io *ownedIO, plan runtimeguard.Plan, binding string) (actor *actorProcess, err error) {
	file, err := os.CreateTemp(a.config.ScratchRoot, ".qualification-filter-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	setup, final, err := actorFilters(file, plan, binding)
	if err != nil {
		return nil, err
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parent := os.NewFile(uintptr(pair[0]), "qualification listener receiver")
	defer parent.Close()
	child := os.NewFile(uintptr(pair[1]), "qualification listener sender")
	defer child.Close()
	if err = unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if actor != nil {
				actor.stop()
			}
		}
	}()
	cmd := exec.CommandContext(ctx, path, io.input, io.output, "candidate-listener")
	cmd.Env = []string{}
	cmd.ExtraFiles = []*os.File{file, child}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	actor = &actorProcess{cmd: cmd, done: make(chan error, 1), setupSHA256: setup, finalSHA256: final}
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if e := cmd.Start(); e != nil {
			started <- e
			return
		}
		started <- nil
		actor.done <- cmd.Wait()
		close(actor.done)
	}()
	if err = <-started; err != nil {
		actor = nil
		return nil, err
	}
	actor.listener, actor.listenerData, err = receiveListener(ctx, parent, cmd.Process.Pid, binding)
	if err != nil {
		return actor, err
	}
	actor.ready, err = waitBootstrapReady(ctx, cmd.Process.Pid, path, workerHash)
	if err != nil {
		return actor, err
	}
	err = cmd.Process.Signal(syscall.SIGSTOP)
	return actor, err
}

func (a *actorProcess) resume() error {
	return a.cmd.Process.Signal(syscall.SIGCONT)
}
