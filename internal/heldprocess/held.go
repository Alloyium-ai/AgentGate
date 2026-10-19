// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package heldprocess owns the measured trusted bootstrap barrier.
package heldprocess

import (
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Spec struct {
	Executable, SHA256              string
	Arguments, Environment          []string
	ExtraFiles                      []*os.File
	RequireSeccomp                  bool
	RequireFilterAcknowledgement    bool
	NamespaceDevice, NamespaceInode uint64
	Docker                          bool
	NetworkDevice, NetworkInode     uint64
	PIDDevice, PIDInode             uint64
	RootDevice, RootInode           uint64
}
type Held struct {
	process                      lifecycle.HeldProcess
	spec                         Spec
	gate                         *os.File
	pipe                         string
	pidfd                        int
	launcherPidfd                int
	launcherPID                  int
	done                         chan struct{}
	waitErr                      error
	mu                           sync.Mutex
	released, closed, terminated bool
	filterAcknowledgement        []byte
}

func (h *Held) Process() lifecycle.HeldProcess { return h.process }
func (h *Held) ArtifactDigest() string         { return h.spec.SHA256 }

// VerifyMeasuredArtifact checks custody for a bounded trusted helper artifact.
func VerifyMeasuredArtifact(path, expected string) error { return artifact(path, expected) }
func (h *Held) BarrierInode() (uint64, error) {
	if !strings.HasPrefix(h.pipe, "pipe:[") || !strings.HasSuffix(h.pipe, "]") {
		return 0, errors.New("held pipe identity is invalid")
	}
	return strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(h.pipe, "pipe:["), "]"), 10, 64)
}
func artifact(path string, expected string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("a canonical trusted helper path is required")
	}
	var st unix.Stat_t
	var err error
	if err = unix.Lstat(path, &st); err != nil {
		return err
	}
	if st.Size <= 0 || st.Size > 16<<20 {
		return errors.New("trusted helper artifact size differs")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if len(expected) != 64 || hex.EncodeToString(sum[:]) != expected {
		return errors.New("trusted bootstrap artifact differs")
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&022 != 0 {
		return errors.New("trusted bootstrap artifact custody differs")
	}
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		if err = unix.Lstat(directory, &st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&022 != 0 {
			return errors.New("trusted bootstrap parent custody differs")
		}
		if directory == "/" {
			break
		}
	}
	return nil
}
func Start(ctx context.Context, spec Spec) (out *Held, err error) {
	if (spec.NamespaceDevice == 0) != (spec.NamespaceInode == 0) {
		return nil, errors.New("the held mount namespace identity is incomplete")
	}
	if spec.Docker && (spec.NamespaceDevice == 0 || spec.NetworkDevice == 0 || spec.NetworkInode == 0 ||
		spec.PIDDevice == 0 || spec.PIDInode == 0 || spec.RootDevice == 0 || spec.RootInode == 0) {
		return nil, errors.New("the held Docker target identity is incomplete")
	}
	if err = kernel.Preflight(); err != nil {
		return nil, err
	}
	if err = artifact(spec.Executable, spec.SHA256); err != nil {
		return nil, err
	}
	read, write, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer read.Close()
	ready, readyWriter, err := os.Pipe()
	if err != nil {
		write.Close()
		return nil, err
	}
	defer ready.Close()
	defer readyWriter.Close()
	h := &Held{spec: spec, gate: write, pidfd: -1, launcherPidfd: -1, done: make(chan struct{})}
	cmd := exec.Command(spec.Executable, spec.Arguments...)
	cmd.Env = append([]string{}, spec.Environment...)
	cmd.ExtraFiles = append([]*os.File{read, readyWriter}, spec.ExtraFiles...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, PidFD: &h.pidfd}
	// Linux binds Pdeathsig to the creating thread. Retain that thread until Wait.
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if startErr := cmd.Start(); startErr != nil {
			started <- startErr
			return
		}
		started <- nil
		h.waitErr = cmd.Wait()
		close(h.done)
	}()
	if err = <-started; err != nil {
		write.Close()
		return nil, err
	}
	defer func() {
		if err != nil {
			if stopErr := h.Close(); stopErr != nil {
				out = h
				err = errors.Join(err, stopErr)
			}
		}
	}()
	h.process.PID = cmd.Process.Pid
	if spec.Docker {
		h.launcherPID, h.launcherPidfd = h.process.PID, h.pidfd
		h.pidfd = -1
		_ = ready.SetReadDeadline(time.Now().Add(5 * time.Second))
		var report [12]byte
		if _, err = io.ReadFull(ready, report[:]); err != nil || string(report[:8]) != "AGPID001" {
			return nil, errors.New("the Docker held child PID report is unavailable")
		}
		h.process.PID = int(binary.LittleEndian.Uint32(report[8:]))
		if h.process.PID <= 1 || h.process.PID == h.launcherPID {
			return nil, errors.New("the Docker held child PID is unsafe")
		}
		if h.pidfd, err = unix.PidfdOpen(h.process.PID, 0); err != nil {
			return nil, err
		}
	}
	identity, err := readIdentity(h.process.PID)
	if err != nil {
		return nil, err
	}
	h.process.StartTimeTicks = identity.start
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	h.process.BarrierID = hex.EncodeToString(nonce[:])
	readyWriter.Close()
	_ = ready.SetReadDeadline(time.Now().Add(5 * time.Second))
	if spec.RequireFilterAcknowledgement {
		h.filterAcknowledgement = make([]byte, FilterAcknowledgementBytes)
		if _, err = io.ReadFull(ready, h.filterAcknowledgement); err != nil {
			return nil, errors.New("the trusted filter acknowledgement is unavailable")
		}
		if _, err = DecodeFilterAcknowledgement(h.filterAcknowledgement); err != nil {
			return nil, err
		}
	} else {
		var token [1]byte
		if _, err = ready.Read(token[:]); err != nil || token[0] != 1 {
			return nil, errors.New("trusted bootstrap readiness failed")
		}
	}
	h.pipe, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/3", h.process.PID))
	if err != nil || !strings.HasPrefix(h.pipe, "pipe:[") {
		return nil, errors.New("trusted bootstrap barrier descriptor differs")
	}
	if err = await(ctx, func() error { return h.verify(false) }); err != nil {
		return nil, err
	}
	if err = unix.PidfdSendSignal(h.pidfd, unix.SIGSTOP, nil, 0); err != nil {
		return nil, err
	}
	if err = await(ctx, func() error { return h.verify(true) }); err != nil {
		return nil, err
	}
	return h, nil
}
func await(ctx context.Context, check func() error) error {
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if err := check(); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("trusted held process verification timed out")
		case <-tick.C:
		}
	}
}
func (h *Held) Verify(ctx context.Context, process lifecycle.HeldProcess) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if h.process != process {
		return errors.New("held process immutable identity differs")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.released {
		return errors.New("held process barrier is unavailable")
	}
	return h.verify(true)
}
func (h *Held) Release(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if h.closed || h.released {
		return errors.New("held process release is not reusable")
	}
	if err := h.verify(true); err != nil {
		return err
	}
	if _, err := h.gate.Write([]byte{1}); err != nil {
		return err
	}
	if err := unix.PidfdSendSignal(h.pidfd, unix.SIGCONT, nil, 0); err != nil {
		return err
	}
	h.released = true
	return nil
}
func (h *Held) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-h.done:
		return h.waitErr
	}
}
func (h *Held) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.terminated {
		return nil
	}
	h.closed = true
	if h.gate != nil {
		_ = h.gate.Close()
	}
	finish := func() {
		if h.pidfd >= 0 {
			_ = unix.Close(h.pidfd)
			h.pidfd = -1
		}
		if h.launcherPidfd >= 0 {
			_ = unix.Close(h.launcherPidfd)
			h.launcherPidfd = -1
		}
		h.terminated = true
	}
	select {
	case <-h.done:
		finish()
		return nil
	default:
	}
	target := h.pidfd
	if target < 0 {
		target = h.launcherPidfd
	}
	if target < 0 {
		return errors.New("trusted helper pidfd custody is unavailable")
	}
	if err := unix.PidfdSendSignal(target, unix.SIGKILL, nil, 0); err != nil && err != unix.ESRCH {
		return err
	}
	select {
	case <-h.done:
		finish()
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("trusted helper termination is unconfirmed")
	}
}
