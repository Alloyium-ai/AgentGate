// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"alloyium.local/kernel-poc/internal/enforcement"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"golang.org/x/sys/unix"
)

func candidateSupported(request qualification.Request) error {
	r := request.Document.Runtime
	if r.UID != 65534 || r.GID != 65534 || len(r.SupplementaryGroups) != 0 || len(r.Capabilities) != 0 || !r.NoNewPrivileges {
		return errors.New("the fixed qualification actor does not implement this runtime identity")
	}
	for _, name := range []string{"read", "write", "close", "openat", "lseek", "clock_gettime", "exit_group"} {
		if !slices.Contains(r.Seccomp.AllowSyscalls, name) {
			return fmt.Errorf("the fixed actor requires the candidate's explicit %s permission", name)
		}
	}
	for _, name := range []string{"getppid", "clone", "fork", "vfork", "pipe2", "eventfd2", "kill", "tkill", "tgkill"} {
		if slices.Contains(r.Seccomp.AllowSyscalls, name) {
			return fmt.Errorf("the fixed denial actor cannot test a positive %s grant", name)
		}
	}
	if len(request.Document.Network.Rules) != 0 || len(request.Document.Sockets.Rules) != 0 {
		return errors.New("the fixed denial actor requires empty network and socket rules")
	}
	if r.Memory != nil && slices.Contains(r.Memory.Anonymous, "execute") {
		return errors.New("the fixed denial actor does not implement a positive anonymous execute grant")
	}
	return nil
}

func (a *candidateDenial) runCandidate(ctx context.Context, request qualification.Request) (out qualification.Result, err error) {
	if err = candidateSupported(request); err != nil {
		return out, err
	}
	if err = kernel.Preflight(); err != nil {
		return out, err
	}
	if err = sourceBootMatches(request); err != nil {
		return out, err
	}
	if out.StartedMonoNS, err = kernel.MonotonicNS(); err != nil {
		return out, err
	}
	out.Binding = request.Binding
	r := candidateReceipt{Protocol: candidateReceiptVersion, Binding: request.Binding, BootstrapRole: qualificationBootstrapRole, BootstrapMode: listenerBootstrapMode, ExecutedPolicyDigest: request.Binding.PolicyDigest, Generation: 1, Artifacts: map[string]string{}, Streams: map[string][][]byte{}, Counters: map[string]kernel.Counters{}, PinRemovalErrno: map[string]int{}}
	r.ManagerPID = os.Getpid()
	defer func() { out.FinishedMonoNS, _ = kernel.MonotonicNS(); out.Raw, _ = json.Marshal(r) }()
	paths := map[string]string{}
	for _, name := range []string{"files", "peers", "sockets", "custody", "process", "anonymous", "syscalls", "qualification-denial-worker", "exec-broker"} {
		paths[name], err = a.measured(request, name, name == "qualification-denial-worker" || name == "exec-broker")
		if err != nil {
			return out, err
		}
		r.Artifacts[name] = request.Binding.ArtifactDigests[name]
	}
	io, err := a.prepareIO(request.Document)
	if io != nil {
		defer func() { err = errors.Join(err, io.close()) }()
	}
	if err != nil {
		return out, err
	}
	r.Domain = filepath.Join("/sys/fs/cgroup", "alloyium-poc-qualification-"+digestJSON(struct {
		Binding qualification.Binding
		Mono    uint64
	}{request.Binding, out.StartedMonoNS})[:16])
	if err = os.Mkdir(r.Domain, 0700); err != nil {
		return out, err
	}
	defer func() {
		if _, e := os.Lstat(r.Domain); e == nil {
			err = errors.Join(err, os.Remove(r.Domain))
		}
	}()
	var st unix.Stat_t
	if err = unix.Lstat(r.Domain, &st); err != nil {
		return out, err
	}
	r.DomainID = st.Ino
	g, err := enforcement.New(r.Domain, r.DomainID, enforcement.Artifacts{Files: paths["files"], Peers: paths["peers"], Sockets: paths["sockets"], Custody: paths["custody"], Process: paths["process"], Anonymous: paths["anonymous"]})
	if err != nil {
		return out, err
	}
	defer func() { err = errors.Join(err, g.Close()) }()
	observer, err := kernel.AttachOwnedProfile(paths["syscalls"], r.Domain, "syscalls", r.DomainID, syscallrules.RuntimeProfile())
	if err != nil {
		return out, err
	}
	observerOpen := true
	defer func() {
		if observerOpen {
			err = errors.Join(err, observer.Close())
		}
	}()
	r.Hooks = map[string][]string{}
	for name, runtime := range map[string]*kernel.Runtime{"files": g.Files, "peers": g.Peers, "sockets": g.Sockets, "custody": g.Custody, "process": g.Process, "anonymous": g.Anonymous, "syscalls": observer} {
		r.Hooks[name] = runtime.Hooks()
	}
	defer func() {
		if len(r.Streams) < 6 {
			err = errors.Join(err, collectStreams(g, observer, &r))
		}
	}()
	r.DeadlineNS = out.StartedMonoNS + uint64(20*time.Second)
	plan, err := enforcement.Compile(request.Document, r.DomainID, r.Generation, out.StartedMonoNS, r.DeadlineNS, nil)
	if err != nil {
		return out, err
	}
	r.PlanSHA256 = plan.Digest()
	r.FilterSHA256 = plan.Syscalls().Digest()
	if err = observer.Collection.Maps["audit_bindings"].Update(r.DomainID, syscallrules.Binding{Generation: r.Generation, ExpiresNS: r.DeadlineNS}, 0); err != nil {
		return out, err
	}
	actor, err := a.startActor(ctx, paths["qualification-denial-worker"], r.Artifacts["qualification-denial-worker"], io, plan.Syscalls(), digestJSON(request.Binding))
	if actor == nil {
		return out, err
	}
	r.Listener = actor.listenerData
	r.BootstrapReady = actor.ready
	r.SetupFilterSHA256 = actor.setupSHA256
	r.FinalFilterSHA256 = actor.finalSHA256
	defer func() {
		actor.stop()
		if actor.cmd.ProcessState != nil {
			r.ExitStatus = uint32(actor.cmd.ProcessState.Sys().(syscall.WaitStatus))
		}
		if raw, readErr := os.ReadFile(io.output); readErr == nil {
			r.RawRecords = raw
			r.Records, _ = decodeRecords(raw)
		}
	}()
	if err != nil {
		return out, err
	}
	r.HeldBefore, err = waitHeld(actor.cmd.Process.Pid, paths["qualification-denial-worker"], r.Artifacts["qualification-denial-worker"])
	if err != nil {
		return out, err
	}
	if memberSnapshot(r.HeldBefore, r.Domain) {
		return out, errors.New("the actor entered the domain before its measured hold")
	}
	if err = g.Files.Move(actor.cmd.Process.Pid); err != nil {
		return out, err
	}
	r.HeldPlaced, err = inspectProcess(actor.cmd.Process.Pid, r.HeldBefore.Executable, r.HeldBefore.ExecutableSHA256)
	if err != nil {
		return out, err
	}
	verify := func() error {
		current, e := inspectProcess(actor.cmd.Process.Pid, r.HeldBefore.Executable, r.HeldBefore.ExecutableSHA256)
		if e != nil {
			return e
		}
		if current.StartTimeTicks != r.HeldBefore.StartTimeTicks || !memberSnapshot(current, r.Domain) {
			return errors.New("the held qualification actor binding changed")
		}
		if e = validateProcess(current, true, "2"); e != nil {
			return e
		}
		if processFields(current.Status)["Seccomp_filters"] != "1" || len(current.Descriptors) != 0 {
			return errors.New("the held qualification actor filter count differs")
		}
		return nil
	}
	if err = g.Install(plan, verify); err != nil {
		return out, err
	}
	r.HeldInstalled, err = inspectProcess(actor.cmd.Process.Pid, r.HeldBefore.Executable, r.HeldBefore.ExecutableSHA256)
	if err != nil {
		return out, err
	}
	if r.Before, err = snapshotMaps(g, plan, request); err != nil {
		return out, err
	}
	if err = verify(); err != nil {
		return out, err
	}
	broker, err := a.startBroker(ctx, g, plan, request, actor, &r.Broker)
	if err != nil {
		return out, err
	}
	defer func() { err = errors.Join(err, g.Files.StopWorkload(), broker.stop(&r.Broker)) }()
	if err = actor.resume(); err != nil {
		return out, err
	}
	if err = actor.waitOutput(io.output, 24); err != nil {
		return out, err
	}
	r.Active, err = inspectProcess(actor.cmd.Process.Pid, r.HeldBefore.Executable, r.HeldBefore.ExecutableSHA256)
	if err != nil {
		return out, err
	}
	if err = validateProcess(r.Active, false, "2"); err != nil {
		return out, err
	}
	if processFields(r.Active.Status)["Seccomp_filters"] != "2" {
		return out, errors.New("the active qualification actor filter count differs")
	}
	if err = verifyActorDescriptors(request, r); err != nil {
		return out, err
	}
	if !memberSnapshot(r.Active, r.Domain) || r.Active.StartTimeTicks != r.HeldBefore.StartTimeTicks {
		return out, errors.New("the active qualification actor binding differs")
	}
	if raw, e := os.ReadFile(filepath.Join(r.Domain, "cgroup.procs")); e != nil {
		return out, e
	} else {
		r.ActiveMembers = string(raw)
	}
	if err = io.control(1); err != nil {
		return out, err
	}
	if err = actor.waitRecord(io.output, 99); err != nil {
		return out, err
	}
	r.FinalActive, err = inspectProcess(actor.cmd.Process.Pid, r.Active.Executable, r.Active.ExecutableSHA256)
	if err != nil {
		return out, err
	}
	if raw, e := os.ReadFile(filepath.Join(r.Domain, "cgroup.procs")); e != nil {
		return out, e
	} else {
		r.FinalMembers = string(raw)
	}
	if r.After, err = snapshotMaps(g, plan, request); err != nil {
		return out, err
	}
	if err = io.control(2); err != nil {
		return out, err
	}
	if candidateHeap(request) {
		if err = a.expireHeap(ctx, request, actor, io, g, plan, &r); err != nil {
			return out, err
		}
	}
	if err = actor.wait(); err != nil {
		return out, err
	}
	r.ExitStatus = uint32(actor.cmd.ProcessState.Sys().(syscall.WaitStatus))
	if r.RawRecords, err = os.ReadFile(io.output); err != nil {
		return out, err
	}
	if r.Records, err = decodeRecords(r.RawRecords); err != nil {
		return out, err
	}
	if err = g.Files.StopWorkload(); err != nil {
		return out, err
	}
	if raw, e := os.ReadFile(filepath.Join(r.Domain, "cgroup.events")); e != nil {
		return out, e
	} else {
		r.EmptyReadback = string(raw)
	}
	if err = broker.waitClosure(&r.Broker); err != nil {
		return out, err
	}
	if err = broker.stop(&r.Broker); err != nil {
		return out, err
	}
	if err = collectStreams(g, observer, &r); err != nil {
		return out, err
	}
	pins := map[string]string{}
	for name, runtime := range map[string]*kernel.Runtime{"files": g.Files, "peers": g.Peers, "sockets": g.Sockets, "custody": g.Custody, "process": g.Process, "anonymous": g.Anonymous, "syscalls": observer} {
		pins[name] = runtime.Pins
	}
	if err = observer.Close(); err != nil {
		return out, err
	}
	observerOpen = false
	if err = g.Close(); err != nil {
		return out, err
	}
	if err = os.Remove(r.Domain); err != nil {
		return out, err
	}
	r.DomainRemovalErrno = pathErrno(r.Domain)
	for name, path := range pins {
		r.PinRemovalErrno[name] = pathErrno(path)
	}
	return out, nil
}

func (a *actorProcess) wait() error { err := <-a.done; a.finished = true; return err }
func (a *actorProcess) stop() {
	if !a.finished {
		_ = a.cmd.Process.Kill()
		_ = a.wait()
	}
	if a.listener != nil {
		_ = a.listener.Close()
		a.listener = nil
	}
}
func (a *actorProcess) waitOutput(path string, minimum int64) error {
	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		if stat, err := os.Stat(path); err == nil && stat.Size() >= minimum {
			return nil
		}
		select {
		case <-a.brokerDone:
			return errors.New("the measured broker exited before the actor evidence")
		case err := <-a.done:
			a.finished = true
			return fmt.Errorf("the qualification actor exited before evidence: %v", err)
		default:
		}
		time.Sleep(time.Millisecond)
	}
	return errors.New("the qualification actor did not produce its phase record")
}
func (a *actorProcess) waitRecord(path string, id uint32) error {
	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(raw) > 24*64 {
			return errors.New("qualification actor record limit exceeded")
		}
		if len(raw)%24 == 0 {
			records, e := decodeRecords(raw)
			if e != nil {
				return e
			}
			for _, record := range records {
				if record.ID == id {
					return nil
				}
			}
		}
		select {
		case <-a.brokerDone:
			return errors.New("the measured broker exited before actor completion")
		case err := <-a.done:
			a.finished = true
			return fmt.Errorf("qualification actor exited before completion: %v", err)
		default:
		}
		time.Sleep(time.Millisecond)
	}
	return errors.New("qualification actor evidence timed out")
}
func decodeRecords(raw []byte) ([]scalarRecord, error) {
	if len(raw)%24 != 0 || len(raw) > 24*64 {
		return nil, errors.New("qualification actor record shape differs")
	}
	out := make([]scalarRecord, len(raw)/24)
	for i := range out {
		if err := binary.Read(bytes.NewReader(raw[i*24:(i+1)*24]), binary.LittleEndian, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}
func drainRaw(r *kernel.Runtime) ([][]byte, error) {
	r.Reader.SetDeadline(time.Now().Add(20 * time.Millisecond))
	out := [][]byte{}
	for {
		record, err := r.Reader.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, append([]byte{}, record.RawSample...))
		if len(out) > 65536 {
			return nil, errors.New("qualification stream record limit exceeded")
		}
	}
}
func collectStreams(g *enforcement.Group, observer *kernel.Runtime, r *candidateReceipt) error {
	for name, runtime := range map[string]*kernel.Runtime{"files": g.Files, "peers": g.Peers, "sockets": g.Sockets, "custody": g.Custody, "process": g.Process, "syscalls": observer} {
		if _, ok := r.Streams[name]; ok {
			continue
		}
		raw, err := drainRaw(runtime)
		if err != nil {
			return err
		}
		r.Streams[name] = raw
		counter, err := runtime.Counters()
		if err != nil {
			return err
		}
		r.Counters[name] = counter
	}
	return nil
}
func pathErrno(path string) int {
	_, err := os.Lstat(path)
	if err == nil {
		return 0
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return int(errno)
	}
	return -1
}
