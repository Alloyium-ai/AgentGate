// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"alloyium.local/kernel-poc/internal/enforcement"
	"alloyium.local/kernel-poc/internal/execbroker"
	"alloyium.local/kernel-poc/internal/fsrules"
	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"golang.org/x/sys/unix"
)

func verifyActorDescriptors(request qualification.Request, r candidateReceipt) error {
	for _, s := range []processSnapshot{r.HeldBefore, r.HeldPlaced, r.HeldInstalled} {
		if processFields(s.Status)["Seccomp_filters"] != "1" || len(s.Descriptors) != 0 {
			return errors.New("the held bootstrap descriptors or filter stack differ")
		}
	}
	if processFields(r.Active.Status)["Seccomp_filters"] != "2" || len(r.Active.Descriptors) != 2 {
		return errors.New("the candidate retains a bootstrap descriptor or lacks the final filter")
	}
	for i, id := range []string{"input", "output"} {
		path := ""
		for _, rule := range request.Document.Files.Rules {
			if rule.ID == id || rule.ID == "job-"+id {
				path = rule.Selector.Path
			}
		}
		d := r.Active.Descriptors[i]
		if path == "" || d.Number != fmt.Sprint(i) || d.Target != path || d.Mode&unix.S_IFMT != unix.S_IFREG || d.Mode&0777 != 0600 || d.UID != 65534 || d.GID != 65534 || d.Links != 1 || d.Inode == 0 {
			return errors.New("the active candidate regular descriptor differs")
		}
	}
	return nil
}

func verifyBrokerConfig(request qualification.Request, result qualification.Result, r candidateReceipt) error {
	c := r.Broker.Config
	if err := c.Validate(); err != nil {
		return err
	}
	if c.Domain != r.Domain || c.DomainID != r.DomainID || c.Generation != r.Generation || c.DeadlineNS != r.DeadlineNS || c.BootID != request.Binding.BootID || c.PolicyDigest != r.PlanSHA256 || c.Files != r.Before.Files {
		return errors.New("the measured broker binding or exact maps differ")
	}
	index := slices.Index(fsrules.AccessProfile().LSMPrograms, "fs_exec")
	if index < 0 || c.ExecLink != filepath.Join("/sys/fs/bpf", filepath.Base(r.Domain)+"-files", fmt.Sprintf("link-%d", index)) {
		return errors.New("the measured broker exec link differs")
	}
	s := r.Broker.Process
	fields := processFields(s.Status)
	if s.PID <= 1 || s.PID == r.Active.PID || s.StartTimeTicks == 0 || s.ExecutableSHA256 != request.Binding.ArtifactDigests["exec-broker"] || memberSnapshot(s, r.Domain) || fields["NoNewPrivs"] != "1" || strings.Join(strings.Fields(fields["Uid"]), " ") != "0 0 0 0" || strings.Join(strings.Fields(fields["Gid"]), " ") != "0 0 0 0" {
		return errors.New("the separate measured broker identity differs")
	}
	listener := false
	for _, fd := range s.Descriptors {
		if fd.Number == "3" && fd.Target == "anon_inode:seccomp notify" {
			listener = true
		}
	}
	if !listener || s.MonoNS < r.HeldInstalled.MonoNS || s.MonoNS > r.Broker.ParentListenerClosedMonoNS || r.Broker.ParentListenerClosedMonoNS >= r.Active.MonoNS || r.Broker.ParentListenerClosedErrno != int(unix.EBADF) || r.Broker.StoppedMonoNS < r.Active.MonoNS || r.Broker.StoppedMonoNS >= result.FinishedMonoNS || r.Broker.ProcessGoneErrno != int(unix.ENOENT) || r.Broker.ExitStatus != 256 {
		return errors.New("the broker listener custody, lifetime or cleanup differs")
	}
	return nil
}

func verifyBrokerClosure(r candidateReceipt, calls []syscallrules.Event) error {
	if err := uniqueJSON(r.Broker.Diagnostic); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(r.Broker.Diagnostic))
	decoder.DisallowUnknownFields()
	var closure execbroker.ListenerClosure
	if err := decoder.Decode(&closure); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("the broker closure contains extra data")
	}
	exitMono := uint64(0)
	lastResult := uint64(0)
	for _, call := range calls {
		if call.Type == syscallrules.Result && call.MonoNS > lastResult {
			lastResult = call.MonoNS
		}
		if call.Type == syscallrules.TaskExit && call.ExitCode == 0 {
			if exitMono != 0 {
				return errors.New("the broker closure contains multiple task exits")
			}
			exitMono = call.MonoNS
		}
	}
	flags := closure.PollFlags
	if closure.Protocol != "agentgate.listener-closure.v1" || closure.Domain != r.DomainID || closure.Generation != r.Generation || closure.DomainInode != r.DomainID || closure.ReadbackError != "" || flags&unix.POLLHUP == 0 || flags & ^int16(unix.POLLIN|unix.POLLERR|unix.POLLHUP) != 0 || exitMono == 0 || closure.MonotonicNS < lastResult || closure.MonotonicNS >= r.Broker.StoppedMonoNS || len(closure.Readbacks) == 0 || len(closure.Readbacks) > 33 {
		return errors.New("the broker closure lacks exact kernel flags, domain identity, ordering, or empty controls")
	}
	empty, err := closurePopulation(closure.Events)
	if err != nil || empty != closure.Empty {
		return errors.New("the first broker population readback differs")
	}
	previous := closure.MonotonicNS
	for i, sample := range closure.Readbacks {
		empty, err = closurePopulation(sample.Events)
		if err != nil || empty != sample.Empty || sample.MonotonicNS <= previous || sample.MonotonicNS >= r.Broker.StoppedMonoNS || sample.MonotonicNS-closure.MonotonicNS > 100_000_000 || (empty && i != len(closure.Readbacks)-1) {
			return errors.New("the repeated broker population readbacks or clocks differ")
		}
		if i == 0 && (!bytes.Equal(sample.Events, closure.Events) || sample.Empty != closure.Empty) {
			return errors.New("the broker replaced its first population readback")
		}
		previous = sample.MonotonicNS
	}
	final := closure.Readbacks[len(closure.Readbacks)-1]
	if !final.Empty || final.MonotonicNS < exitMono || !bytes.Equal(final.Events, []byte(r.EmptyReadback)) {
		return errors.New("the broker lacks an actual empty population readback after task exit")
	}
	return nil
}

func closurePopulation(raw []byte) (bool, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return false, errors.New("the broker population bytes exceed their bound")
	}
	seen := map[string]bool{}
	populated := ""
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || seen[fields[0]] || (fields[0] != "populated" && fields[0] != "frozen") || (fields[1] != "0" && fields[1] != "1") || (fields[0] == "frozen" && fields[1] != "0") {
			return false, errors.New("the broker closure domain controls differ")
		}
		seen[fields[0]] = true
		if fields[0] == "populated" {
			populated = fields[1]
		}
	}
	if len(seen) != 2 {
		return false, errors.New("the broker closure domain controls are incomplete")
	}
	return populated == "0", nil
}

func verifyListenerBootstrap(request qualification.Request, result qualification.Result, r candidateReceipt, plan enforcement.Plan) error {
	setup, final, err := plan.Syscalls().BootstrapFilters(4)
	if err != nil {
		return err
	}
	if filterDigest(setup) != r.SetupFilterSHA256 || filterDigest(final) != r.FinalFilterSHA256 {
		return errors.New("the exact bootstrap or final filter differs")
	}
	fd, _, err := listenerCustody(r.Listener, r.HeldBefore.PID, digestJSON(request.Binding))
	if err != nil {
		return err
	}
	if fd < 0 || fd != r.Listener.FD || r.Listener.FDFlags != unix.FD_CLOEXEC || r.Listener.FDTarget != "anon_inode:seccomp notify" || r.Listener.IDValidErrno != int(unix.ENOENT) || r.Listener.ReceivedMonoNS < result.StartedMonoNS || r.Listener.ReceivedMonoNS >= r.HeldBefore.MonoNS {
		return errors.New("the actual idle listener readback or transfer order differs")
	}
	ready := r.BootstrapReady
	if err = validateProcess(ready, false, "2"); err != nil {
		return err
	}
	if ready.PID != r.HeldBefore.PID || ready.StartTimeTicks != r.HeldBefore.StartTimeTicks || ready.Executable != r.HeldBefore.Executable || ready.ExecutableSHA256 != r.HeldBefore.ExecutableSHA256 || memberSnapshot(ready, r.Domain) || len(ready.Descriptors) != 0 || processFields(ready.Status)["Seccomp_filters"] != "1" || !strings.HasPrefix(processFields(ready.Status)["State"], "R") || ready.MonoNS <= r.Listener.ReceivedMonoNS || ready.MonoNS >= r.HeldBefore.MonoNS || r.ManagerPID <= 1 || r.ManagerPID == ready.PID {
		return errors.New("the descriptor-free bootstrap readiness or manager differs")
	}
	if err = verifyActorDescriptors(request, r); err != nil {
		return err
	}
	return verifyBrokerConfig(request, result, r)
}

func brokerDecisions(raw []byte) ([]execbroker.Decision, error) {
	if len(raw) > 2<<20 {
		return nil, errors.New("the measured broker audit exceeds its bound")
	}
	out := []execbroker.Decision{}
	for i, line := range bytes.Split(raw, []byte{'\n'}) {
		if len(line) == 0 {
			if i == bytes.Count(raw, []byte{'\n'}) {
				continue
			}
			return nil, errors.New("the measured broker audit contains an empty record")
		}
		if len(line) > 4096 || len(out) >= 4096 {
			return nil, errors.New("the measured broker record exceeds its bound")
		}
		if err := uniqueJSON(line); err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		var decision execbroker.Decision
		if err := decoder.Decode(&decision); err != nil {
			return nil, err
		}
		out = append(out, decision)
	}
	return out, nil
}

func verifyLiveHeapDecisions(request qualification.Request, r candidateReceipt, calls []syscallrules.Event, records map[uint32]scalarRecord) error {
	decisions, err := brokerDecisions(r.Broker.Audit)
	if err != nil {
		return err
	}
	heap := request.Document.Runtime.Memory != nil && request.Document.Runtime.Memory.Heap == "allow" && slices.Contains(request.Document.Runtime.Seccomp.AllowSyscalls, "brk")
	results := []syscallrules.Event{}
	for _, call := range calls {
		if call.Type == syscallrules.Result && call.SyscallID == unix.SYS_BRK && call.MonoNS >= r.Active.MonoNS {
			results = append(results, call)
		}
	}
	if !heap {
		if len(decisions) != 0 {
			return errors.New("the broker continued a heap allowance absent from the candidate")
		}
		return nil
	}
	if len(decisions) != 4 || len(results) != 4 || r.Expiry == nil {
		return errors.New("the heap broker lacks one exact decision for each actual heap call")
	}
	previous := r.Active.MonoNS
	seen := map[uint64]bool{}
	for i, decision := range decisions {
		if i == 3 {
			if decision.Protocol != "agentgate.exec-decision.v1" || decision.Domain != r.DomainID || decision.Generation != r.Generation || decision.NotificationID == 0 || seen[decision.NotificationID] || decision.PID != uint32(r.Active.PID) || decision.Syscall != unix.SYS_BRK || decision.Continued || decision.Reason != "expired-binding" || decision.MonotonicNS < r.Expiry.ResumedMonoNS || decision.MonotonicNS >= results[i].MonoNS || results[i].MonoNS < r.DeadlineNS || results[i].Result != -int64(unix.EPERM) {
				return errors.New("the expired heap notification lacks its actual denied allocation result")
			}
			continue
		}
		if decision.Protocol != "agentgate.exec-decision.v1" || decision.Domain != r.DomainID || decision.Generation != r.Generation || decision.NotificationID == 0 || seen[decision.NotificationID] || decision.PID != uint32(r.Active.PID) || decision.Syscall != unix.SYS_BRK || !decision.Continued || decision.Reason != "continue-live-heap" || decision.MonotonicNS <= previous || decision.MonotonicNS >= results[i].MonoNS || results[i].MonoNS >= r.DeadlineNS || results[i].Result != records[[]uint32{24, 25, 26}[i]].Result {
			return errors.New("the live heap notification and actual result differ")
		}
		seen[decision.NotificationID] = true
		previous = results[i].MonoNS
	}
	return nil
}
