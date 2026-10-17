// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"alloyium.local/kernel-poc/internal/anonrules"
	"alloyium.local/kernel-poc/internal/enforcement"
	"alloyium.local/kernel-poc/internal/fsrules"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/nodeaudit"
	"alloyium.local/kernel-poc/internal/processrules"
	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"golang.org/x/sys/unix"
)

func parseCandidate(raw []byte) (candidateReceipt, error) {
	var out candidateReceipt
	if len(raw) == 0 || len(raw) > 32<<20 {
		return out, errors.New("qualification raw evidence size differs")
	}
	if err := uniqueJSON(raw); err != nil {
		return out, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}
func verifyActorBinding(request qualification.Request, result qualification.Result, r candidateReceipt) error {
	if r.BootstrapRole != qualificationBootstrapRole || !reflect.DeepEqual(r.Binding, request.Binding) || !reflect.DeepEqual(result.Binding, request.Binding) || r.ExecutedPolicyDigest != request.Binding.PolicyDigest {
		return errors.New("qualification evidence binding or fixture role differs")
	}
	if result.StartedMonoNS == 0 || result.FinishedMonoNS <= result.StartedMonoNS || r.Generation != 1 || r.DomainID == 0 || r.DeadlineNS <= result.StartedMonoNS {
		return errors.New("qualification evidence clock or domain differs")
	}
	if r.Expiry == nil && r.DeadlineNS <= result.FinishedMonoNS {
		return errors.New("qualification exceeded cutoff without its fixed expiry phase")
	}
	if r.Expiry != nil && (result.FinishedMonoNS <= r.DeadlineNS || result.FinishedMonoNS-r.DeadlineNS > 5_000_000_000) {
		return errors.New("qualification expiry completion clock differs")
	}
	if filepath.Dir(r.Domain) != "/sys/fs/cgroup" || !strings.HasPrefix(filepath.Base(r.Domain), "alloyium-poc-qualification-") {
		return errors.New("qualification evidence names a foreign domain")
	}
	prior := result.StartedMonoNS
	snapshots := []processSnapshot{r.HeldBefore, r.HeldPlaced, r.HeldInstalled, r.Active}
	if r.Protocol == candidateReceiptVersion {
		snapshots = append(snapshots, r.FinalActive)
	}
	for i, s := range snapshots {
		seccomp := "0"
		if i >= 3 || r.BootstrapMode == listenerBootstrapMode {
			seccomp = "2"
		}
		if err := validateProcess(s, i < 3, seccomp); err != nil {
			return err
		}
		if s.PID != r.HeldBefore.PID || s.StartTimeTicks != r.HeldBefore.StartTimeTicks || s.Executable != r.HeldBefore.Executable || s.ExecutableSHA256 != request.Binding.ArtifactDigests["qualification-denial-worker"] || s.MonoNS < prior || s.MonoNS >= result.FinishedMonoNS {
			return errors.New("qualification actor changed across the held transition")
		}
		if (i == 0) == memberSnapshot(s, r.Domain) {
			return errors.New("qualification actor placement order differs")
		}
		prior = s.MonoNS
	}
	names := []string{"files", "peers", "sockets", "custody", "process", "anonymous", "syscalls", "qualification-denial-worker"}
	if r.BootstrapMode == listenerBootstrapMode {
		names = append(names, "exec-broker")
	}
	for _, name := range names {
		if r.Artifacts[name] == "" || r.Artifacts[name] != request.Binding.ArtifactDigests[name] {
			return fmt.Errorf("qualification measured artifact differs: %s", name)
		}
	}
	if len(r.Artifacts) != len(names) || r.ExitStatus != 0 || r.DomainRemovalErrno != int(unix.ENOENT) || !strings.Contains(r.EmptyReadback, "populated 0") || len(r.PinRemovalErrno) != 7 {
		return errors.New("qualification cleanup evidence differs")
	}
	for _, name := range []string{"files", "peers", "sockets", "custody", "process", "anonymous", "syscalls"} {
		if r.PinRemovalErrno[name] != int(unix.ENOENT) {
			return errors.New("qualification retains an owned pin")
		}
	}
	return nil
}
func verifyCandidateStreams(r candidateReceipt) ([]syscallrules.Event, []kernel.Event, error) {
	version := syscallrules.Format
	if samples := r.Streams["syscalls"]; len(samples) > 0 && len(samples[0]) == 104 {
		version = syscallrules.LegacyFormat
	}
	if err := verifyHooks(r.Hooks, version == syscallrules.LegacyFormat); err != nil {
		return nil, nil, err
	}
	if len(r.Streams) != 6 || len(r.Counters) != 6 {
		return nil, nil, errors.New("qualification evidence lacks a required raw stream")
	}
	registry := nodeaudit.Registry()
	versions := map[string]string{"files": "files216.v1", "peers": "peers96.v2", "sockets": "sockets112.v1", "custody": "custody64.v1", "process": "process80.v1", "syscalls": "syscalls104.v1"}
	versions["syscalls"] = version
	fileEvents := []kernel.Event{}
	calls := []syscallrules.Event{}
	for name, version := range versions {
		counter, ok := r.Counters[name]
		if !ok || counter.Lost != 0 || counter.Decisions != uint64(len(r.Streams[name])) {
			return nil, nil, errors.New("qualification raw stream lost events or differs from its counters")
		}
		decode := registry[name+"/"+version]
		if decode == nil {
			return nil, nil, errors.New("qualification raw ABI decoder is unavailable")
		}
		for i, raw := range r.Streams[name] {
			fact, err := decode(raw)
			if err != nil {
				return nil, nil, err
			}
			if fact.Sequence != uint64(i+1) || fact.CgroupID != r.DomainID || fact.Generation != r.Generation || fact.TimestampNS < r.HeldPlaced.MonoNS {
				return nil, nil, errors.New("qualification raw event binding differs")
			}
			if fact.TimestampNS >= r.DeadlineNS && (name != "syscalls" || r.Expiry == nil || fact.TimestampNS < r.Expiry.ResumedMonoNS || fact.TimestampNS-r.Expiry.ResumedMonoNS > 5_000_000_000) {
				return nil, nil, errors.New("qualification contains an event outside its bounded expiry phase")
			}
			if name == "syscalls" {
				event, e := syscallrules.Decode(raw)
				if e != nil {
					return nil, nil, e
				}
				if event.TGID != uint32(r.Active.PID) || event.TID != uint32(r.Active.PID) || event.UID != 65534 || event.Cgroup != r.DomainID {
					return nil, nil, errors.New("qualification syscall actor differs")
				}
				if err := verifyExpiryEvent(r, event); err != nil {
					return nil, nil, err
				}
				calls = append(calls, event)
			}
			if name == "files" {
				var event kernel.Event
				if err = binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err != nil {
					return nil, nil, err
				}
				if event.PID != uint32(r.Active.PID) || event.UID != 65534 {
					return nil, nil, errors.New("qualification resource actor differs")
				}
				fileEvents = append(fileEvents, event)
			}
		}
	}
	stats := r.Counters["syscalls"]
	if err := syscallrules.Complete(calls, syscallrules.Counters{Records: stats.Decisions, Lost: stats.Lost}); err != nil {
		return nil, nil, err
	}
	return calls, fileEvents, nil
}

func verifyHooks(actual map[string][]string, legacy bool) error {
	expected := map[string][]string{
		"files":     fsrules.AccessProfile().LSMPrograms,
		"anonymous": anonrules.Programs(),
		"process":   processrules.Profile().LSMPrograms,
		"peers":     {"net_connect4", "net_connect6", "net_sendmsg4", "net_sendmsg6", "net_egress", "net_ingress"},
		"sockets":   {"operation_create", "operation_post_create", "operation_bind", "operation_listen", "operation_accept", "operation_send", "operation_receive", "operation_local_name", "operation_peer_name", "operation_shutdown", "operation_set_option", "operation_get_option", "operation_file_permission", "operation_ingress", "operation_egress"},
		"custody":   {"custody_sendmsg", "custody_recvmsg"},
		"syscalls":  {"audit_sys_exit", "audit_task_exit"},
	}
	if !legacy {
		expected["syscalls"] = append(expected["syscalls"], "audit_sys_enter")
	}
	if len(actual) != len(expected) {
		return errors.New("qualification attachment families differ")
	}
	for name, wanted := range expected {
		got := append([]string{}, actual[name]...)
		want := append([]string{}, wanted...)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			return fmt.Errorf("qualification mandatory hooks differ: %s", name)
		}
	}
	return nil
}

func verifyRecords(request qualification.Request, r candidateReceipt) (map[uint32]scalarRecord, error) {
	decoded, err := decodeRecords(r.RawRecords)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(decoded, r.Records) {
		return nil, errors.New("qualification actor records differ from their exact raw bytes")
	}
	expected := []uint32{1}
	if r.Protocol == candidateReceiptVersion {
		expected = append(expected, 2, 3, 4)
	}
	expected = append(expected, 10, 11, 12)
	if r.Protocol == candidateReceiptVersion {
		expected = append(expected, 50, 51, 52)
	}
	expected = append(expected, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24)
	heap := request.Document.Runtime.Memory != nil && request.Document.Runtime.Memory.Heap == "allow" && slices.Contains(request.Document.Runtime.Seccomp.AllowSyscalls, "brk")
	if heap {
		expected = append(expected, 25, 27, 26)
	}
	expected = append(expected, 99)
	if r.Expiry != nil {
		expected = append(expected, 100)
	}
	if len(decoded) != len(expected) {
		return nil, errors.New("qualification actor record count differs")
	}
	out := map[uint32]scalarRecord{}
	for i, record := range decoded {
		if record.ID != expected[i] || record.PID != uint32(r.Active.PID) || record.Reserved != 0 {
			return nil, errors.New("qualification actor raw identity or operation differs")
		}
		switch record.ID {
		case 2:
			if record.Result != int64(r.ManagerPID) || record.Error != 0 {
				return nil, errors.New("the release signal sender PID differs")
			}
		case 3:
			if record.Result != 0 || record.Error != 0 {
				return nil, errors.New("the release signal sender UID differs")
			}
		case 4:
			if record.Error != 0 || (record.Result != 0 && record.Result != -6) {
				return nil, errors.New("the release signal origin is not a kernel-authenticated user signal")
			}
		case 1, 99, 100:
			if record.Result != 0 || record.Error != 0 {
				return nil, errors.New("qualification phase boundary differs")
			}
		case 12:
			if record.Result != -1 || record.Error != uint32(unix.ENOSYS) {
				return nil, errors.New("qualification clone3 denial differs")
			}
		case 24:
			if heap {
				if record.Result <= 0 || record.Error != 0 {
					return nil, errors.New("qualification heap query differs")
				}
			} else if record.Result != -1 || record.Error != uint32(unix.EPERM) {
				return nil, errors.New("qualification heap denial differs")
			}
		case 25:
			if record.Result != out[24].Result+4096 || record.Error != 0 {
				return nil, errors.New("qualification heap allocation differs")
			}
		case 26:
			if record.Result != out[24].Result || record.Error != 0 {
				return nil, errors.New("qualification heap release differs")
			}
		case 27:
			if record.Result != 1 || record.Error != 0 {
				return nil, errors.New("qualification heap read/write differs")
			}
		default:
			if record.Result != -1 || record.Error != uint32(unix.EPERM) {
				return nil, fmt.Errorf("qualification denial differs for raw operation %d", record.ID)
			}
		}
		out[record.ID] = record
	}
	return out, nil
}

func observedCall(calls []syscallrules.Event, r candidateReceipt, number, result int64) bool {
	for _, call := range calls {
		if call.Type == syscallrules.Result && call.SyscallID == number && call.Result == result && call.MonoNS >= r.Active.MonoNS && call.MonoNS < r.DeadlineNS {
			return true
		}
	}
	return false
}
func observedMemory(events []kernel.Event, r candidateReceipt, minimum int) bool {
	count := 0
	for _, event := range events {
		if event.Hook == 14 && event.Allowed == 0 && event.MonoNS >= r.Active.MonoNS && event.MonoNS < r.DeadlineNS {
			count++
		}
	}
	return count >= minimum
}

func candidateCoverage(request qualification.Request, result qualification.Result, r candidateReceipt, calls []syscallrules.Event, files []kernel.Event, records map[uint32]scalarRecord) []qualification.Coverage {
	cases := positiveCases(request, r, calls, files)
	add := func(capability, name string, number int64) {
		if observedCall(calls, r, number, -int64(unix.EPERM)) {
			cases[capability] = append(cases[capability], name)
		}
	}
	add("runtime.explicit-syscalls.v2", "unknown-syscall-denied", 0x3fffffff)
	add("runtime.explicit-syscalls.v2", "ungranted-known-syscall-denied", unix.SYS_GETPPID)
	if observedCall(calls, r, unix.SYS_CLONE3, -int64(unix.ENOSYS)) {
		cases["runtime.explicit-syscalls.v2"] = append(cases["runtime.explicit-syscalls.v2"], "clone3-pointer-flags-denied")
	}
	add("runtime.explicit-pipes.v1", "ungranted-pipe-create-denied", unix.SYS_PIPE)
	add("runtime.explicit-pipes.v1", "ungranted-pipe2-create-denied", unix.SYS_PIPE2)
	add("runtime.explicit-eventfds.v1", "legacy-eventfd-denied", unix.SYS_EVENTFD)
	add("runtime.explicit-eventfds.v1", "ungranted-eventfd2-denied", unix.SYS_EVENTFD2)
	add("runtime.explicit-signals.v1", "ungranted-kill-denied", unix.SYS_KILL)
	add("runtime.explicit-signals.v1", "ungranted-tkill-denied", unix.SYS_TKILL)
	add("runtime.explicit-signals.v1", "ungranted-tgkill-denied", unix.SYS_TGKILL)
	if observedMemory(files, r, 2) && observedCall(calls, r, unix.SYS_MMAP, -int64(unix.EPERM)) {
		cases["runtime.explicit-memory.v1"] = []string{"anonymous-execute-denied", "writable-execute-denied"}
	}
	if heap, ok := records[25]; ok && observedCall(calls, r, unix.SYS_BRK, heap.Result) {
		cases["runtime.explicit-memory.v1"] = append(cases["runtime.explicit-memory.v1"], "explicit-allow:"+digestJSON("heap"))
	}
	if r.Expiry != nil {
		cases["runtime.explicit-memory.v1"] = append(cases["runtime.explicit-memory.v1"], "expired-allocation-denied")
	}
	out := []qualification.Coverage{}
	for _, contract := range request.Contracts {
		proved := []string{}
		for _, name := range cases[contract.CapabilityID] {
			if slices.Contains(contract.Cases, name) {
				proved = append(proved, name)
			}
		}
		if len(proved) > 0 {
			slices.Sort(proved)
			out = append(out, qualification.Coverage{CapabilityID: contract.CapabilityID, ContractVersion: contract.Version, Cases: proved, ReceiptSHA256: digestBytes(result.Raw)})
		}
	}
	return out
}

func (a *candidateDenial) verify(request qualification.Request, result qualification.Result) ([]qualification.Coverage, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	if err := candidateSupported(request); err != nil {
		return nil, err
	}
	r, err := parseCandidate(result.Raw)
	if err != nil {
		return nil, err
	}
	if r.Protocol != candidateReceiptVersion || r.BootstrapMode != listenerBootstrapMode {
		return nil, errors.New("the current adapter requires its measured listener bootstrap receipt")
	}
	if err = verifyActorBinding(request, result, r); err != nil {
		return nil, err
	}
	plan, err := enforcement.Compile(request.Document, r.DomainID, r.Generation, result.StartedMonoNS, r.DeadlineNS, nil)
	if err != nil || plan.Digest() != r.PlanSHA256 || plan.Syscalls().Digest() != r.FilterSHA256 {
		return nil, errors.New("qualification compiled policy or exact filter differs")
	}
	if err = verifyMaps(request, r); err != nil {
		return nil, err
	}
	if r.HeldBefore.Executable != a.config.Artifacts["qualification-denial-worker"] || r.Broker.Process.Executable != a.config.Artifacts["exec-broker"] {
		return nil, errors.New("the measured qualification role paths differ")
	}
	if err = verifyListenerBootstrap(request, result, r, plan); err != nil {
		return nil, err
	}
	records, err := verifyRecords(request, r)
	if err != nil {
		return nil, err
	}
	calls, files, err := verifyCandidateStreams(r)
	if err != nil {
		return nil, err
	}
	if err = verifyNoCreateProjection(request, r, calls); err != nil {
		return nil, err
	}
	if err = verifyBrokerClosure(r, calls); err != nil {
		return nil, err
	}
	if err = verifyLiveHeapDecisions(request, r, calls, records); err != nil {
		return nil, err
	}
	if err = verifyExpiryBinding(request, result, r, calls); err != nil {
		return nil, err
	}
	return candidateCoverage(request, result, r, calls, files, records), nil
}
