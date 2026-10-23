// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"slices"
	"strings"

	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/runtimeguard"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"golang.org/x/sys/unix"
)

func fileSelectorMatches(kind, root, path string) bool {
	if path == "" || root == "" {
		return false
	}
	switch kind {
	case "exact":
		return path == root
	case "subtree":
		return path == root || root == "/" && strings.HasPrefix(path, "/") || strings.HasPrefix(path, root+"/")
	default:
		return false
	}
}

// The LSM decision must fall between the fixed actor's installed filter and
// the successful syscall result. The short join bound prevents an unrelated
// later read or write from supplying the result for an earlier file event.
func observedFileUse(calls []syscallrules.Event, files []kernel.Event, r candidateReceipt, filterSequence uint64, hook uint32, number, result int64, kind, path string) bool {
	if filterSequence == 0 {
		return false
	}
	for _, event := range files {
		if event.Hook != hook || event.Allowed != 1 || event.Cgroup != r.DomainID ||
			event.Generation != r.Generation || event.PID != uint32(r.Active.PID) || event.UID != 65534 ||
			event.MonoNS < r.Active.MonoNS || event.MonoNS >= r.DeadlineNS ||
			!fileSelectorMatches(kind, path, string(bytes.TrimRight(event.Path[:], "\x00"))) {
			continue
		}
		for _, call := range calls {
			original, known := call.OriginalNumber()
			if !known || call.Type != syscallrules.Result || call.Sequence <= filterSequence ||
				original != number || call.Result != result || call.TGID != event.PID || call.TID != event.PID ||
				call.UID != event.UID || call.Cgroup != event.Cgroup || call.Generation != event.Generation ||
				call.BindingState != syscallrules.Live || call.MonoNS < event.MonoNS ||
				call.MonoNS-event.MonoNS > 1_000_000 || call.MonoNS >= r.DeadlineNS ||
				call.EntryMonoNS != 0 && call.EntryMonoNS > event.MonoNS {
				continue
			}
			return true
		}
	}
	return false
}

func installedFilterSequence(r candidateReceipt, calls []syscallrules.Event) uint64 {
	var sequence uint64
	for _, call := range calls {
		if call.Type == syscallrules.Result && call.SyscallID == unix.SYS_SECCOMP {
			if sequence != 0 || call.Result != 0 || call.MonoNS < r.HeldInstalled.MonoNS || call.MonoNS >= r.Active.MonoNS {
				return 0
			}
			sequence = call.Sequence
		}
	}
	return sequence
}

func successfulAfterFilter(calls []syscallrules.Event, r candidateReceipt, sequence uint64, number, result int64) bool {
	if sequence == 0 {
		return false
	}
	for _, call := range calls {
		original, known := call.OriginalNumber()
		if known && call.Type == syscallrules.Result && call.Sequence > sequence && original == number && call.Result == result && call.MonoNS < r.DeadlineNS {
			return true
		}
	}
	return false
}

// The fixed actor requests a readable and writable anonymous page, then
// protects that same page as read-only. Credit requires an allowed LSM event
// joined to a successful syscall result from its measured PID and job domain.
func observedAnonymousMemory(calls []syscallrules.Event, files []kernel.Event, r candidateReceipt, sequence uint64, hook uint32, number int64) bool {
	if sequence == 0 {
		return false
	}
	for _, event := range files {
		if event.Hook != hook || event.Allowed != 1 || event.Cgroup != r.DomainID ||
			event.Generation != r.Generation || event.PID != uint32(r.Active.PID) || event.UID != 65534 ||
			event.MonoNS < r.Active.MonoNS || event.MonoNS >= r.DeadlineNS {
			continue
		}
		for _, call := range calls {
			original, known := call.OriginalNumber()
			if !known || call.Type != syscallrules.Result || call.Sequence <= sequence || original != number ||
				call.Domain != r.DomainID || call.TGID != event.PID || call.TID != event.PID || call.UID != event.UID ||
				call.Cgroup != event.Cgroup || call.Generation != event.Generation ||
				call.BindingState != syscallrules.Live || call.MonoNS < event.MonoNS ||
				call.MonoNS-event.MonoNS > 1_000_000 || call.MonoNS >= r.DeadlineNS ||
				call.EntryMonoNS != 0 && call.EntryMonoNS > event.MonoNS {
				continue
			}
			if number == unix.SYS_MMAP && call.Result > 0 || number == unix.SYS_MPROTECT && call.Result == 0 {
				return true
			}
		}
	}
	return false
}

func positiveCases(request qualification.Request, r candidateReceipt, calls []syscallrules.Event, files []kernel.Event) map[string][]string {
	out := map[string][]string{}
	sequence := installedFilterSequence(r, calls)
	if sequence == 0 {
		return out
	}
	for _, name := range request.Document.Runtime.Seccomp.AllowSyscalls {
		number, supported := runtimeguard.Number(name)
		if !supported || name == "clone3" {
			continue
		}
		for _, call := range calls {
			original, known := call.OriginalNumber()
			if known && call.Type == syscallrules.Result && call.Sequence > sequence && original == int64(number) && call.Result >= 0 && call.MonoNS < r.DeadlineNS {
				out["runtime.explicit-syscalls.v2"] = append(out["runtime.explicit-syscalls.v2"], "explicit-allow:"+digestJSON(name))
				break
			}
		}
	}
	for _, rule := range request.Document.Files.Rules {
		if rule.Effect != "allow" || rule.Selector.Kind != "exact" && rule.Selector.Kind != "subtree" {
			continue
		}
		for _, proof := range []struct {
			operation, capability string
			hook                  uint32
			number, result        int64
		}{{"read", "fs.read.v1", 0, unix.SYS_READ, 1}, {"write", "fs.write.v1", 1, unix.SYS_WRITE, 24}} {
			ambiguous := false
			for _, other := range request.Document.Files.Rules {
				if other.ID != rule.ID && slices.Contains(other.Operations, proof.operation) &&
					(fileSelectorMatches(rule.Selector.Kind, rule.Selector.Path, other.Selector.Path) ||
						fileSelectorMatches(other.Selector.Kind, other.Selector.Path, rule.Selector.Path)) {
					ambiguous = true
					break
				}
			}
			if ambiguous || !slices.Contains(rule.Operations, proof.operation) ||
				!observedFileUse(calls, files, r, sequence, proof.hook, proof.number, proof.result, rule.Selector.Kind, rule.Selector.Path) {
				continue
			}
			out[proof.capability] = append(out[proof.capability], "explicit-allow:"+digestJSON(rule))
			if rule.Selector.Kind == "exact" {
				out["fs.rules.v1"] = []string{"exact-path-match"}
			}
		}
	}
	if memory := request.Document.Runtime.Memory; memory != nil {
		if observedAnonymousMemory(calls, files, r, sequence, 14, unix.SYS_MMAP) {
			for _, operation := range []string{"map", "read", "write"} {
				if slices.Contains(memory.Anonymous, operation) {
					out["runtime.explicit-memory.v1"] = append(out["runtime.explicit-memory.v1"], "explicit-allow:"+digestJSON(operation))
				}
			}
		}
		if slices.Contains(memory.Anonymous, "protect") && observedAnonymousMemory(calls, files, r, sequence, 15, unix.SYS_MPROTECT) {
			out["runtime.explicit-memory.v1"] = append(out["runtime.explicit-memory.v1"], "explicit-allow:"+digestJSON("protect"))
		}
	}
	return out
}
