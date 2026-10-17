// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"slices"

	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"golang.org/x/sys/unix"
)

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

func positiveCases(request qualification.Request, r candidateReceipt, calls []syscallrules.Event, files []kernel.Event) map[string][]string {
	out := map[string][]string{}
	sequence := installedFilterSequence(r, calls)
	if sequence == 0 {
		return out
	}
	allowed := map[string]int64{"read": unix.SYS_READ, "write": unix.SYS_WRITE, "openat": unix.SYS_OPENAT, "lseek": unix.SYS_LSEEK, "clock_gettime": unix.SYS_CLOCK_GETTIME, "brk": unix.SYS_BRK}
	for name, number := range allowed {
		if !slices.Contains(request.Document.Runtime.Seccomp.AllowSyscalls, name) {
			continue
		}
		for _, call := range calls {
			original, known := call.OriginalNumber()
			if known && call.Type == syscallrules.Result && call.Sequence > sequence && original == number && call.Result >= 0 && call.MonoNS < r.DeadlineNS {
				out["runtime.explicit-syscalls.v2"] = append(out["runtime.explicit-syscalls.v2"], "explicit-allow:"+digestJSON(name))
				break
			}
		}
	}
	for _, rule := range request.Document.Files.Rules {
		if rule.Effect != "allow" || rule.Selector.Kind != "exact" {
			continue
		}
		for _, proof := range []struct {
			operation, capability string
			hook                  uint32
			number, result        int64
		}{{"read", "fs.read.v1", 0, unix.SYS_READ, 1}, {"write", "fs.write.v1", 1, unix.SYS_WRITE, 24}} {
			if !slices.Contains(rule.Operations, proof.operation) || !observedCall(calls, r, proof.number, proof.result) {
				continue
			}
			for _, event := range files {
				if event.Hook == proof.hook && event.Allowed == 1 && event.MonoNS >= r.Active.MonoNS && event.MonoNS < r.DeadlineNS && string(bytes.TrimRight(event.Path[:], "\x00")) == rule.Selector.Path {
					out[proof.capability] = append(out[proof.capability], "explicit-allow:"+digestJSON(rule))
					out["fs.rules.v1"] = []string{"exact-path-match"}
					break
				}
			}
		}
	}
	return out
}
