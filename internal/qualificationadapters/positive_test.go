//go:build agentgate_native_evidence

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func TestActualPositiveCasesNeedSuccessfulCallsAndExactFilePaths(t *testing.T) {
	request, _, receipt := actualFixture(t)
	calls, files, err := verifyCandidateStreams(receipt)
	if err != nil {
		t.Fatal(err)
	}
	proved := positiveCases(request, receipt, calls, files)
	if len(proved["runtime.explicit-syscalls.v2"]) != 6 || len(proved["fs.read.v1"]) != 1 || len(proved["fs.write.v1"]) != 1 || !slices.Equal(proved["fs.rules.v1"], []string{"exact-path-match"}) {
		t.Fatal("the actual positive facts differ", proved)
	}
	for i := range files {
		files[i].Path = [160]byte{}
	}
	proved = positiveCases(request, receipt, calls, files)
	if len(proved["fs.read.v1"]) != 0 || len(proved["fs.write.v1"]) != 0 {
		t.Fatal("a changed path supplied a rule witness")
	}
	for i := range calls {
		if calls[i].SyscallID == unix.SYS_READ {
			calls[i].Result = -int64(unix.EPERM)
		}
	}
	proved = positiveCases(request, receipt, calls, files)
	if slices.Contains(proved["runtime.explicit-syscalls.v2"], "explicit-allow:"+digestJSON("read")) {
		t.Fatal("a failed read supplied a positive witness")
	}
	for i := range calls {
		if calls[i].SyscallID == unix.SYS_SECCOMP {
			calls[i].Result = -int64(unix.EPERM)
		}
	}
	if len(positiveCases(request, receipt, calls, files)) != 0 {
		t.Fatal("a failed filter install supplied a positive witness")
	}
}
