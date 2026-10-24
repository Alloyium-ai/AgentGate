// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestPreflightReportsTheRefusalVerbatim(t *testing.T) {
	var out bytes.Buffer
	if err := preflightCommand(&out, func() error { return errors.New("refuse kernel load: disposable VM marker absent") }); err != nil {
		t.Fatal(err)
	}
	var report preflightReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.OK || report.Error != "refuse kernel load: disposable VM marker absent" {
		t.Fatalf("report %s", out.String())
	}
}

func compileObject(t *testing.T, name string) string {
	t.Helper()
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang unavailable; the object load check is not exercised")
	}
	out := filepath.Join(t.TempDir(), name+".o")
	cmd := exec.Command(clang, "-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86", "-I/usr/include/x86_64-linux-gnu", "-c", "../../bpf/"+name+".bpf.c", "-o", out)
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("BPF object did not compile here: %s", raw)
	}
	return out
}

func TestLoadCheckLoadsEachProgramAloneAndKeepsVerifierLogs(t *testing.T) {
	object := compileObject(t, "process_guard")
	var seen []string
	failing := func(spec *ebpf.CollectionSpec) error {
		if len(spec.Programs) != 1 {
			t.Fatalf("a load received %d programs", len(spec.Programs))
		}
		for name := range spec.Programs {
			seen = append(seen, name)
			if strings.Contains(name, "ptrace") {
				return &ebpf.VerifierError{Cause: errors.New("permission denied"), Log: []string{"0: R1=ctx", "invalid mem access 'scalar'"}}
			}
		}
		return nil
	}
	var out bytes.Buffer
	err := loadCheckCommand([]string{"load-check", object}, &out, func() error { return nil }, failing)
	if err == nil {
		t.Fatal("a verifier failure was not reported as an error")
	}
	var report struct {
		OK      bool
		Objects []objectLoad
	}
	if jsonErr := json.Unmarshal(out.Bytes(), &report); jsonErr != nil || report.OK || len(report.Objects) != 1 {
		t.Fatalf("report %s", out.String())
	}
	if len(seen) != len(report.Objects[0].Programs) || len(seen) < 3 {
		t.Fatalf("programs loaded %v", seen)
	}
	found := false
	for _, program := range report.Objects[0].Programs {
		if !program.OK {
			found = true
			if !strings.Contains(program.VerifierLog, "invalid mem access 'scalar'") {
				t.Fatalf("verifier log not verbatim: %q", program.VerifierLog)
			}
		}
	}
	if !found {
		t.Fatal("the failing program is not marked")
	}
}

func TestLoadCheckRefusesWithoutPreflightAndBoundsLogs(t *testing.T) {
	if err := loadCheckCommand([]string{"load-check", "x.o"}, &bytes.Buffer{}, func() error { return errors.New("refuse") }, nil); err == nil {
		t.Fatal("load-check ran without the preflight")
	}
	if err := loadCheckCommand([]string{"load-check"}, &bytes.Buffer{}, func() error { return nil }, nil); err == nil {
		t.Fatal("load-check ran without objects")
	}
	text, truncated := boundedLog(strings.Repeat("a", maxVerifierLog) + "tail")
	if !truncated || len(text) != maxVerifierLog || !strings.HasSuffix(text, "tail") {
		t.Fatal("verifier log bound keeps the wrong end")
	}
	missing := checkObject(filepath.Join(t.TempDir(), "absent.o"), nil)
	if missing.OK || missing.Error == "" {
		t.Fatal("a missing object passed")
	}
}
