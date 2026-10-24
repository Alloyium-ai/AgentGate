// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The test binary re-runs itself as the CLI so main's exit codes are real.
func TestMain(m *testing.M) {
	if os.Getenv("AGENTGATE_TEST_RUN_MAIN") == "1" {
		os.Args = append([]string{"agentgate"}, strings.Fields(os.Getenv("AGENTGATE_TEST_ARGS"))...)
		main()
		return
	}
	os.Exit(m.Run())
}

func runMain(t *testing.T, args string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = []string{"AGENTGATE_TEST_RUN_MAIN=1", "AGENTGATE_TEST_ARGS=" + args, "AGENTGATE_CONFIG_DIR=" + t.TempDir() + "/cfg", "HOME=" + t.TempDir()}
	out, err := cmd.CombinedOutput()
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

func TestMainExitCodes(t *testing.T) {
	if out, code := runMain(t, "version"); code != 0 || !strings.Contains(out, "agentgate ") {
		t.Fatalf("version: %d %s", code, out)
	}
	if out, code := runMain(t, "frobnicate"); code != 2 || !strings.Contains(out, "unknown command") {
		t.Fatalf("usage: %d %s", code, out)
	}
	if out, code := runMain(t, "ps"); code != 3 || !strings.Contains(out, "agentgate login") {
		t.Fatalf("not signed in: %d %s", code, out)
	}
}
