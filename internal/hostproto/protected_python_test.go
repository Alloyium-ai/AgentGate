// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostproto

import (
	"os"
	"strings"
	"testing"
)

const (
	mountsPy       = "../../poc/ssh-diagnostic/mounts.py"
	generatedBegin = "# BEGIN GENERATED FROM internal/hostproto\n"
	generatedEnd   = "# END GENERATED FROM internal/hostproto\n"
)

// pythonTuple renders a Python tuple of strings, wrapped near 100 columns.
func pythonTuple(name string, items []string) string {
	var b strings.Builder
	b.WriteString(name + " = (\n")
	line := "   "
	for _, item := range items {
		piece := " '" + item + "',"
		if len(line)+len(piece) > 100 {
			b.WriteString(line + "\n")
			line = "   "
		}
		line += piece
	}
	b.WriteString(line + "\n)\n")
	return b.String()
}

// generatedMountRules is the block of mounts.py that holds this package's
// protected mount rules.
func generatedMountRules() string {
	return generatedBegin + pythonTuple("PROTECTED", ProtectedMountTrees) +
		"INSTANCE_PREFIX = '" + InstanceDirPrefix + "'\n" + pythonTuple("SECRET_NAMES", secretComponents) + generatedEnd
}

// TestPythonMountRulesAreGeneratedFromHostproto keeps the Python runtime's
// protected trees, instance prefix and credential stores equal to this
// package's, the one list every component uses (the guard calls
// CheckProtectedSource). AGENTGATE_WRITE_PROTECTED_MOUNTS=1 rewrites the block.
func TestPythonMountRulesAreGeneratedFromHostproto(t *testing.T) {
	raw, err := os.ReadFile(mountsPy)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	start, end := strings.Index(text, generatedBegin), strings.Index(text, generatedEnd)
	if start < 0 || end < start || strings.Count(text, generatedBegin) != 1 {
		t.Fatalf("%s has no single generated block", mountsPy)
	}
	current, want := text[start:end+len(generatedEnd)], generatedMountRules()
	if current == want {
		return
	}
	if os.Getenv("AGENTGATE_WRITE_PROTECTED_MOUNTS") == "1" {
		if err = os.WriteFile(mountsPy, []byte(text[:start]+want+text[end+len(generatedEnd):]), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("%s's protected mount rules differ from hostproto's; regenerate with AGENTGATE_WRITE_PROTECTED_MOUNTS=1 go test ./internal/hostproto -run TestPythonMountRules\nhave:\n%s\nwant:\n%s", mountsPy, current, want)
}
