// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dockerplacement

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func pythonTuple(t *testing.T, source, name string) []string {
	t.Helper()
	match := regexp.MustCompile(`(?s)\n` + name + ` = \((.*?)\)\n`).FindStringSubmatch(source)
	if match == nil {
		t.Fatalf("mounts.py lacks %s", name)
	}
	var out []string
	for _, item := range regexp.MustCompile(`'([^']*)'`).FindAllStringSubmatch(match[1], -1) {
		out = append(out, item[1])
	}
	return out
}

// The guard and the operator-side validator refuse exactly the same trees.
func TestProtectedTreesMatchTheMountValidator(t *testing.T) {
	raw, err := os.ReadFile("../../poc/ssh-diagnostic/mounts.py")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	if got, want := strings.Join(pythonTuple(t, source, "PROTECTED"), ","), strings.Join(protectedHostTrees, ","); got != want {
		t.Fatalf("PROTECTED %s\nGo        %s", got, want)
	}
	if got, want := strings.Join(pythonTuple(t, source, "SECRET_NAMES"), ","), strings.Join(credentialStores, ","); got != want {
		t.Fatalf("SECRET_NAMES %s\nGo           %s", got, want)
	}
	if !strings.Contains(source, "INSTANCE_PREFIX = '"+instancePrefix+"'") {
		t.Fatal("instance prefix differs")
	}
}

func TestProtectedSourceRefusesHomesStoresAndInstances(t *testing.T) {
	for _, source := range []string{"/home", "/home/alice", "/srv/x/.ssh", "/srv/x/.ssh/keys", "/data/.local/share/agentgate",
		"/var/lib/agentgate-poc-demo", "/var/lib", "/snap/core", "/var/lib/kubelet/pods", "/var/lib/cloud"} {
		if protectedSource(source) == nil {
			t.Errorf("%s accepted", source)
		}
	}
	for _, source := range []string{"/home/alice/src/app", "/srv/repos/app", "/data/sshkeys-docs"} {
		if err := protectedSource(source); err != nil {
			t.Errorf("%s refused: %v", source, err)
		}
	}
}
