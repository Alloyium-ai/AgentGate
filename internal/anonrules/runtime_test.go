// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package anonrules

import (
	"testing"

	"alloyium.local/kernel-poc/internal/kernel"
)

func TestProfileRejectsMissingFileComponent(t *testing.T) {
	for _, runtime := range []*kernel.Runtime{nil, {}, {ID: 1, Domain: "/sys/fs/cgroup/alloyium-poc-test"}} {
		if _, err := Profile(runtime); err == nil {
			t.Fatal("an absent file component received a guard profile")
		}
	}
}

func TestRequiredHooksAndReturnedProgramsStayIndependent(t *testing.T) {
	programs := Programs()
	if err := requireHooks(programs, Programs()...); err != nil {
		t.Fatal(err)
	}
	for i := range programs {
		missing := append([]string{}, programs[:i]...)
		missing = append(missing, programs[i+1:]...)
		if err := requireHooks(missing, Programs()...); err == nil {
			t.Fatalf("missing hook %s passed", programs[i])
		}
	}
	programs[0] = "changed"
	if Programs()[0] != "anonymous_alloc" {
		t.Fatal("the caller changed the mandatory hooks")
	}
}

func TestVerifyCouplingRejectsMissingComponents(t *testing.T) {
	if err := VerifyCoupling(nil, nil); err == nil {
		t.Fatal("absent components coupled")
	}
}
