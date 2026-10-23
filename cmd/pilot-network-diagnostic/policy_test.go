// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import "testing"

func TestDiagnosticPolicyBindsOnlyExplicitEndpoints(t *testing.T) {
	d, err := diagnosticPolicy("example.org", "10.10.10.10", 8080, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Network.Rules) != 2 || d.Network.Pilot.TaskboardTaskID != 1 || d.Lifecycle.DurationSeconds != 30 {
		t.Fatal("diagnostic scope differs")
	}
	if _, err := d.Digest(); err != nil {
		t.Fatal(err)
	}
	if len(d.Files.Rules) != 0 || len(d.Programs.Rules) != 0 {
		t.Fatal("setup added unrelated rights")
	}
}

func TestDiagnosticPolicyRejectsWrongInputs(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "8.8.8.8", "::ffff:10.10.10.10", "invalid"} {
		if _, err := diagnosticPolicy("example.org", ip, 8080, 1); err == nil {
			t.Fatalf("accepted taskboard address %s", ip)
		}
	}
	if _, err := diagnosticPolicy("UPPER.example", "10.10.10.10", 8080, 1); err == nil {
		t.Fatal("accepted invalid hostname")
	}
	if _, err := diagnosticPolicy("example.org", "10.10.10.10", 0, 1); err == nil {
		t.Fatal("accepted invalid port")
	}
	if _, err := diagnosticPolicy("example.org", "10.10.10.10", 8080, 0); err == nil {
		t.Fatal("accepted invalid task ID")
	}
}
