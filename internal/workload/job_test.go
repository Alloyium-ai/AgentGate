// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package workload

import (
	"strings"
	"testing"
)

func TestWorkloadDeclarationBoundsAndDigest(t *testing.T) {
	valid := `{"executable":"/usr/bin/dash","arguments":["-c","printf '%s' example"],"workspace":"/var/lib/workspace"}`
	job, err := Read(strings.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	changed := job
	changed.Arguments = []string{"-c", "printf '%s' altered"}
	if job.Digest() == changed.Digest() {
		t.Fatal("the workload digest did not bind the arguments")
	}
	for _, bad := range []string{valid + `{}`, strings.Replace(valid, `"/usr/bin/dash"`, `"dash"`, 1), strings.Replace(valid, `"/var/lib/workspace"`, `"/"`, 1), strings.Replace(valid, `"/var/lib/workspace"`, `"/tmp/workspace"`, 1), strings.Replace(valid, `"arguments"`, `"untrusted"`, 1), strings.Repeat(" ", 32769)} {
		if _, err := Read(strings.NewReader(bad)); err == nil {
			t.Fatal("an invalid workload declaration was accepted")
		}
	}
}
