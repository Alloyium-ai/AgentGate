// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/nodeapi"
	"alloyium.local/kernel-poc/internal/testpolicy"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApprovedDocumentRequiresItsExactBytes(t *testing.T) {
	d := testpolicy.Deny()
	raw, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := d.Digest()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err = os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	s := &Sources{Config: Config{Documents: map[string]string{digest: path}}}
	if _, err = s.Resolve(context.Background(), digest); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Resolve(context.Background(), strings.Repeat("0", 64)); err == nil {
		t.Fatal("an unapproved document was accepted")
	}
	d.Lifecycle.DurationSeconds++
	raw, _ = d.Canonical()
	if err = os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Resolve(context.Background(), digest); err == nil {
		t.Fatal("changed approved bytes were accepted")
	}
}
func TestEnrollmentReturnsNoMutableRegistryReference(t *testing.T) {
	s := &Sources{enrollments: map[string]nodeapi.Enrollment{"agent": {AgentID: "agent", Enabled: true, Runtimes: map[string]nodeapi.RuntimeArtifact{"codex": {Version: "pinned"}}}}}
	e, err := s.Enrollment(context.Background(), "agent")
	if err != nil {
		t.Fatal(err)
	}
	e.Runtimes["codex"] = nodeapi.RuntimeArtifact{Version: "changed"}
	again, _ := s.Enrollment(context.Background(), "agent")
	if again.Runtimes["codex"].Version != "pinned" {
		t.Fatal("the caller changed enrolled runtime custody")
	}
	if _, err = s.Enrollment(context.Background(), "foreign"); err == nil {
		t.Fatal("a foreign agent was enrolled")
	}
}
