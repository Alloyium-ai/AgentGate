// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"alloyium.local/kernel-poc/internal/jobaudit"
)

func TestServiceLifecycleRetainsIncompleteAndTruncatedAuditBytes(t *testing.T) {
	recipe := serviceLifecycleRecipeFixture(t)
	root := filepath.Join(recipe.Spec.OwnedRoot, "private/audit")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	header := serviceLifecycleHeader(t, recipe)
	scene := serviceLifecycleScene{Recipe: recipe}
	scene.Prepared.Record.Binding = header.Binding
	scene.NodeConfig.AuditRoot = root
	path, err := serviceLifecycleAuditPath(scene)
	if err != nil {
		t.Fatal(err)
	}
	// This file contains only an incomplete header. It supplies no signed audit.
	raw := append(serviceJSON(struct {
		Kind   string          `json:"kind"`
		Header jobaudit.Header `json:"header"`
	}{"header", header}), '\n')
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = captureServiceLifecycleAudit(&scene); err != nil || !bytes.Equal(scene.AuditFile.Raw, raw) || scene.AuditFile.SHA256 != digestBytes(raw) {
		t.Fatal("the incomplete bytes changed", err)
	}
	if err = verifyServiceLifecycleAuditFile(scene); err != nil {
		t.Fatal(err)
	}
	truncated := append(append([]byte{}, raw...), []byte(`{"kind":`)...)
	if err = os.WriteFile(path, truncated, 0600); err != nil {
		t.Fatal(err)
	}
	if err = captureServiceLifecycleAudit(&scene); err == nil || !bytes.Equal(scene.AuditFile.Raw, truncated) || scene.AuditFile.SHA256 != digestBytes(truncated) || scene.AuditFile.Error == "" {
		t.Fatal("the truncated bytes or their error disappeared", err)
	}
	if verifyServiceLifecycleAuditFile(scene) == nil {
		t.Fatal("a truncated audit supplied verified file custody")
	}
	if err = os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(path+".original", path); err != nil {
		t.Fatal(err)
	}
	if err = captureServiceLifecycleAudit(&scene); err == nil || len(scene.AuditFile.Raw) != 0 || scene.AuditFile.Error == "" {
		t.Fatal("a linked audit passed or lost its read error", err)
	}
}
