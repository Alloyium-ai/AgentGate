// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package openrules

import (
	"alloyium.local/kernel-poc/internal/policy"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func TestCompiledComponentMatchesPolicyPrecedence(t *testing.T) {
	rules := []policy.FileRule{
		{ID: "root", Selector: policy.Selector{"subtree", "/"}, Operations: []string{"read"}, Effect: "deny"},
		{ID: "work", Selector: policy.Selector{"subtree", "/work"}, Operations: []string{"read", "write"}, Effect: "allow"},
		{ID: "secret", Selector: policy.Selector{"exact", "/work/secret"}, Operations: []string{"read"}, Effect: "deny"},
		{ID: "equal", Selector: policy.Selector{"subtree", "/work/secret"}, Operations: []string{"read"}, Effect: "allow"},
		{ID: "own", Selector: policy.Selector{"exact", "/other/own"}, Operations: []string{"read"}, Effect: "allow"},
	}
	plan, err := Compile(rules, 42, 3, 1000000)
	if err != nil {
		t.Fatal(err)
	}
	files := policy.Files{Defaults: policy.FileDefaults{"deny", "deny"}, Rules: rules}
	for _, path := range []string{"/", "/work", "/work/file", "/work/secret", "/work/secret/child", "/workspace/file", "/other/own", "/other/no", "/work/../other", "relative"} {
		for _, operation := range []string{"read", "write", "create"} {
			if got, want := plan.Effect(path, operation), policy.FileEffect(files, path, operation); got != want {
				t.Fatalf("%s %s: got %s want %s", operation, path, got, want)
			}
		}
	}
	for i, j := 0, len(rules)-1; i < j; i, j = i+1, j-1 {
		rules[i], rules[j] = rules[j], rules[i]
	}
	reversed, err := Compile(rules, 42, 3, 1000000)
	if err != nil || !reflect.DeepEqual(plan, reversed) {
		t.Fatal("input order changed the compiled rules")
	}
	entries := plan.Entries()
	for i := range entries {
		entries[i].Node.SubRead = Action{Allow, 1}
		entries[i].Node.ExactRead = Action{Allow, 1}
	}
	state := plan.State()
	state.Root.SubRead = Action{Allow, 1}
	if plan.Effect("/unmatched", "read") != "deny" || plan.Effect("/work/secret", "read") != "deny" {
		t.Fatal("a caller changed the compiled component through its inspection copy")
	}
}
func TestComponentRejectsUnsupportedOperationsAndKeepsEmptyDeny(t *testing.T) {
	plan, err := Compile(nil, 42, 1, 100)
	if err != nil || plan.Effect("/any", "read") != "deny" {
		t.Fatal("empty component permissions granted access")
	}
	rule := policy.FileRule{ID: "unsupported", Selector: policy.Selector{"subtree", "/work"}, Operations: []string{"rename"}, Effect: "allow"}
	if _, err = Compile([]policy.FileRule{rule}, 42, 1, 100); err == nil {
		t.Fatal("a file-open component silently ignored rename")
	}
	rule.Operations = []string{"read"}
	rule.Selector.Path = "/" + strings.Repeat("x", NameSize)
	if _, err = Compile([]policy.FileRule{rule}, 42, 1, 100); err == nil {
		t.Fatal("a target component limit silently truncated a selector")
	}
	if binary.Size(Key{}) != 280 || binary.Size(Node{}) != 36 || binary.Size(State{}) != 56 {
		t.Fatal("the map ABI changed")
	}
}

func TestInstallationRejectsStaleExpiredAndChangedComponents(t *testing.T) {
	plan, err := Compile(nil, 42, 5, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateInstall(plan, 42, 500, 4); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ domain, now, generation uint64 }{
		{43, 500, 4}, {42, 1000, 4}, {42, 500, 5}, {42, 500, 6},
	} {
		if err = validateInstall(plan, test.domain, test.now, test.generation); err == nil {
			t.Fatal("a stale, expired, or unbound component passed installation")
		}
	}
	plan.state.Root.SubRead = Action{Allow, 1}
	if err = validateInstall(plan, 42, 500, 4); err == nil {
		t.Fatal("a changed component retained its immutable binding")
	}
}
