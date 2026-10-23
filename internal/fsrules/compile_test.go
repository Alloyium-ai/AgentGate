// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package fsrules

import (
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/policy"
	"encoding/binary"
	"testing"
)

func TestAnonymousDelegationNeverEnablesStandaloneInstallation(t *testing.T) {
	files := policy.Files{Defaults: policy.FileDefaults{Read: "deny", Write: "deny"}, ResourceUse: "recheck-and-terminate"}
	programs := policy.Programs{Default: "deny"}
	runtime := policy.Runtime{Profile: "managed-unprivileged.v1", UID: 65534, GID: 65534, SupplementaryGroups: []int{}, Capabilities: []string{}, NoNewPrivileges: true, Seccomp: policy.Seccomp{Profile: "explicit-allowlist-notify.v2", Architecture: "x86_64", Default: "deny", AllowSyscalls: []string{}}}
	ops := []string{"create", "read", "write"}
	runtime.IPC = &policy.IPCPolicy{Default: "deny", Pipes: []string{}, EventFDs: &ops}
	plan, err := CompileWithRuntime(files, programs, runtime, 42, 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if plan.CheckAccess(42, 100) == nil || plan.CheckAccessWithAnonymous(42, 100) == nil {
		t.Fatal("eventfd rights lacked mandatory delegation")
	}
	guarded := plan.WithAnonymousGuard()
	if guarded.State().Pipes != AnonymousDelegation|56 || plan.State().Pipes != 56 || guarded.Digest() == plan.Digest() {
		t.Fatal("delegation changed the source plan or lost its digest")
	}
	if guarded.CheckAccess(42, 100) == nil {
		t.Fatal("the standalone access component accepted delegated rights")
	}
	if err = guarded.CheckAccessWithAnonymous(42, 100); err != nil {
		t.Fatal(err)
	}
	if InstallAccessCoupled(nil, guarded, nil) == nil || verifyAnonymousCoupling(&kernel.Runtime{}, &kernel.Runtime{}) == nil {
		t.Fatal("missing guard custody reached an update")
	}
	for _, op := range Operations() {
		if guarded.Effect("/anything", op) != "deny" {
			t.Fatal("delegation granted a pathname right")
		}
	}
}

func TestFileAndExecutableOperationsRemainIndependent(t *testing.T) {
	files := policy.Files{Defaults: policy.FileDefaults{Read: "deny", Write: "deny"}, ResourceUse: "recheck-and-terminate", Rules: []policy.FileRule{
		{ID: "read", Selector: policy.Selector{Kind: "subtree", Path: "/work"}, Operations: []string{"read"}, Effect: "allow"},
		{ID: "rename", Selector: policy.Selector{Kind: "exact", Path: "/work/renamed"}, Operations: []string{"rename"}, Effect: "allow"},
		{ID: "deny", Selector: policy.Selector{Kind: "exact", Path: "/work/secret"}, Operations: []string{"read"}, Effect: "deny"},
	}}
	programs := policy.Programs{Default: "deny", Rules: []policy.ProgramRule{{ID: "executable", Selector: policy.Selector{Kind: "exact", Path: "/work/tool"}, Effect: "allow"}}}
	plan, err := Compile(files, programs, 42, 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/work", "/work/file", "/work/tool", "/work/secret", "/workspace/file", "/work/renamed"} {
		for _, operation := range Operations() {
			expect := policy.FileEffect(files, path, operation)
			if operation == "execute" && path == "/work/tool" {
				expect = "allow"
			}
			if got := plan.Effect(path, operation); got != expect {
				t.Fatalf("%s %s: got %s expected %s", operation, path, got, expect)
			}
		}
	}
	if binary.Size(State{}) != 544 {
		t.Fatal("the full file policy ABI changed")
	}
	files.Rules = nil
	programs.Rules = nil
	empty, err := Compile(files, programs, 42, 2, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range Operations() {
		if empty.Effect("/anything", operation) != "deny" {
			t.Fatal("empty component permissions authorized an operation")
		}
	}
}

func TestFileCompilerRejectsUnqualifiedApprovalAndImplicitDefaults(t *testing.T) {
	files := policy.Files{Defaults: policy.FileDefaults{Read: "deny", Write: "deny"}, ResourceUse: "recheck-and-terminate"}
	programs := policy.Programs{Default: "deny"}
	files.Defaults.Read = "allow"
	if _, err := Compile(files, programs, 42, 1, 100); err == nil {
		t.Fatal("implicit reads passed compilation")
	}
	files.Defaults.Read = "deny"
	programs.Rules = []policy.ProgramRule{{ID: "gated", Selector: policy.Selector{Kind: "exact", Path: "/usr/bin/git"}, Effect: "allow", Approval: &policy.Approval{Argv1: []string{"push"}, TimeoutSeconds: 120, Scope: "one-shot-actual-executable", ArgumentAssurance: "observed"}}}
	if _, err := Compile(files, programs, 42, 1, 100); err == nil {
		t.Fatal("an unqualified approval silently became an executable allowance")
	}
}

func TestAccessInstallerRejectsUnsupportedAllowsAndChangedBindings(t *testing.T) {
	files := policy.Files{Defaults: policy.FileDefaults{Read: "deny", Write: "deny"}, ResourceUse: "recheck-and-terminate", Rules: []policy.FileRule{{ID: "one-read", Selector: policy.Selector{Kind: "exact", Path: "/work/one"}, Operations: []string{"read"}, Effect: "allow"}}}
	programs := policy.Programs{Default: "deny"}
	plan, err := Compile(files, programs, 42, 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateAccessInstall(plan, 42, 500, 0); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ domain, now, generation uint64 }{{43, 500, 0}, {42, 1000, 0}, {42, 500, 1}} {
		if err = validateAccessInstall(plan, test.domain, test.now, test.generation); err == nil {
			t.Fatal("an invalid file access installation passed")
		}
	}
	copy := plan.AllowedOperations()
	copy[0] = "rename"
	if err = validateAccessInstall(plan, 42, 500, 0); err != nil {
		t.Fatal("a caller changed the private operation set", err)
	}
	files.Rules[0].Operations = []string{"rename"}
	unsupported, err := Compile(files, programs, 42, 2, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateAccessInstall(unsupported, 42, 500, 0); err == nil {
		t.Fatal("an unavailable mutation allowance silently installed")
	}
	plan.state.Generation = 2
	if err = validateAccessInstall(plan, 42, 500, 0); err == nil {
		t.Fatal("a changed file access plan retained its digest binding")
	}
}

func TestExecutableMappingsDoNotGrantProgramExecution(t *testing.T) {
	files := policy.Files{Defaults: policy.FileDefaults{Read: "deny", Write: "deny"}, ResourceUse: "recheck-and-terminate", Rules: []policy.FileRule{{ID: "library", Selector: policy.Selector{Kind: "exact", Path: "/usr/lib/runtime.so"}, Operations: []string{"read", "mmap", "map_execute"}, Effect: "allow"}}}
	programs := policy.Programs{Default: "deny"}
	plan, err := Compile(files, programs, 42, 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Effect("/usr/lib/runtime.so", "map_execute") != "allow" || plan.Effect("/usr/lib/runtime.so", "execute") != "deny" || plan.Effect("/usr/lib/runtime.so", "mprotect") != "deny" {
		t.Fatal("mapping permissions widened another operation")
	}
	files.Rules = nil
	programs.Rules = []policy.ProgramRule{{ID: "binary", Selector: policy.Selector{Kind: "exact", Path: "/usr/bin/tool"}, Effect: "allow"}}
	plan, err = Compile(files, programs, 42, 2, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Effect("/usr/bin/tool", "execute") != "allow" || plan.Effect("/usr/bin/tool", "map_execute") != "deny" {
		t.Fatal("program execution granted executable mappings")
	}
}

func TestAnonymousMemoryRequiresExplicitRights(t *testing.T) {
	files := policy.Files{Defaults: policy.FileDefaults{Read: "deny", Write: "deny"}, ResourceUse: "recheck-and-terminate"}
	programs := policy.Programs{Default: "deny"}
	runtime := policy.Runtime{Profile: "managed-unprivileged.v1", UID: 65534, GID: 65534, SupplementaryGroups: []int{}, Capabilities: []string{}, NoNewPrivileges: true, Seccomp: policy.Seccomp{Profile: "explicit-allowlist-notify.v2", Architecture: "x86_64", Default: "deny", AllowSyscalls: []string{}}}
	empty, err := CompileWithRuntime(files, programs, runtime, 42, 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if empty.State().Memory != 0 {
		t.Fatal("missing memory policy permits anonymous memory")
	}
	runtime.Memory = &policy.MemoryPolicy{Default: "deny", Anonymous: []string{"map", "read", "write", "protect"}, Heap: "deny"}
	explicit, err := CompileWithRuntime(files, programs, runtime, 42, 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if explicit.State().Memory != 27 || explicit.Digest() == empty.Digest() {
		t.Fatal("memory mask or digest differs")
	}
	runtime.Memory.Anonymous = append(runtime.Memory.Anonymous, "execute")
	executable, err := CompileWithRuntime(files, programs, runtime, 42, 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if executable.State().Memory != 31 {
		t.Fatal("executable mapping right differs")
	}
	for _, op := range Operations() {
		if executable.Effect("/anything", op) != "deny" {
			t.Fatal("anonymous memory widened file rights")
		}
	}
	runtime.Memory.Default = "allow"
	if _, err = CompileWithRuntime(files, programs, runtime, 42, 1, 1000); err == nil {
		t.Fatal("implicit memory default accepted")
	}
}

func TestSocketDelegationRequiresLiveCompleteGuards(t *testing.T) {
	files := policy.Files{Defaults: policy.FileDefaults{Read: "deny", Write: "deny"}, ResourceUse: "recheck-and-terminate"}
	p, err := Compile(files, policy.Programs{Default: "deny"}, 42, 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EnableSocketDelegation(p, nil, nil, nil); err == nil {
		t.Fatal("socket delegation bypassed mandatory guard verification")
	}
}

func TestMutationAllowancesNeedTheExplicitMarkAndHardLinksNever(t *testing.T) {
	for _, operation := range []string{"create", "mkdir", "delete", "rename", "symlink", "metadata"} {
		files := policy.Files{Defaults: policy.FileDefaults{Read: "deny", Write: "deny"}, ResourceUse: "recheck-and-terminate", Rules: []policy.FileRule{
			{ID: "work", Selector: policy.Selector{Kind: "subtree", Path: "/work"}, Operations: []string{operation}, Effect: "allow"}}}
		plan, err := Compile(files, policy.Programs{Default: "deny"}, 42, 1, 1000)
		if err != nil {
			t.Fatal(operation, err)
		}
		// The product pipeline never sets the mark, so it still refuses the right.
		if validateAccessInstall(plan, 42, 500, 0) == nil || plan.CheckAccess(42, 500) == nil {
			t.Fatalf("%s installed without the mutation mark", operation)
		}
		marked := plan.WithMutationEnforcement()
		if marked.Digest() == plan.Digest() || plan.mutation {
			t.Fatal("the mark changed the source plan or missed its digest")
		}
		if err = validateAccessInstall(marked, 42, 500, 0); err != nil {
			t.Fatalf("%s allowance refused: %v", operation, err)
		}
		if marked.Effect("/work/new", operation) != "allow" || marked.Effect("/etc/new", operation) != "deny" || marked.Effect("/work/new", "read") != "deny" {
			t.Fatalf("%s allowance leaked into another path or operation", operation)
		}
		forged := plan
		forged.mutation = true
		if validateAccessInstall(forged, 42, 500, 0) == nil {
			t.Fatalf("%s: setting the mark without recomputing the digest installed", operation)
		}
	}
	files := policy.Files{Defaults: policy.FileDefaults{Read: "deny", Write: "deny"}, ResourceUse: "recheck-and-terminate", Rules: []policy.FileRule{
		{ID: "link", Selector: policy.Selector{Kind: "subtree", Path: "/work"}, Operations: []string{"hardlink"}, Effect: "allow"}}}
	plan, err := Compile(files, policy.Programs{Default: "deny"}, 42, 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if validateAccessInstall(plan.WithMutationEnforcement(), 42, 500, 0) == nil {
		t.Fatal("a hard link allowance installed without a kernel hook that can enforce it")
	}
	// An unmarked, read-only plan keeps its digest from before the mark existed.
	read := policy.Files{Defaults: policy.FileDefaults{Read: "deny", Write: "deny"}, ResourceUse: "recheck-and-terminate"}
	a, _ := Compile(read, policy.Programs{Default: "deny"}, 42, 1, 1000)
	if a.Digest() != planDigest(a) {
		t.Fatal("unmarked digest differs")
	}
}

func TestInheritedStdioIsExplicitAndGrantsNoPathRight(t *testing.T) {
	files := policy.Files{Defaults: policy.FileDefaults{Read: "deny", Write: "deny"}, ResourceUse: "recheck-and-terminate"}
	plan, err := Compile(files, policy.Programs{Default: "deny"}, 42, 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if plan.State().Pipes&InheritedStdio != 0 {
		t.Fatal("inherited stdio is on by default")
	}
	marked := plan.WithInheritedStdio()
	if marked.State().Pipes != InheritedStdio || plan.State().Pipes != 0 || marked.Digest() == plan.Digest() {
		t.Fatal("the mark changed the source plan or missed its digest")
	}
	if err = validateAccessInstall(marked, 42, 500, 0); err != nil {
		t.Fatal(err)
	}
	for _, operation := range Operations() {
		if marked.Effect("/anything", operation) != "deny" {
			t.Fatal("inherited stdio granted a pathname right")
		}
	}
	unknown := plan
	unknown.state.Pipes = uint64(1) << 61
	unknown.digest = planDigest(unknown)
	if validateAccessInstall(unknown, 42, 500, 0) == nil {
		t.Fatal("an undefined pipe permission bit installed")
	}
}
