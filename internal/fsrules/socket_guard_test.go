// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package fsrules

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"alloyium.local/kernel-poc/internal/policy"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func observed() []CgroupProgram {
	out := []CgroupProgram{}
	for i, hook := range CgroupNetworkHooks() {
		out = append(out, CgroupProgram{Attach: hook.Attach, ID: ebpf.ProgramID(i + 10), Name: hook.Program, Type: hook.Type})
	}
	return out
}

func emptyPlan(t *testing.T, domain uint64) Plan {
	t.Helper()
	files := policy.Files{Defaults: policy.FileDefaults{Read: "deny", Write: "deny"}, ResourceUse: "recheck-and-terminate"}
	plan, err := Compile(files, policy.Programs{Default: "deny"}, domain, 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestCgroupNetworkEvidenceNeedsEveryHook(t *testing.T) {
	guard, err := NewCgroupNetworkGuard(42, observed())
	if err != nil {
		t.Fatal(err)
	}
	if guard.Domain() != 42 || len(guard.Programs()) != 6 {
		t.Fatalf("evidence differs: %+v", guard)
	}
	// An unrelated program on the same hook only adds refusals; it is ignored.
	extra := append([]CgroupProgram{{Attach: ebpf.AttachCGroupInetEgress, ID: 99, Name: "other", Type: ebpf.CGroupSKB}}, observed()...)
	if _, err = NewCgroupNetworkGuard(42, extra); err != nil {
		t.Fatal(err)
	}
	if _, err = NewCgroupNetworkGuard(0, observed()); err == nil {
		t.Fatal("evidence without a domain was accepted")
	}
	for i := range CgroupNetworkHooks() {
		for name, change := range map[string]func(*CgroupProgram){
			"missing":    nil,
			"wrong name": func(p *CgroupProgram) { p.Name = "net_other" },
			"wrong type": func(p *CgroupProgram) { p.Type = ebpf.LSM },
			"wrong hook": func(p *CgroupProgram) { p.Attach = ebpf.AttachCGroupInet4Bind },
			"no program": func(p *CgroupProgram) { p.ID = 0 },
		} {
			list := observed()
			if change == nil {
				list = append(list[:i], list[i+1:]...)
			} else {
				change(&list[i])
			}
			if _, err = NewCgroupNetworkGuard(42, list); err == nil {
				t.Fatalf("hook %d %s: incomplete evidence was accepted", i, name)
			}
		}
	}
}

func TestCgroupOnlySocketModeNeedsEvidenceForTheSameDomain(t *testing.T) {
	plan := emptyPlan(t, 42)
	if plan.SocketMode() != SocketsDenied || plan.SocketLSMGuard() || plan.State().SocketGeneration != 0 {
		t.Fatal("sockets are not denied by default")
	}
	if _, err := plan.WithCgroupNetworkGuardOnly(CgroupNetworkGuard{}); err == nil {
		t.Fatal("the zero evidence value selected the cgroup-only socket mode")
	}
	other, _ := NewCgroupNetworkGuard(43, observed())
	if _, err := plan.WithCgroupNetworkGuardOnly(other); err == nil {
		t.Fatal("evidence for another domain selected the cgroup-only socket mode")
	}
	forged := CgroupNetworkGuard{domain: 42, programs: observed()[:5]}
	if _, err := plan.WithCgroupNetworkGuardOnly(forged); err == nil {
		t.Fatal("incomplete evidence selected the cgroup-only socket mode")
	}
	guard, _ := NewCgroupNetworkGuard(42, observed())
	marked, err := plan.WithCgroupNetworkGuardOnly(guard)
	if err != nil {
		t.Fatal(err)
	}
	if marked.SocketMode() != SocketsCgroupNetworkOnly || marked.SocketLSMGuard() || marked.State().SocketGeneration != marked.State().Generation {
		t.Fatalf("socket mode differs: %s", marked.SocketMode())
	}
	if plan.SocketMode() != SocketsDenied || marked.Digest() == plan.Digest() {
		t.Fatal("the mode changed the source plan or missed its digest")
	}
	if err = validateAccessInstall(marked, 42, 500, 0); err != nil {
		t.Fatal(err)
	}
	for _, operation := range Operations() {
		if marked.Effect("/anything", operation) != "deny" {
			t.Fatal("the socket mode granted a pathname right")
		}
	}
	// The mode and the kernel mark must agree; neither installs alone.
	unmarked := marked
	unmarked.state.SocketGeneration = 0
	unmarked.digest = planDigest(unmarked)
	bare := plan
	bare.state.SocketGeneration = bare.state.Generation
	bare.digest = planDigest(bare)
	unknown := marked
	unknown.sockets = "anything"
	unknown.digest = planDigest(unknown)
	for name, p := range map[string]Plan{"mode without mark": unmarked, "mark without mode": bare, "unknown mode": unknown} {
		if validateAccessInstall(p, 42, 500, 0) == nil {
			t.Fatalf("%s installed", name)
		}
	}
	// The digest separates the cgroup-only mode from socket LSM delegation.
	delegated := plan
	delegated.state.SocketGeneration = delegated.state.Generation
	delegated.sockets = SocketsLSMGuard
	delegated.digest = planDigest(delegated)
	if delegated.Digest() == marked.Digest() || delegated.Digest() != bare.Digest() {
		t.Fatal("socket mode digests differ from their contract")
	}
	if _, err = delegated.WithCgroupNetworkGuardOnly(guard); err == nil {
		t.Fatal("the cgroup-only mode replaced socket LSM delegation")
	}
	if _, err = EnableSocketDelegation(marked, nil, nil, nil); err == nil {
		t.Fatal("socket LSM delegation replaced the cgroup-only mode")
	}
}

func TestObserveCgroupNetworkGuardRefusesAnotherDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := ObserveCgroupNetworkGuard(dir, 1); err == nil {
		t.Fatal("a directory outside cgroup v2 produced network evidence")
	}
	if _, err := ObserveCgroupNetworkGuard(filepath.Join(dir, "absent"), 1); err == nil {
		t.Fatal("an absent cgroup produced network evidence")
	}
}

// TestObserveCgroupNetworkGuardLive attaches the real network object to a
// scratch cgroup v2 directory and reads the evidence back from the kernel. It
// runs only when AGENTGATE_LIVE_CGROUP2 names a writable cgroup v2 directory and
// AGENTGATE_NETWORK_OBJECT a compiled bpf/network_policy.bpf.c (root required).
func TestObserveCgroupNetworkGuardLive(t *testing.T) {
	root, object := os.Getenv("AGENTGATE_LIVE_CGROUP2"), os.Getenv("AGENTGATE_NETWORK_OBJECT")
	if root == "" || object == "" {
		t.Skip("set AGENTGATE_LIVE_CGROUP2 and AGENTGATE_NETWORK_OBJECT to run against a kernel")
	}
	_ = rlimit.RemoveMemlock()
	cgroup, err := os.MkdirTemp(root, "agentgate-fsrules-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cgroup)
	var st os.FileInfo
	if st, err = os.Stat(cgroup); err != nil {
		t.Fatal(err)
	}
	domain := inode(t, st)
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer collection.Close()
	if _, err = ObserveCgroupNetworkGuard(cgroup, domain); err == nil {
		t.Fatal("an empty cgroup produced network evidence")
	}
	links := map[string]link.Link{}
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()
	for _, hook := range CgroupNetworkHooks() {
		program := collection.Programs[hook.Program]
		if program == nil {
			t.Fatalf("object lacks %s", hook.Program)
		}
		l, attachErr := link.AttachCgroup(link.CgroupOptions{Path: cgroup, Attach: hook.Attach, Program: program})
		if attachErr != nil {
			t.Fatal(attachErr)
		}
		links[hook.Program] = l
	}
	guard, err := ObserveCgroupNetworkGuard(cgroup, domain)
	if err != nil {
		t.Fatal(err)
	}
	for i, program := range guard.Programs() {
		info, infoErr := collection.Programs[CgroupNetworkHooks()[i].Program].Info()
		id, ok := info.ID()
		if infoErr != nil || !ok || id != program.ID {
			t.Fatalf("evidence names program %d, the guard attached %d", program.ID, id)
		}
	}
	if _, err = ObserveCgroupNetworkGuard(cgroup, domain+1); err == nil {
		t.Fatal("evidence was produced for another domain")
	}
	plan := emptyPlan(t, domain)
	if _, err = plan.WithCgroupNetworkGuardOnly(guard); err != nil {
		t.Fatal(err)
	}
	if err = links["net_ingress"].Close(); err != nil {
		t.Fatal(err)
	}
	delete(links, "net_ingress")
	if _, err = ObserveCgroupNetworkGuard(cgroup, domain); err == nil {
		t.Fatal("a missing ingress link still produced network evidence")
	}
}

func inode(t *testing.T, info os.FileInfo) uint64 {
	t.Helper()
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("no inode")
	}
	return st.Ino
}
