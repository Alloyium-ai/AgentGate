// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package domainstore

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"encoding/base64"
	"encoding/json"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func proofFixture() RootProof {
	return RootProof{BootID: "boot-one", MountID: 1, Device: 2, RootInode: 3, MountRoot: "/", MountPoint: RootPath, NamespaceDevice: 4, NamespaceInode: 5, InitNamespaceDevice: 4, InitNamespaceInode: 5, JobDepth: 1, OwnedPrefix: "agj-1234567890abcdef-", QualificationReceiptDigest: strings.Repeat("f", 64)}
}
func bindingFixture(proof RootProof) lifecycle.Binding {
	return lifecycle.Binding{AgentID: "agent-one", AgentKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), JobDigest: strings.Repeat("1", 64), GrantID: "grant-one", RunID: "run-one", NodeID: "node-one", BootID: proof.BootID, PolicyDigest: strings.Repeat("2", 64), SchemaDigest: strings.Repeat("3", 64), CompilerDigest: strings.Repeat("4", 64), ArtifactDigests: map[string]string{"domain-root": proof.Digest()}, Generation: 1, DeadlineNS: ^uint64(0) - 1}
}
func unitStore(t *testing.T) *Store {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root owns the protected reservation test")
	}
	scratch := os.Getenv("AGENTGATE_DOMAIN_TEST_SCRATCH")
	if scratch == "" {
		scratch = os.Getenv("TMPDIR")
	}
	if scratch == "" || strings.HasPrefix(scratch, "/tmp") {
		t.Skip("set a protected owned scratch directory")
	}
	dir, err := os.MkdirTemp(scratch, "domain-store-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	fd, err := openPrivateDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	store := &Store{config: Config{NodeID: "node-one", StateDir: dir, Proof: proofFixture(), StopTimeout: time.Second}, stateFD: fd, key: make([]byte, 32)}
	t.Cleanup(func() { store.Close() })
	return store
}
func unitReservation(t *testing.T, s *Store) Reservation {
	t.Helper()
	b := bindingFixture(s.config.Proof)
	r := Reservation{Binding: b, Proof: s.config.Proof, RootDigest: s.config.Proof.Digest(), Name: reservationName(s.config.Proof.OwnedPrefix, b), State: "reserved", Revision: 1}
	if err := s.write(reservationFile(s.config.NodeID, b.RunID), r, true); err != nil {
		t.Fatal(err)
	}
	return r
}
func TestRootProofBindsNamespaceAndSeparatesMountObservation(t *testing.T) {
	p := proofFixture()
	if p.validate() != nil {
		t.Fatal("unit root proof is invalid")
	}
	next := p
	next.MountID++
	next.QualificationReceiptDigest = strings.Repeat("a", 64)
	if next.Digest() == p.Digest() || next.IdentityDigest() != p.IdentityDigest() {
		t.Fatal("mount observations lost their separate identity")
	}
	for _, change := range []func(*RootProof){func(p *RootProof) { p.BootID = "boot-two" }, func(p *RootProof) { p.RootInode++ }, func(p *RootProof) { p.Device++ }, func(p *RootProof) { p.NamespaceInode++; p.InitNamespaceInode++ }, func(p *RootProof) { p.OwnedPrefix = "agj-fedcba0987654321-" }} {
		next = p
		change(&next)
		if next.IdentityDigest() == p.IdentityDigest() {
			t.Fatal("root custody identity did not change")
		}
	}
	for _, change := range []func(*RootProof){func(p *RootProof) { p.NamespaceInode++ }, func(p *RootProof) { p.MountRoot = "/nested" }, func(p *RootProof) { p.MountPoint = "/other" }, func(p *RootProof) { p.JobDepth = 2 }, func(p *RootProof) { p.OwnedPrefix = "../host" }} {
		next = p
		change(&next)
		if next.validate() == nil {
			t.Fatal("ambiguous root proof passed")
		}
	}
}
func TestReservationRejectsTamperingPathSelectionAndInodeMutation(t *testing.T) {
	s := unitStore(t)
	r := unitReservation(t, s)
	if _, err := s.load(r.Binding); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(s.config.StateDir, reservationFile(s.config.NodeID, r.Binding.RunID))
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(file, []byte(strings.Replace(string(raw), "run-one", "run-two", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.load(r.Binding); err == nil {
		t.Fatal("an unauthenticated reservation passed")
	}
	for _, name := range []string{"/", "../system.slice", "system.slice", "agj-foreign-unowned"} {
		changed := r
		changed.Name = name
		if err = s.write(filepath.Base(file), changed, false); err != nil {
			t.Fatal(err)
		}
		if _, err = s.load(r.Binding); err == nil {
			t.Fatal("a record selected an unrelated host path")
		}
	}
	if err = s.write(filepath.Base(file), r, false); err != nil {
		t.Fatal(err)
	}
	binding := r.Binding
	binding.CgroupID = 0
	if _, fd, err := s.exact(s.stateFD, binding); err == nil || fd != -1 {
		t.Fatal("cgroup zero passed resolved custody")
	}
}
func TestAuthenticatedOldRootProofSupportsCleanupOnly(t *testing.T) {
	s := unitStore(t)
	r := unitReservation(t, s)
	s.config.Proof.MountID++
	s.config.Proof.QualificationReceiptDigest = strings.Repeat("a", 64)
	loaded, err := s.load(r.Binding)
	if err != nil || loaded.RootDigest == s.config.Proof.Digest() {
		t.Fatal("stop-only old observation lost custody", err)
	}
	if s.validateBinding(r.Binding, true) == nil {
		t.Fatal("an old observation qualified creation")
	}
	s.config.Proof.RootInode++
	if _, err = s.load(r.Binding); err == nil {
		t.Fatal("a different root inherited a reservation")
	}
}
func TestPrivateStateRejectsLinksPermissionsAndReplacementDirectories(t *testing.T) {
	var err error
	s := unitStore(t)
	path := filepath.Join(s.config.StateDir, "value")
	if err = os.WriteFile(path, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(path, path+"-link"); err != nil {
		t.Fatal(err)
	}
	if _, err = readPrivate(s.stateFD, "value", 32); err == nil {
		t.Fatal("a linked state file passed")
	}
	os.Remove(path + "-link")
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = readPrivate(s.stateFD, "value", 32); err == nil {
		t.Fatal("public state permissions passed")
	}
	if err = os.Symlink(path, filepath.Join(s.config.StateDir, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err = readPrivate(s.stateFD, "linked", 32); err == nil {
		t.Fatal("a state symlink passed")
	}
	if err = os.Mkdir(filepath.Join(s.config.StateDir, "directory"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = readPrivate(s.stateFD, "directory", 32); err == nil {
		t.Fatal("a directory replaced a state file")
	}
	if _, err = openPrivateDirectory(filepath.Join(s.config.StateDir, "linked")); err == nil {
		t.Fatal("a linked directory path passed")
	}
}
func TestExclusiveDurableReservationHasOneWinner(t *testing.T) {
	s := unitStore(t)
	b := bindingFixture(s.config.Proof)
	r := Reservation{Binding: b, Proof: s.config.Proof, RootDigest: s.config.Proof.Digest(), Name: reservationName(s.config.Proof.OwnedPrefix, b), State: "reserved", Revision: 1}
	var group sync.WaitGroup
	result := make(chan error, 2)
	for i := 0; i < 2; i++ {
		group.Add(1)
		go func() { defer group.Done(); result <- s.write(reservationFile(s.config.NodeID, b.RunID), r, true) }()
	}
	group.Wait()
	close(result)
	winners := 0
	for err := range result {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatal("multiple durable reservation winners")
	}
	if _, err := s.load(b); err != nil {
		t.Fatal(err)
	}
	names, err := os.ReadDir(s.config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if strings.HasPrefix(name.Name(), ".stage-") {
			t.Fatal("a private stage survived commit")
		}
	}
}
func TestPopulationReadbackAndControlPathsFailClosed(t *testing.T) {
	s := unitStore(t)
	path := filepath.Join(s.config.StateDir, "cgroup.events")
	for _, text := range []string{"", "populated 2\n", "populated 0\npopulated 1\n", "frozen 0\n"} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := domainEmpty(s.stateFD); err == nil {
			t.Fatal("invalid population readback passed")
		}
	}
	if err := os.WriteFile(path, []byte("populated 0\nfrozen 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if empty, _, err := domainEmpty(s.stateFD); err != nil || !empty {
		t.Fatal("a valid empty readback failed", err)
	}
	if err := os.Symlink(path, filepath.Join(s.config.StateDir, "cgroup.kill")); err != nil {
		t.Fatal(err)
	}
	if err := writeControl(s.stateFD, "cgroup.kill", "1"); err == nil {
		t.Fatal("a control symlink passed")
	}
}
func waitStopped(t *testing.T, p lifecycle.HeldProcess) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for stoppedProcess(p) != nil {
		select {
		case <-deadline.C:
			t.Fatal("owned helper did not stop")
		case <-ticker.C:
		}
	}
}
func TestPlacementRequiresMeasuredStoppedSingleThreadProcess(t *testing.T) {
	s := unitStore(t)
	command := exec.Command("/bin/cat")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { input.Close(); command.Process.Kill(); command.Wait() })
	ticks, err := lifecycle.ProcessStartTime(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	p := lifecycle.HeldProcess{PID: command.Process.Pid, StartTimeTicks: ticks, BarrierID: "unit-only-barrier"}
	if err = stoppedProcess(p); err == nil {
		t.Fatal("a running helper passed placement")
	}
	if err = command.Process.Signal(unix.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	waitStopped(t, p)
	wrong := p
	wrong.StartTimeTicks++
	if stoppedProcess(wrong) == nil {
		t.Fatal("a reused process identity passed")
	}
	if _, err = s.PlaceHeld(context.Background(), bindingFixture(s.config.Proof), p); err == nil {
		t.Fatal("a caller flag replaced measured barrier evidence")
	}
}
func TestOwnedNamespaceNamesNeverSelectForeignOrNestedPaths(t *testing.T) {
	s := unitStore(t)
	b := bindingFixture(s.config.Proof)
	name := reservationName(s.config.Proof.OwnedPrefix, b)
	if !s.ownedName(name) {
		t.Fatal("a derived owned name failed")
	}
	for _, name := range []string{"/", "system.slice", s.config.Proof.OwnedPrefix + strings.Repeat("a", 64) + "/child", s.config.Proof.OwnedPrefix + "../host", "agj-ffffffffffffffff-" + strings.Repeat("a", 64)} {
		if s.ownedName(name) {
			t.Fatal("a foreign path entered orphan custody")
		}
	}
	changed := b
	changed.Generation++
	if reservationName(s.config.Proof.OwnedPrefix, changed) == name {
		t.Fatal("generation did not bind the domain name")
	}
	raw, _ := json.Marshal(b)
	if strings.Contains(string(raw), "cgroup_id\":0") {
		t.Fatal("the transport lost decimal cgroup identity")
	}
}
