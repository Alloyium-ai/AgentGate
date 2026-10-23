// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/dockerplacement"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/noderuntime"
	"golang.org/x/sys/unix"
)

func TestLifecycleUnreadReplyPeekKeepsBytesAndDetectsClose(t *testing.T) {
	parent, child, err := serviceLifecycleSocketpair()
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.FileConn(parent)
	parent.Close()
	if err != nil {
		child.Close()
		t.Fatal(err)
	}
	defer connection.Close()
	ready, err := serviceLifecycleReplyPending(connection)
	if err != nil || ready {
		t.Fatal("an empty socket appeared to have a reply", ready, err)
	}
	want := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	if _, err = child.Write(want); err != nil {
		child.Close()
		t.Fatal(err)
	}
	for range 2 {
		ready, err = serviceLifecycleReplyPending(connection)
		if err != nil || !ready {
			child.Close()
			t.Fatal("the pending reply disappeared", ready, err)
		}
	}
	got := make([]byte, len(want))
	if _, err = io.ReadFull(connection, got); err != nil || !bytes.Equal(got, want) {
		child.Close()
		t.Fatal("the peek consumed or changed the reply", err)
	}
	if err = child.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = serviceLifecycleReplyPending(connection); err == nil {
		t.Fatal("a closed reply socket appeared live")
	}
}

func TestLifecyclePrepareUsesTheStrictEmptyObject(t *testing.T) {
	call := serviceLifecycleHTTPCall{Method: "POST", Path: "/fixture/prepare", Request: []byte("{}")}
	if err := verifyServiceLifecycleHTTPCall(call, serviceLifecycleScene{}); err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{nil, []byte("null"), []byte(`{"unexpected":true}`)} {
		call.Request = body
		if verifyServiceLifecycleHTTPCall(call, serviceLifecycleScene{}) == nil {
			t.Fatal("the prepare command used a different body")
		}
	}
}

func TestLifecycleStartDescriptorRejectsMutation(t *testing.T) {
	recipe := serviceLifecycleRecipeFixture(t)
	ticks, err := lifecycle.ProcessStartTime(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	start := noderuntime.QualificationStart{Protocol: noderuntime.QualificationStartProtocol, NodeConfigFile: filepath.Join(recipe.Spec.OwnedRoot, "private/node.json"), Spec: recipe.Spec, Parent: lifecycle.DaemonIdentity{PID: os.Getpid(), StartTimeTicks: ticks, InstanceID: "unit-parent"}}
	file, err := sealedServiceLifecycleStart(start)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	expected := unix.F_SEAL_SEAL | unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK
	if err != nil || seals != expected {
		t.Fatal(seals, err)
	}
	if _, err = file.Write([]byte("changed")); err == nil {
		t.Fatal("the sealed start descriptor changed")
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	var actual noderuntime.QualificationStart
	if lifecycle.DecodeTransport(bytes.NewReader(raw), &actual) != nil || actual.Validate() != nil {
		t.Fatal("the sealed start descriptor lost its strict DTO")
	}
}
func TestLifecycleAuthorityUsesOnlyThePrivateSocketpair(t *testing.T) {
	recipe := serviceLifecycleRecipeFixture(t)
	roles, err := stageServiceLifecycleKeys(recipe)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := newServiceLifecycleAuthority(filepath.Join(recipe.Spec.OwnedRoot, "private/authority"), recipe, roles.nodeKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.close()
	serverSide, clientSide, err := serviceLifecycleSocketpair()
	if err != nil {
		t.Fatal(err)
	}
	server, err := serveServiceLifecycleAuthority(serverSide, authority)
	if err != nil {
		t.Fatal(err)
	}
	client, err := newServiceLifecycleHTTPClient(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		client.close()
		if err := server.close(); err != nil {
			t.Error(err)
		}
	}()
	// The first real callback follows BPF preparation, not socket acceptance.
	// This delay exceeds the former one-second header limit.
	delay := time.NewTimer(1200 * time.Millisecond)
	defer delay.Stop()
	<-delay.C
	payload := noderuntime.QualificationStateRequest{Protocol: noderuntime.QualificationStateProtocol, GrantID: recipe.Spec.Binding.GrantID}
	request, err := http.NewRequestWithContext(context.Background(), "POST", "http://qualification-fixture/fixture/state", bytes.NewReader(serviceJSON(payload)))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	var state noderuntime.QualificationStateResponse
	if response.StatusCode != 200 || lifecycle.DecodeTransport(bytes.NewReader(raw), &state) != nil || state.Protocol != noderuntime.QualificationStateProtocol || state.GrantID != payload.GrantID || state.Known || state.Revoked {
		t.Fatal(response.StatusCode, string(raw))
	}
	request, err = http.NewRequest("POST", "http://qualification-fixture/fixture/state", bytes.NewReader([]byte(`{"protocol":"bad","protocol":"duplicate"}`)))
	if err != nil {
		t.Fatal(err)
	}
	response, err = client.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 422 {
		t.Fatal("the private callback accepted ambiguous JSON")
	}
}
func TestLifecycleStagingCreatesOnlyFreshPrivateRoleKeys(t *testing.T) {
	recipe := serviceLifecycleRecipeFixture(t)
	roles, err := stageServiceLifecycleKeys(recipe)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := newServiceLifecycleAuthority(filepath.Join(recipe.Spec.OwnedRoot, "private/authority"), recipe, roles.nodeKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.close()
	base := serviceLifecycleBase{config: noderuntime.Config{NodeID: recipe.Spec.Binding.NodeID, PilotTarget: &dockerplacement.Target{}, Qualification: noderuntime.QualificationConfig{PublicKey: "public-only", Challenge: "unit", SourceRevision: recipe.Spec.SourceRevision}}, report: []byte("unavailable-public-report-only")}
	staged, err := stageServiceLifecycleNode(base, recipe, authority, roles)
	if err != nil {
		t.Fatal(err)
	}
	config, err := noderuntime.ReadConfig(staged.nodePath)
	if err != nil {
		t.Fatal(err)
	}
	if config.Credentials != nil || config.Resolver != nil || config.PilotTarget != nil || config.OwnedPrefix == recipe.CandidateRoot.OwnedPrefix || config.ArtifactDigests["domain-root"] != recipe.FixtureRoot.Digest() {
		t.Fatal("the staged node changed the fixture boundary")
	}
	for _, path := range []string{config.NodeKeyFile, config.WatchdogKeyFile} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 || info.Size() != 64 {
			t.Fatal(path, info, err)
		}
	}
	if _, err = os.Stat(filepath.Join(recipe.Spec.OwnedRoot, "private/authority.key")); !os.IsNotExist(err) {
		t.Fatal("the parent authority signer entered the node files")
	}
}
