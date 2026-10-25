// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/noderuntime"
	"alloyium.local/kernel-poc/internal/qualification"
)

func TestServiceLifecycleLossReadsTheOwnedJournalWithoutWrites(t *testing.T) {
	recipe := serviceLifecycleRecipeFixture(t)
	private := filepath.Join(recipe.Spec.OwnedRoot, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "node.db")
	journal, err := lifecycle.OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	writer, err := openServiceLifecycleWatchdogDatabase(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Exec("DELETE FROM lifecycle_records"); err == nil {
		t.Fatal("the evidence reader can write")
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	scene := serviceLifecycleScene{Recipe: recipe}
	scene.NodeConfig.Journal = path
	scene.Prepared.Record.Binding = recipe.Spec.Binding
	// The writer under test is the supported journal API.
	binding := recipe.Spec.Binding
	binding.CgroupID = 0
	record := lifecycle.Record{Binding: binding, State: "preparing", Revision: 1}
	if err = journal.Save(context.Background(), record, 0); err != nil {
		t.Fatal(err)
	}
	captured, err := readServiceLifecycleJournal(context.Background(), scene)
	if err != nil {
		t.Fatal(err)
	}
	if captured.RunID != binding.RunID || !reflect.DeepEqual(captured.Before, captured.After) || captured.Path != path {
		t.Fatal(captured)
	}
	// A preparing row remains actual evidence and cannot prove a stopped domain.
	if _, err = verifyServiceLifecycleJournal(captured, scene); err == nil {
		t.Fatal("a preparing row qualified a loss")
	}
	if err = journal.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestServiceLifecycleLossRequiresExactFaultAndNaturalNodeExit(t *testing.T) {
	request := adapterRequest(t)
	request.Binding.ArtifactDigests["watchdog"] = strings.Repeat("a", 64)
	result := qualification.Result{StartedMonoNS: 1, FinishedMonoNS: 100}
	scene := serviceLifecycleScene{Mode: "watchdog-loss", NodeSnapshot: processSnapshot{PID: 42, StartTimeTicks: 8}, Actors: []processSnapshot{{MonoNS: 10}, {MonoNS: 11}, {MonoNS: 12}}, NodeStderr: []byte("the fixed fixture watchdog stopped")}
	scene.Active.Record.Evidence = []lifecycle.Evidence{{EffectiveDeadlineNS: 90}}
	scene.WatchdogState = &serviceLifecycleWatchdogReadback{FinishedNS: 15}
	scene.Prepared.PreparedMonoNS = 2
	scene.Prepared.Record.PreparationDeadlineNS = 89
	scene.Active.Record.Authorization = &lifecycle.Authorization{Document: []byte("{}")}
	scene.Calls = []serviceLifecycleHTTPCall{{Method: "POST", Path: "/fixture/prepare", Request: []byte("{}"), Response: append(serviceJSON(scene.Prepared), '\n'), Status: 200, MonoNS: 3}, {Method: "POST", Path: "/fixture/start", Request: serviceJSON(noderuntime.QualificationRunRequest{Protocol: noderuntime.QualificationRunProtocol, Authorization: *scene.Active.Record.Authorization}), Response: serviceJSON(scene.Active), Status: 200, MonoNS: 4}}
	scene.Loss = &serviceLifecycleLoss{Protocol: serviceLifecycleLossProtocol, Signal: int(syscall.SIGKILL), SignalStartedNS: 20, SignalFinishedNS: 21, Watchdog: processSnapshot{PID: 43, StartTimeTicks: 9, ExecutableSHA256: request.Binding.ArtifactDigests["watchdog"], MonoNS: 16, Status: "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n"}, WatchdogExit: serviceLifecycleExit{PID: 43, StartTicks: 9, ObservedNS: 22, ExitCode: -1, Signal: int(syscall.SIGKILL), Error: "signal: killed"}, NodeExit: serviceLifecycleExit{PID: 42, StartTicks: 8, ObservedNS: 50, ExitCode: 1, Error: "exit status 1"}, Journal: serviceLifecycleJournalReadback{StartedNS: 51, FinishedNS: 52}}
	if err := verifyServiceLifecycleLossFault(request, result, scene); err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*serviceLifecycleScene){
		"missing fault":                 func(s *serviceLifecycleScene) { s.Loss = nil },
		"different watchdog hash":       func(s *serviceLifecycleScene) { s.Loss.Watchdog.ExecutableSHA256 = "" },
		"wrong pid":                     func(s *serviceLifecycleScene) { s.Loss.WatchdogExit.PID++ },
		"wrong start":                   func(s *serviceLifecycleScene) { s.Loss.WatchdogExit.StartTicks++ },
		"graceful watchdog stop":        func(s *serviceLifecycleScene) { s.Loss.Signal = int(syscall.SIGTERM) },
		"fault after expiry":            func(s *serviceLifecycleScene) { s.Loss.SignalFinishedNS = 90 },
		"actor after fault":             func(s *serviceLifecycleScene) { s.Actors[2].MonoNS = 21 },
		"parent killed node":            func(s *serviceLifecycleScene) { s.Loss.NodeExit.Signal = int(syscall.SIGKILL) },
		"missing actual wait":           func(s *serviceLifecycleScene) { s.Loss.NodeExit.Error = "" },
		"journal before watchdog death": func(s *serviceLifecycleScene) { s.Loss.Journal.StartedNS = 21 },
		"parent revoke": func(s *serviceLifecycleScene) {
			s.AuthorityCalls = []serviceLifecycleAuthorityCall{{Operation: "revoke"}}
		},
		"parent stop": func(s *serviceLifecycleScene) {
			s.Calls = append(s.Calls, serviceLifecycleHTTPCall{Path: "/fixture/stop"})
		},
		"borrowed status": func(s *serviceLifecycleScene) { s.Stopped.Protocol = noderuntime.QualificationStatusProtocol },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			var altered serviceLifecycleScene
			if err := lifecycle.DecodeTransport(bytes.NewReader(serviceJSON(scene)), &altered); err != nil {
				t.Fatal(err)
			}
			change(&altered)
			if verifyServiceLifecycleLossFault(request, result, altered) == nil {
				t.Fatal("a substituted loss fault passed")
			}
		})
	}
}

func TestServiceLifecycleLossAcceptsAStoppedRunInALiveNode(t *testing.T) {
	recipe := serviceLifecycleRecipeFixture(t)
	request := adapterRequest(t)
	request.Binding.ArtifactDigests["node"] = strings.Repeat("b", 64)
	scene := serviceLifecycleScene{Recipe: recipe, NodeSnapshot: processSnapshot{PID: 42, StartTimeTicks: 8}}
	scene.Active.Record = lifecycle.Record{Binding: recipe.Spec.Binding, State: "active", Revision: 4}
	scene.NodeConfig.Journal = filepath.Join(recipe.Spec.OwnedRoot, "private/node.db")
	record := scene.Active.Record
	record.State, record.Revision, record.StopReason = "stopped", 5, "active-watchdog-unavailable"
	b := record.Binding
	stat := serviceLifecycleDatabaseIdentity{Device: 1, Inode: 2, UID: 0, Links: 1, Mode: 0100600}
	scene.Loss = &serviceLifecycleLoss{WatchdogExit: serviceLifecycleExit{ObservedNS: 20}, NodeAfterFault: &processSnapshot{PID: 42, StartTimeTicks: 8, ExecutableSHA256: request.Binding.ArtifactDigests["node"], MonoNS: 53}, Journal: serviceLifecycleJournalReadback{Path: scene.NodeConfig.Journal, Before: stat, After: stat, StartedNS: 51, FinishedNS: 52, RunID: b.RunID, AgentID: b.AgentID, NodeID: b.NodeID, BootID: b.BootID, Generation: b.Generation, Revision: 5, Raw: serviceJSON(record)}}
	result := qualification.Result{StartedMonoNS: 1, FinishedMonoNS: 100}
	if err := verifyServiceLifecycleLossNode(request, result, scene); err != nil {
		t.Fatal(err)
	}
	scene.Loss.NodeAfterFault.StartTimeTicks++
	if verifyServiceLifecycleLossNode(request, result, scene) == nil {
		t.Fatal("a changed live node start time passed")
	}
	scene.Loss.NodeAfterFault.StartTimeTicks--
	record.StopReason = "manager-shutdown"
	scene.Loss.Journal.Raw = serviceJSON(record)
	if verifyServiceLifecycleLossNode(request, result, scene) == nil {
		t.Fatal("a generic manager shutdown qualified a watchdog loss")
	}
	scene.NodeStderr = []byte("the fixed fixture watchdog stopped")
	if err := verifyServiceLifecycleLossNode(request, result, scene); err != nil {
		t.Fatal(err)
	}
	record.StopReason = "grant-expired"
	scene.Loss.Journal.Raw = serviceJSON(record)
	if verifyServiceLifecycleLossNode(request, result, scene) == nil {
		t.Fatal("an expiry qualified a watchdog loss")
	}
}
