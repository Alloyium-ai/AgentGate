// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"time"

	"alloyium.local/kernel-poc/internal/lifecycle"
)

type serviceLifecycleJournalReadback struct {
	Path       string                           `json:"path"`
	Before     serviceLifecycleDatabaseIdentity `json:"before"`
	After      serviceLifecycleDatabaseIdentity `json:"after"`
	StartedNS  uint64                           `json:"started_mono_ns,string"`
	FinishedNS uint64                           `json:"finished_mono_ns,string"`
	RunID      string                           `json:"run_id"`
	AgentID    string                           `json:"agent_id"`
	NodeID     string                           `json:"node_id"`
	BootID     string                           `json:"boot_id"`
	Generation uint64                           `json:"generation,string"`
	Revision   uint64                           `json:"revision,string"`
	Raw        []byte                           `json:"raw"`
}

func readServiceLifecycleJournal(ctx context.Context, scene serviceLifecycleScene) (out serviceLifecycleJournalReadback, err error) {
	return readServiceLifecycleJournalRun(ctx, scene, scene.Prepared.Record.Binding.RunID)
}

func readServiceLifecycleJournalRun(ctx context.Context, scene serviceLifecycleScene, runID string) (out serviceLifecycleJournalReadback, err error) {
	out.Path, out.StartedNS = scene.NodeConfig.Journal, serviceMono()
	defer func() { out.FinishedNS = serviceMono() }()
	if out.Path != filepath.Join(scene.Recipe.Spec.OwnedRoot, "private/node.db") {
		return out, errors.New("the fixture node journal path differs")
	}
	out.Before, err = serviceLifecycleDatabaseStat(out.Path)
	if err != nil {
		return out, err
	}
	database, err := openServiceLifecycleWatchdogDatabase(ctx, out.Path)
	if err != nil {
		return out, err
	}
	defer func() { err = errors.Join(err, database.Close()) }()
	var raw string
	err = database.QueryRowContext(ctx, "SELECT run_id,agent_id,node_id,boot_id,generation,revision,record FROM lifecycle_records WHERE run_id=?", runID).Scan(&out.RunID, &out.AgentID, &out.NodeID, &out.BootID, &out.Generation, &out.Revision, &raw)
	out.Raw = []byte(raw)
	if err != nil {
		return out, err
	}
	out.After, err = serviceLifecycleDatabaseStat(out.Path)
	if err == nil && out.Before != out.After {
		err = errors.New("the fixture node journal identity changed")
	}
	return out, err
}

func verifyServiceLifecycleJournal(r serviceLifecycleJournalReadback, scene serviceLifecycleScene) (record lifecycle.Record, err error) {
	if r.Path != filepath.Join(scene.Recipe.Spec.OwnedRoot, "private/node.db") || r.Path != scene.NodeConfig.Journal || !validServiceLifecycleDatabase(r.Before) || r.Before != r.After || r.StartedNS == 0 || r.FinishedNS < r.StartedNS || len(r.Raw) == 0 || len(r.Raw) > 2<<20 || uniqueJSON(r.Raw) != nil {
		return record, errors.New("the actual node journal custody differs")
	}
	if err = lifecycle.DecodeTransport(bytes.NewReader(r.Raw), &record); err != nil {
		return record, err
	}
	b := record.Binding
	if b.RunID != r.RunID || b.AgentID != r.AgentID || b.NodeID != r.NodeID || b.BootID != r.BootID || b.Generation != r.Generation || record.Revision != r.Revision || !reflect.DeepEqual(b, scene.Active.Record.Binding) || record.State != "stopped" || record.Revision <= scene.Active.Record.Revision || !reflect.DeepEqual(record.Process, scene.Active.Record.Process) || !reflect.DeepEqual(record.Authorization, scene.Active.Record.Authorization) || !reflect.DeepEqual(record.Watchdog, scene.Active.Record.Watchdog) {
		return record, errors.New("the actual stopped node journal row differs")
	}
	return record, nil
}

// Read-only polling observes the node's durable stop. A stopped run does not
// require the service process to exit.
func waitServiceLifecycleLossJournal(ctx context.Context, scene serviceLifecycleScene) (out serviceLifecycleJournalReadback, err error) {
	deadline, cancel := context.WithTimeout(ctx, time.Duration(scene.NodeConfig.StopTimeoutMS)*time.Millisecond+3*time.Second)
	defer cancel()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		out, err = readServiceLifecycleJournal(deadline, scene)
		if err != nil {
			return out, err
		}
		var record lifecycle.Record
		if err = lifecycle.DecodeTransport(bytes.NewReader(out.Raw), &record); err != nil {
			return out, err
		}
		if record.State == "stopped" {
			return out, nil
		}
		select {
		case <-deadline.Done():
			return out, errors.New("the watchdog loss durable stop is unconfirmed")
		case <-tick.C:
		}
	}
}
