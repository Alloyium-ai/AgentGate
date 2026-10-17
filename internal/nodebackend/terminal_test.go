// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDurableTerminalSurvivesCompletedBufferEviction(t *testing.T) {
	binding := pinBinding()
	proof := domainstore.RootProof{OwnedPrefix: "alloyium-poc-job-1234567890abcdef-"}
	name, err := domainstore.ReservationName(proof.OwnedPrefix, binding)
	if err != nil {
		t.Fatal(err)
	}
	stopped := lifecycle.Evidence{Binding: binding, Phase: "stopped", Terminated: true, Empty: true, RightsRemoved: true, ReadbackDigest: strings.Repeat("6", 64)}
	stopped.Digest = lifecycle.EvidenceDigest(stopped)
	evidence := stopped.Digest
	output := []byte("owned result")
	sum := sha256.Sum256(output)
	terminal := lifecycle.Terminal{Protocol: lifecycle.TerminalProtocol, Binding: binding, State: "aborted", ExitCode: 1, DomainEmpty: true, RightsRemoved: true, EvidenceDigest: evidence, Output: output, OutputDigest: hex.EncodeToString(sum[:]), EvidenceVerdict: "INCOMPLETE"}
	r := &run{binding: binding, reservation: domainstore.Reservation{Name: name}, stopped: &stopped}
	b := &Backend{config: Config{AuditRoot: t.TempDir(), Domain: domainstore.Config{Proof: proof}}, runs: map[string]*run{binding.RunID: r}}
	if err = b.persistTerminal(r, terminal); err != nil {
		t.Fatal(err)
	}
	b.evict(r)
	if _, err = b.get(binding.RunID); err == nil {
		t.Fatal("the completed kernel buffers remained cached")
	}
	got, err := b.Terminal(context.Background(), binding, evidence)
	if err != nil || string(got.Output) != string(output) || got.EvidenceVerdict != "INCOMPLETE" {
		t.Fatal(got, err)
	}
	terminal.Output = []byte("changed")
	raw, _ := json.Marshal(terminal)
	if err = os.WriteFile(filepath.Join(b.config.AuditRoot, name+".terminal.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Terminal(context.Background(), binding, evidence); err == nil {
		t.Fatal("changed output bytes became a valid terminal")
	}
}

func TestRecoveredStopRemainsDurableAndIncomplete(t *testing.T) {
	binding := pinBinding()
	proof := domainstore.RootProof{OwnedPrefix: "alloyium-poc-job-1234567890abcdef-"}
	b := &Backend{config: Config{AuditRoot: t.TempDir(), Domain: domainstore.Config{Proof: proof}}}
	e := lifecycle.Evidence{Binding: binding, Phase: "stopped", Terminated: true, Empty: true, RightsRemoved: true, ReadbackDigest: strings.Repeat("7", 64)}
	e.Digest = lifecycle.EvidenceDigest(e)
	got, err := b.persistRecovered(context.Background(), e, "recovery-fail-closed")
	if err != nil || got.Digest != e.Digest {
		t.Fatal(got, err)
	}
	terminal, err := b.Terminal(context.Background(), binding, got.Digest)
	if err != nil || terminal.State != "aborted" || terminal.ExitCode != -1 || terminal.EvidenceVerdict != "INCOMPLETE" || got.CountersAvailable {
		t.Fatal(terminal, got, err)
	}
	// A crash after terminal fsync can precede the lifecycle journal commit.
	// The next physical absence proof must retain the original stop digest.
	retry := copyValue(e)
	retry.NoDomain = true
	retry.ReadbackDigest = strings.Repeat("8", 64)
	retry.Digest = lifecycle.EvidenceDigest(retry)
	got, err = b.persistRecovered(context.Background(), retry, "recovery-fail-closed")
	if err != nil || got.Digest != e.Digest {
		t.Fatal(got, err)
	}
	entries, err := os.ReadDir(b.config.AuditRoot)
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
	name, _ := domainstore.ReservationName(proof.OwnedPrefix, binding)
	record, legacy, err := readStopRecord(filepath.Join(b.config.AuditRoot, name+".terminal.json"))
	if err != nil || legacy || record.Evidence.Digest != e.Digest {
		t.Fatal(record, legacy, err)
	}
	r := &run{binding: binding, reservation: domainstore.Reservation{Name: name}, stopped: &record.Evidence}
	if err = b.persistTerminal(r, terminal); err != nil {
		t.Fatal("an exact durable write is not idempotent", err)
	}
	terminal.State = "revoked"
	if err = b.persistTerminal(r, terminal); err == nil {
		t.Fatal("a different terminal replaced durable evidence")
	}
}

func TestRecoveredStopRejectsCorruptOrChangedRecords(t *testing.T) {
	binding := pinBinding()
	proof := domainstore.RootProof{OwnedPrefix: "alloyium-poc-job-1234567890abcdef-"}
	b := &Backend{config: Config{AuditRoot: t.TempDir(), Domain: domainstore.Config{Proof: proof}}}
	e := lifecycle.Evidence{Binding: binding, Phase: "stopped", Terminated: true, Empty: true, RightsRemoved: true, ReadbackDigest: strings.Repeat("7", 64)}
	e.Digest = lifecycle.EvidenceDigest(e)
	if _, err := b.persistRecovered(context.Background(), e, "node-recovery"); err != nil {
		t.Fatal(err)
	}
	name, _ := domainstore.ReservationName(proof.OwnedPrefix, binding)
	path := filepath.Join(b.config.AuditRoot, name+".terminal.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record stopRecord
	if err = json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	record.Evidence.Decisions++
	raw, _ = json.Marshal(record)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = b.persistRecovered(context.Background(), e, "node-recovery"); err == nil {
		t.Fatal("corrupt evidence repaired the journal")
	}
}
func TestCompleteTerminalRequiresBothDurableSignatures(t *testing.T) {
	b := pinBinding()
	sum := sha256.Sum256(nil)
	terminal := lifecycle.Terminal{Protocol: lifecycle.TerminalProtocol, Binding: b, State: "completed", ExitCode: 0, DomainEmpty: true, RightsRemoved: true, EvidenceDigest: strings.Repeat("6", 64), OutputDigest: hex.EncodeToString(sum[:]), EvidenceVerdict: "INCOMPLETE"}
	if terminalIdentity(b, terminal, terminal.EvidenceDigest) == nil {
		t.Fatal("an incomplete result became completed")
	}
	terminal.State = "aborted"
	if terminalIdentity(b, terminal, terminal.EvidenceDigest) != nil {
		t.Fatal("an explicit incomplete abort was rejected")
	}
}

func TestHistoricalCutoffGapRemainsReadableWithoutCompleteClaim(t *testing.T) {
	tm := lifecycle.Terminal{Binding: pinBinding(), State: "completed", ExitCode: 0, OutputDigest: strings.Repeat("a", 64), EvidenceVerdict: "VALID_COMPLETE"}
	bundle := jobaudit.Bundle{Header: jobaudit.Header{Binding: tm.Binding}, Seal: &jobaudit.NodeSeal{Terminal: jobaudit.Terminal{State: tm.State, ExitCode: tm.ExitCode, OutputDigest: tm.OutputDigest}}}
	got, err := terminalAuditReadback(tm, bundle, jobaudit.Verdict{State: "INCOMPLETE", Reason: "grant-expiry-bound-missing"})
	if files, filesErr := terminalAuditReadback(tm, bundle, jobaudit.Verdict{State: "INCOMPLETE", Reason: "runtime-files-proof-missing"}); filesErr != nil || files.State != "aborted" || files.EvidenceVerdict != "INCOMPLETE" {
		t.Fatal(files, filesErr)
	}
	if err != nil || got.State != "aborted" || got.EvidenceVerdict != "INCOMPLETE" || got.ExitCode != 0 || tm.State != "completed" {
		t.Fatal(got, err)
	}
	for _, v := range []jobaudit.Verdict{{State: "TAMPERED", Reason: "raw-resource-event-differs"}, {State: "UNKNOWN_KEY"}, {State: "INCOMPLETE", Reason: "terminal-or-counters-incomplete"}} {
		if _, err = terminalAuditReadback(tm, bundle, v); err == nil {
			t.Fatal("an unrelated audit failure became a valid historical readback", v)
		}
	}
	bundle.Seal.Terminal.OutputDigest = strings.Repeat("b", 64)
	if _, err = terminalAuditReadback(tm, bundle, jobaudit.Verdict{State: "INCOMPLETE", Reason: "grant-expiry-bound-missing"}); err == nil {
		t.Fatal("a changed historical output became readable")
	}
}
