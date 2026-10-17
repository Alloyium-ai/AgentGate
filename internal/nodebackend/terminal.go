// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
)

const stopRecordProtocol = "agentgate.node.stop.v1"

type stopRecord struct {
	Protocol string             `json:"protocol"`
	Evidence lifecycle.Evidence `json:"evidence"`
	Terminal lifecycle.Terminal `json:"terminal"`
}

func (r stopRecord) validate() error {
	e := r.Evidence
	if r.Protocol != stopRecordProtocol || e.Phase != "stopped" || !e.Terminated || !e.Empty || !e.RightsRemoved || e.Released || !validDigest(e.ReadbackDigest) || e.Binding.CgroupID == 0 && !e.NoDomain || e.Digest != lifecycle.EvidenceDigest(e) {
		return errors.New("the durable stop evidence differs")
	}
	return terminalIdentity(e.Binding, r.Terminal, e.Digest)
}

func terminalIdentity(b lifecycle.Binding, t lifecycle.Terminal, evidence string) error {
	if b.Validate(b.CgroupID == 0) != nil {
		return errors.New("the terminal binding is invalid")
	}
	switch t.EvidenceVerdict {
	case "VALID_COMPLETE", "INCOMPLETE", "TAMPERED", "UNKNOWN_KEY":
	default:
		return errors.New("the terminal evidence verdict is unknown")
	}
	sum := sha256.Sum256(t.Output)
	if t.Protocol != lifecycle.TerminalProtocol || !sameQuery(b, t.Binding) || b.CgroupID != t.Binding.CgroupID || !t.DomainEmpty || !t.RightsRemoved || t.EvidenceDigest != evidence || !validDigest(evidence) || t.OutputDigest != hex.EncodeToString(sum[:]) || len(t.Output) > lifecycle.MaxInputBytes {
		return errors.New("the durable terminal binding or output differs")
	}
	switch t.State {
	case "completed":
		if t.ExitCode != 0 || t.EvidenceVerdict != "VALID_COMPLETE" {
			return errors.New("a completed terminal lacks valid evidence")
		}
	case "failed", "cancelled", "expired", "revoked", "aborted":
	default:
		return errors.New("the terminal state is unknown")
	}
	return nil
}
func (b *Backend) persistTerminal(r *run, t lifecycle.Terminal) error {
	if r.stopped == nil {
		return errors.New("the terminal has no stop evidence")
	}
	if err := terminalIdentity(r.binding, t, r.stopped.Digest); err != nil {
		return err
	}
	record := stopRecord{Protocol: stopRecordProtocol, Evidence: copyValue(*r.stopped), Terminal: t}
	if err := record.validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err = protectedRoot(b.config.AuditRoot); err != nil {
		return err
	}
	fd, err := unix.Open(b.config.AuditRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	name := r.reservation.Name + ".terminal.json"
	temporary := ".stop-" + hex.EncodeToString(nonce[:])
	fileFD, err := unix.Openat(fd, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fileFD), temporary)
	defer file.Close()
	defer unix.Unlinkat(fd, temporary, 0)
	if _, err = file.Write(raw); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = unix.Renameat2(fd, temporary, fd, name, unix.RENAME_NOREPLACE); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return err
		}
		prior, _, readErr := readStopRecord(filepath.Join(b.config.AuditRoot, name))
		if readErr != nil || !bytes.Equal(mustJSON(prior), raw) {
			return errors.New("the existing durable stop record differs")
		}
	}
	return unix.Fsync(fd)
}
func readStopRecord(path string) (stopRecord, bool, error) {
	var record stopRecord
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return record, false, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&077 != 0 || st.Nlink != 1 || st.Size <= 0 || st.Size > 2<<20 {
		return record, false, errors.New("the terminal file custody differs")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return record, false, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil {
		return record, false, err
	}
	var identity struct {
		Protocol string `json:"protocol"`
	}
	if err = json.Unmarshal(raw, &identity); err != nil {
		return record, false, err
	}
	if identity.Protocol == lifecycle.TerminalProtocol {
		// Preserve terminal readback from the earlier file format. It contains
		// no recoverable stop evidence and cannot repair an unfinished journal.
		err = lifecycle.DecodeTransport(bytes.NewReader(raw), &record.Terminal)
		return record, true, err
	}
	if err = lifecycle.DecodeTransport(bytes.NewReader(raw), &record); err != nil {
		return record, false, err
	}
	return record, false, record.validate()
}
func readTerminalFile(path string) (lifecycle.Terminal, error) {
	record, _, err := readStopRecord(path)
	return record.Terminal, err
}

// Terminal reconstructs a stopped reply after restart. A complete reply also
// requires the durable raw log and both signatures under current pinned trust.
func (b *Backend) Terminal(ctx context.Context, binding lifecycle.Binding, evidence string) (lifecycle.Terminal, error) {
	if err := ctx.Err(); err != nil {
		return lifecycle.Terminal{}, err
	}
	if err := protectedRoot(b.config.AuditRoot); err != nil {
		return lifecycle.Terminal{}, err
	}
	name, err := domainstore.ReservationName(b.config.Domain.Proof.OwnedPrefix, binding)
	if err != nil {
		return lifecycle.Terminal{}, err
	}
	t, err := readTerminalFile(filepath.Join(b.config.AuditRoot, name+".terminal.json"))
	if err != nil {
		return t, err
	}
	if err = terminalIdentity(binding, t, evidence); err != nil {
		return t, err
	}
	if t.EvidenceVerdict != "VALID_COMPLETE" {
		return t, nil
	}
	path := filepath.Join(b.config.AuditRoot, name+".audit")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return t, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return t, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&077 != 0 {
		return t, errors.New("the terminal audit custody differs")
	}
	bundle, err := jobaudit.Read(file)
	if err != nil {
		return t, err
	}
	document, err := b.config.Documents.Resolve(ctx, binding.PolicyDigest)
	if err != nil {
		return t, err
	}
	v := jobaudit.VerifyOffline(bundle, jobaudit.Trust{NodeKeys: b.config.NodeKeys, AuthorityKeys: b.config.AuthorityKeys, Registry: nodecontrol.Registry(b.config.Registry, binding), Document: document})
	return terminalAuditReadback(t, bundle, v)
}
func terminalAuditReadback(t lifecycle.Terminal, bundle jobaudit.Bundle, v jobaudit.Verdict) (lifecycle.Terminal, error) {
	if bundle.Seal == nil || !bytes.Equal(mustJSON(bundle.Header.Binding), mustJSON(t.Binding)) || bundle.Seal.Terminal.OutputDigest != t.OutputDigest || bundle.Seal.Terminal.State != t.State || bundle.Seal.Terminal.ExitCode != t.ExitCode {
		return t, errors.New("the durable terminal lacks complete signed audit evidence")
	}
	if v.State == "VALID_COMPLETE" {
		return t, nil
	}
	if v.State == "INCOMPLETE" && (v.Reason == "grant-expiry-bound-missing" || v.Reason == "runtime-files-proof-missing") {
		// Keep a historical result readable without upgrading its old runtime or expiry
		// evidence. The protected original terminal and raw trail stay intact.
		t.EvidenceVerdict = "INCOMPLETE"
		if t.State == "completed" {
			t.State = "aborted"
		}
		return t, nil
	}
	return t, errors.New("the durable terminal lacks complete signed audit evidence")
}
func mustJSON(v any) []byte { raw, _ := json.Marshal(v); return raw }
func (b *Backend) evict(r *run) {
	b.mu.Lock()
	if b.runs[r.binding.RunID] == r {
		delete(b.runs, r.binding.RunID)
	}
	b.mu.Unlock()
}
