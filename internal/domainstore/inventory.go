// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package domainstore

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"strings"
)

func (s *Store) reservations() (map[string]Reservation, []error) {
	entries, err := s.entries()
	if err != nil {
		return nil, []error{err}
	}
	out := map[string]Reservation{}
	failures := []error{}
	for _, entry := range entries {
		var record Reservation
		if s.read(entry.Name(), &record) != nil || reservationFile(s.config.NodeID, record.Binding.RunID) != entry.Name() {
			failures = append(failures, errors.New("a protected reservation is corrupt"))
			continue
		}
		if record.Binding.BootID != s.config.Proof.BootID {
			continue
		}
		r, loadErr := s.load(record.Binding)
		if loadErr != nil {
			failures = append(failures, loadErr)
			continue
		}
		if _, exists := out[r.Name]; exists {
			failures = append(failures, errors.New("the reservation namespace has duplicate domains"))
			continue
		}
		out[r.Name] = r
	}
	return out, failures
}
func (s *Store) ownedName(name string) bool {
	prefix := s.config.Proof.OwnedPrefix
	return strings.HasPrefix(name, prefix) && digestPattern.MatchString(strings.TrimPrefix(name, prefix))
}
func (s *Store) stopOrphan(ctx context.Context, root int, name string, id uint64) error {
	if !s.ownedName(name) || id == 0 {
		return errors.New("the orphan namespace custody differs")
	}
	fd, actual, err := openDomain(root, name)
	if err != nil || actual != id {
		if fd >= 0 {
			unix.Close(fd)
		}
		return errors.New("the orphan cgroup inode changed")
	}
	defer unix.Close(fd)
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.config.StopTimeout)
	defer cancel()
	readback, err := stopDomain(cleanup, fd)
	if err != nil {
		return err
	}
	receipt := OrphanReceipt{RootDigest: s.config.Proof.Digest(), Name: name, CgroupID: id, Terminated: true, Empty: true, PinsRetained: true, ReadbackDigest: readback}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", name, id)))
	return s.write("orphan-"+hex.EncodeToString(sum[:])+".json", receipt, false)
}

// ListOwnedDomains also stops corrupt or missing-record orphans inside the
// independently qualified namespace. It returns an error after orphan cleanup.
// The error closes admission. It never invents job or grant fields for an orphan.
func (s *Store) ListOwnedDomains(ctx context.Context) ([]lifecycle.Binding, error) {
	root, err := s.root()
	if err != nil {
		return nil, err
	}
	defer unix.Close(root)
	unlock, err := s.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	reservations, failures := s.reservations()
	duplicate, err := unix.Dup(root)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(duplicate), RootPath)
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return nil, errors.New("the owned root-level namespace cannot read")
	}
	bindings := []lifecycle.Binding{}
	for _, entry := range entries {
		name := entry.Name()
		if !s.ownedName(name) {
			continue
		}
		fd, id, openErr := openDomain(root, name)
		if openErr != nil {
			failures = append(failures, errors.New("an owned root-level cgroup custody differs"))
			continue
		}
		r, exists := reservations[name]
		valid := exists && r.State != "reserved" && r.State != "reconciled"
		b := copyValue(r.Binding)
		if valid && r.State == "creating" && b.CgroupID == 0 {
			b.CgroupID = id
		}
		valid = valid && b.CgroupID == id && b.Validate(false) == nil
		if valid && r.State == "terminated" && digestPattern.MatchString(r.TerminationReadback) {
			empty, _, readErr := domainEmpty(fd)
			if readErr == nil && empty {
				unix.Close(fd)
				continue
			}
			if readErr != nil {
				failures = append(failures, errors.New("the terminated domain empty readback is unavailable"))
			}
		}
		unix.Close(fd)
		if !valid {
			if stopErr := s.stopOrphan(ctx, root, name, id); stopErr != nil {
				failures = append(failures, stopErr)
			}
			failures = append(failures, errors.New("an owned orphan stopped or requires reconciliation"))
			continue
		}
		bindings = append(bindings, b)
	}
	return bindings, errors.Join(failures...)
}

// StopOwnedDomain tolerates a stale watchdog inventory only through the exact
// authenticated terminal reservation. Missing counters remain an explicit error.
func (s *Store) StopOwnedDomain(ctx context.Context, b lifecycle.Binding, reason string) (lifecycle.WatchdogStopEvidence, error) {
	if b.Validate(false) != nil {
		return lifecycle.WatchdogStopEvidence{}, errors.New("a resolved owned stop binding is required")
	}
	result, err := s.StopReservation(ctx, b, reason)
	if result.DomainEvidence != nil {
		return *result.DomainEvidence, err
	}
	r := result.Reservation
	if !reservationMatches(r, b) || !result.Empty || !digestPattern.MatchString(result.ReadbackDigest) || (r.State != "terminated" && r.State != "reconciled") {
		return lifecycle.WatchdogStopEvidence{}, errors.New("the exact terminal domain proof is unavailable")
	}
	e := lifecycle.WatchdogStopEvidence{Binding: copyValue(r.Binding), Reason: reason, Retired: true, NoDomain: result.NoDomain, Terminated: true, Empty: true, RightsRemoved: result.RightsRemoved, CountersAvailable: false, ReadbackDigest: result.ReadbackDigest, CurrentRootProofDigest: result.CurrentRootProofDigest, ReservationRootProofDigest: result.ReservationRootProofDigest}
	if err = s.saveWatchdogEvidence(e); err != nil {
		return lifecycle.WatchdogStopEvidence{}, err
	}
	e.Digest = lifecycle.WatchdogStopDigest(e)
	return e, errors.New("the domain stopped but kernel counters are unavailable")
}
func (s *Store) saveWatchdogEvidence(e lifecycle.WatchdogStopEvidence) error {
	e.Digest = lifecycle.WatchdogStopDigest(e)
	if err := s.write("stop-"+e.Digest+".json", e, true); err != nil {
		var prior lifecycle.WatchdogStopEvidence
		if s.read("stop-"+e.Digest+".json", &prior) != nil || prior.Digest != e.Digest {
			return errors.New("the domain stop receipt is not durable")
		}
	}
	return nil
}

func (s *Store) stopOwnedLocked(ctx context.Context, r *Reservation, fd int, b lifecycle.Binding, reason string) (lifecycle.WatchdogStopEvidence, error) {
	if r.State != "stop-pending" && r.State != "terminated" {
		r.State = "stop-pending"
		if err := s.save(r); err != nil {
			_, _ = stopDomain(ctx, fd)
			return lifecycle.WatchdogStopEvidence{}, errors.New("the domain stop intent is not durable")
		}
	}
	readback, events, mono, err := stopDomainRaw(ctx, fd)
	if err != nil {
		return lifecycle.WatchdogStopEvidence{}, err
	}
	r.Binding = copyValue(b)
	r.State = "terminated"
	r.TerminationReadback = readback
	r.TerminationEvents = events
	r.TerminationMonoNS = mono
	if err = s.save(r); err != nil {
		return lifecycle.WatchdogStopEvidence{}, errors.New("the domain stopped but termination custody is not durable")
	}
	if s.config.CounterReader == nil {
		return lifecycle.WatchdogStopEvidence{}, errors.New("the domain stopped but kernel counters are unavailable")
	}
	decisions, lost, err := s.config.CounterReader.ReadCounters(ctx, b)
	if err != nil {
		return lifecycle.WatchdogStopEvidence{}, errors.New("the domain stopped but kernel counters are unavailable")
	}
	e := lifecycle.WatchdogStopEvidence{Binding: copyValue(b), Reason: reason, Terminated: true, Empty: true, PinsRetained: true, CountersAvailable: true, ReadbackDigest: readback, CurrentRootProofDigest: s.config.Proof.Digest(), ReservationRootProofDigest: r.RootDigest, Decisions: decisions, Lost: lost}
	e.Digest = lifecycle.WatchdogStopDigest(e)
	if err = s.write("stop-"+e.Digest+".json", e, true); err != nil {
		var prior lifecycle.WatchdogStopEvidence
		if s.read("stop-"+e.Digest+".json", &prior) != nil || prior.Digest != e.Digest {
			return lifecycle.WatchdogStopEvidence{}, errors.New("the domain stop receipt is not durable")
		}
	}
	return e, nil

}

var _ lifecycle.WatchdogDomainStopper = (*Store)(nil)
