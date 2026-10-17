// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package domainstore

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"reflect"
)

// ReservationName derives a name only. It proves no ownership or live cgroup.
// Counter readers can use it under the store lock without recursive resolution.
func ReservationName(prefix string, b lifecycle.Binding) (string, error) {
	if !ownedPrefix.MatchString(prefix) || b.Validate(b.CgroupID == 0) != nil {
		return "", errors.New("the reservation name inputs are invalid")
	}
	return reservationName(prefix, b), nil
}
func reservationMatches(r Reservation, b lifecycle.Binding) bool {
	expected := copyValue(r.Binding)
	if b.CgroupID == 0 {
		expected.CgroupID = 0
	}
	return reflect.DeepEqual(expected, b)
}
func (s *Store) resolveLocked(root int, b lifecycle.Binding) (Reservation, error) {
	if b.Validate(b.CgroupID == 0) != nil || b.NodeID != s.config.NodeID || b.BootID != s.config.Proof.BootID {
		return Reservation{}, errors.New("the reservation query binding is invalid")
	}
	r, err := s.load(b)
	if err != nil {
		return r, err
	}
	if !reservationMatches(r, b) {
		return r, errors.New("the authenticated reservation binding differs")
	}
	fd, id, err := openDomain(root, r.Name)
	if errors.Is(err, unix.ENOENT) {
		if r.Binding.CgroupID == 0 && (r.State == "reserved" || r.State == "creating" || r.State == "reconciled") {
			return r, nil
		}
		if r.Binding.CgroupID != 0 && (r.State == "terminated" || r.State == "reconciled") {
			return r, nil
		}
		return r, errors.New("the allocated domain disappeared before confirmed termination")
	}
	if err != nil {
		return r, err
	}
	defer unix.Close(fd)
	if r.Binding.CgroupID == 0 {
		if r.State != "creating" {
			return r, errors.New("the reservation has an unexpected allocated domain")
		}
		r.Binding.CgroupID = id
		r.State = "created"
		if err = s.save(&r); err != nil {
			return r, err
		}
	} else if r.Binding.CgroupID != id {
		return r, errors.New("the authenticated domain inode changed")
	}
	if r.State == "reconciled" {
		return r, errors.New("a reconciled domain reappeared")
	}
	return r, nil
}

// Resolve accepts CgroupID0 only as an unallocated query. A creating reservation
// resolves its actual inode once. Every other immutable field must still match.
func (s *Store) Resolve(ctx context.Context, b lifecycle.Binding) (Reservation, error) {
	root, err := s.root()
	if err != nil {
		return Reservation{}, err
	}
	defer unix.Close(root)
	unlock, err := s.lock(ctx)
	if err != nil {
		return Reservation{}, err
	}
	defer unlock()
	return s.resolveLocked(root, copyValue(b))
}

type ReservationStop struct {
	Protocol                   string                          `json:"protocol"`
	Reservation                Reservation                     `json:"reservation"`
	NoDomain                   bool                            `json:"no_domain"`
	Empty                      bool                            `json:"empty"`
	PinsRetained               bool                            `json:"pins_retained"`
	RightsRemoved              bool                            `json:"rights_removed"`
	CountersAvailable          bool                            `json:"counters_available"`
	DomainEvidence             *lifecycle.WatchdogStopEvidence `json:"domain_evidence,omitempty"`
	CurrentRootProofDigest     string                          `json:"current_root_proof_digest"`
	ReservationRootProofDigest string                          `json:"reservation_root_proof_digest"`
	ReadbackDigest             string                          `json:"readback_digest"`
	Digest                     string                          `json:"digest"`
}

func stopDigest(result ReservationStop) string {
	result.Digest = ""
	raw, _ := json.Marshal(result)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func (s *Store) saveStopResult(result *ReservationStop) error {
	result.Digest = stopDigest(*result)
	name := "reservation-stop-" + result.Digest + ".json"
	if err := s.write(name, *result, true); err != nil {
		var prior ReservationStop
		if s.read(name, &prior) != nil || prior.Digest != result.Digest {
			return errors.New("the reservation stop outcome is not durable")
		}
	}
	return nil
}

// StopReservation resolves failure cleanup without selecting cgroup zero. An
// allocation absence gets a distinct durable outcome. It grants no execution.
func (s *Store) StopReservation(ctx context.Context, b lifecycle.Binding, reason string) (ReservationStop, error) {
	result := ReservationStop{Protocol: "agentgate.domain.reservation-stop.v1"}
	if !identifier.MatchString(reason) {
		return result, errors.New("the reservation stop reason is invalid")
	}
	root, err := s.root()
	if err != nil {
		return result, err
	}
	defer unix.Close(root)
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.config.StopTimeout)
	defer cancel()
	unlock, err := s.lock(cleanup)
	if err != nil {
		return result, err
	}
	defer unlock()
	r, err := s.resolveLocked(root, copyValue(b))
	if err != nil {
		return result, err
	}
	result.Reservation = r
	result.CurrentRootProofDigest = s.config.Proof.Digest()
	result.ReservationRootProofDigest = r.RootDigest
	fd, id, err := openDomain(root, r.Name)
	if errors.Is(err, unix.ENOENT) {
		if r.Binding.CgroupID != 0 && (s.config.RightsVerifier == nil || s.config.RightsVerifier.VerifyRemoved(cleanup, r.Binding) != nil) {
			return result, errors.New("the absent allocated domain has no verified rights cleanup")
		}
		r.State = "reconciled"
		raw, _ := json.Marshal(struct {
			Binding                                    lifecycle.Binding
			Name, CurrentRoot, ReservationRoot, Reason string
		}{r.Binding, r.Name, result.CurrentRootProofDigest, result.ReservationRootProofDigest, reason})
		sum := sha256.Sum256(append([]byte("agentgate-no-allocated-domain-v1\n"), raw...))
		r.TerminationReadback = hex.EncodeToString(sum[:])
		if err = s.save(&r); err != nil {
			return result, err
		}
		result.Reservation = r
		result.NoDomain = true
		result.Empty = true
		result.RightsRemoved = true
		result.ReadbackDigest = r.TerminationReadback
		if err = s.saveStopResult(&result); err != nil {
			return result, err
		}
		return result, nil
	}
	if err != nil {
		return result, err
	}
	defer unix.Close(fd)
	if id == 0 || id != r.Binding.CgroupID {
		return result, errors.New("the resolved reservation inode differs")
	}
	evidence, stopErr := s.stopOwnedLocked(cleanup, &r, fd, r.Binding, reason)
	result.Reservation = r
	result.ReadbackDigest = r.TerminationReadback
	empty, _, readErr := domainEmpty(fd)
	result.Empty = readErr == nil && empty
	result.PinsRetained = true
	if stopErr == nil {
		result.DomainEvidence = &evidence
		result.CountersAvailable = true
	}
	if err = s.saveStopResult(&result); err != nil {
		return result, err
	}
	return result, stopErr
}
