// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package domainstore

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"reflect"
	"strings"
	"time"
)

type Store struct {
	config  Config
	stateFD int
	key     []byte
}
type namespaceRecord struct {
	NodeID     string `json:"node_id"`
	RootDigest string `json:"root_digest"`
	Prefix     string `json:"prefix"`
}

func New(config Config) (*Store, error) {
	if os.Geteuid() != 0 || !identifier.MatchString(config.NodeID) || config.Proof.validate() != nil || config.StopTimeout <= 0 || config.StopTimeout > 30*time.Second {
		return nil, errors.New("protected domain configuration and bounded cleanup are required")
	}
	fd, err := openPrivateDirectory(config.StateDir)
	if err != nil {
		return nil, err
	}
	s := &Store{config: config, stateFD: fd}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	root, err := s.root()
	if err != nil {
		return nil, err
	}
	unix.Close(root)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	unlock, err := s.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	s.key, err = readPrivate(fd, "ownership.key", 32)
	if errors.Is(err, unix.ENOENT) {
		entries, listErr := os.ReadDir(config.StateDir)
		if listErr != nil {
			return nil, listErr
		}
		for _, entry := range entries {
			if entry.Name() != ".lock" {
				return nil, errors.New("the existing reservation namespace has no ownership key")
			}
		}
		s.key = make([]byte, 32)
		if _, err = rand.Read(s.key); err != nil {
			return nil, err
		}
		keyFD, createErr := unix.Openat(fd, "ownership.key", unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if createErr != nil {
			return nil, errors.New("the reservation key cannot create")
		}
		keyFile := os.NewFile(uintptr(keyFD), "ownership.key")
		_, err = keyFile.Write(s.key)
		if err == nil {
			err = keyFile.Sync()
		}
		keyFile.Close()
		if err != nil || unix.Fsync(fd) != nil {
			return nil, errors.New("the reservation key is not durable")
		}
	}
	if err != nil || len(s.key) != 32 {
		return nil, errors.New("the reservation ownership key is invalid")
	}
	expected := namespaceRecord{config.NodeID, config.Proof.IdentityDigest(), config.Proof.OwnedPrefix}
	var namespace namespaceRecord
	namespaceName := "namespace-" + strings.TrimPrefix(reservationFile("namespace", config.Proof.BootID), "r-")
	err = s.read(namespaceName, &namespace)
	if errors.Is(err, unix.ENOENT) {
		err = s.write(namespaceName, expected, true)
		namespace = expected
	}
	if err != nil || namespace != expected {
		return nil, errors.New("the reservation namespace differs from the qualified root")
	}
	ok = true
	return s, nil
}
func (s *Store) Close() error {
	for i := range s.key {
		s.key[i] = 0
	}
	if s.stateFD < 0 {
		return nil
	}
	err := unix.Close(s.stateFD)
	s.stateFD = -1
	return err
}
func copyValue[T any](value T) T {
	raw, _ := json.Marshal(value)
	var out T
	_ = json.Unmarshal(raw, &out)
	return out
}
func (s *Store) validateBinding(b lifecycle.Binding, preparing bool) error {
	if b.Validate(preparing) != nil || b.NodeID != s.config.NodeID || b.BootID != s.config.Proof.BootID || b.ArtifactDigests["domain-root"] != s.config.Proof.Digest() {
		return errors.New("the domain binding differs from the qualified root")
	}
	return nil
}
func (s *Store) load(b lifecycle.Binding) (Reservation, error) {
	var r Reservation
	if err := s.read(reservationFile(s.config.NodeID, b.RunID), &r); err != nil {
		return r, err
	}
	if r.Binding.Validate(r.Binding.CgroupID == 0) != nil || r.Binding.NodeID != s.config.NodeID || r.Binding.BootID != s.config.Proof.BootID || r.Proof.validate() != nil || r.Proof.IdentityDigest() != s.config.Proof.IdentityDigest() || r.RootDigest != r.Proof.Digest() || r.Binding.ArtifactDigests["domain-root"] != r.RootDigest || r.Name != reservationName(s.config.Proof.OwnedPrefix, r.Binding) || r.Revision == 0 {
		return r, errors.New("the protected reservation identity differs")
	}
	switch r.State {
	case "reserved", "creating", "created", "placed", "stop-pending", "terminated", "reconciled":
	default:
		return r, errors.New("the protected reservation state is invalid")
	}
	return r, nil
}
func (s *Store) save(r *Reservation) error {
	next := copyValue(*r)
	next.Revision++
	if err := s.write(reservationFile(s.config.NodeID, r.Binding.RunID), next, false); err != nil {
		return err
	}
	*r = next
	return nil
}
func (s *Store) Reserve(ctx context.Context, binding lifecycle.Binding) (Reservation, error) {
	b := copyValue(binding)
	if s.validateBinding(b, true) != nil || b.CgroupID != 0 {
		return Reservation{}, errors.New("a fresh unallocated root-bound reservation is required")
	}
	now, err := (lifecycle.MonotonicClock{}).NowNS()
	if err != nil || now >= b.DeadlineNS {
		return Reservation{}, errors.New("the reservation deadline is unavailable or expired")
	}
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
	r := Reservation{Binding: b, Proof: s.config.Proof, RootDigest: s.config.Proof.Digest(), Name: reservationName(s.config.Proof.OwnedPrefix, b), State: "reserved", Revision: 1}
	var info unix.Stat_t
	if unix.Fstatat(root, r.Name, &info, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {
		return Reservation{}, errors.New("the fresh reservation domain already exists or is ambiguous")
	}
	if err = s.write(reservationFile(s.config.NodeID, b.RunID), r, true); err != nil {
		return Reservation{}, err
	}
	return copyValue(r), nil
}
func (s *Store) Create(ctx context.Context, reservation Reservation) (lifecycle.Binding, error) {
	if s.validateBinding(reservation.Binding, true) != nil {
		return lifecycle.Binding{}, errors.New("the reservation binding is invalid")
	}
	root, err := s.root()
	if err != nil {
		return lifecycle.Binding{}, err
	}
	defer unix.Close(root)
	unlock, err := s.lock(ctx)
	if err != nil {
		return lifecycle.Binding{}, err
	}
	defer unlock()
	r, err := s.load(reservation.Binding)
	if err != nil || !reflect.DeepEqual(r, reservation) || r.State != "reserved" || r.Binding.CgroupID != 0 {
		return lifecycle.Binding{}, errors.New("the immutable creation reservation differs")
	}
	r.State = "creating"
	if err = s.save(&r); err != nil {
		return lifecycle.Binding{}, err
	}
	if unix.Mkdirat(root, r.Name, 0755) != nil {
		return lifecycle.Binding{}, errors.New("the owned root-level cgroup cannot create")
	}
	fd, id, err := openDomain(root, r.Name)
	if err != nil {
		return lifecycle.Binding{}, err
	}
	defer unix.Close(fd)
	empty, _, err := domainEmpty(fd)
	if err != nil || !empty {
		return lifecycle.Binding{}, errors.New("the fresh cgroup is not empty")
	}
	r.Binding.CgroupID = id
	r.State = "created"
	if err = s.save(&r); err != nil {
		return lifecycle.Binding{}, err
	}
	return copyValue(r.Binding), nil
}
func (s *Store) exact(root int, b lifecycle.Binding) (Reservation, int, error) {
	if b.Validate(false) != nil || b.NodeID != s.config.NodeID || b.BootID != s.config.Proof.BootID || b.CgroupID == 0 {
		return Reservation{}, -1, errors.New("a resolved owned cgroup binding is required")
	}
	r, err := s.load(b)
	if err != nil {
		return r, -1, err
	}
	expected := r.Binding
	if expected.CgroupID == 0 && r.State == "creating" {
		expected.CgroupID = b.CgroupID
	}
	if !reflect.DeepEqual(expected, b) || r.State == "reconciled" {
		return r, -1, errors.New("the immutable cgroup binding differs")
	}
	fd, id, err := openDomain(root, r.Name)
	if err != nil {
		return r, -1, err
	}
	if id != b.CgroupID {
		unix.Close(fd)
		return r, -1, errors.New("the owned cgroup inode changed")
	}
	return r, fd, nil
}
func (s *Store) ReconcileEmpty(ctx context.Context, b lifecycle.Binding) error {
	root, err := s.root()
	if err != nil {
		return err
	}
	defer unix.Close(root)
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	r, fd, err := s.exact(root, b)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if s.config.RightsVerifier == nil || s.config.RightsVerifier.VerifyRemoved(ctx, b) != nil {
		return errors.New("the kernel rights and pin cleanup is unconfirmed")
	}
	if r.State != "terminated" {
		return errors.New("the domain has no confirmed termination receipt")
	}
	empty, _, err := domainEmpty(fd)
	if err != nil || !empty {
		return errors.New("the terminated domain is not empty")
	}
	// The backend calls this only after it verifies complete rights and pin cleanup.
	if err = unix.Unlinkat(root, r.Name, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("the empty owned domain cannot remove: %w", err)
	}
	r.State = "reconciled"
	return s.save(&r)
}
func (s *Store) entries() ([]os.DirEntry, error) {
	entries, err := os.ReadDir(s.config.StateDir)
	if err != nil {
		return nil, errors.New("the reservation namespace cannot read")
	}
	out := []os.DirEntry{}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "r-") && strings.HasSuffix(entry.Name(), ".json") {
			out = append(out, entry)
		}
	}
	return out, nil
}
