// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package domainstore owns protected root-level job reservations and cgroup custody.
package domainstore

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

const RootPath = "/sys/fs/cgroup"

var ownedPrefix = regexp.MustCompile(`^(?:agj-|alloyium-poc-job-)[a-f0-9]{16}-$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type RootProof struct {
	BootID                     string `json:"boot_id"`
	MountID                    uint64 `json:"mount_id,string"`
	Device                     uint64 `json:"device,string"`
	RootInode                  uint64 `json:"root_inode,string"`
	MountRoot                  string `json:"mount_root"`
	MountPoint                 string `json:"mount_point"`
	NamespaceDevice            uint64 `json:"namespace_device,string"`
	NamespaceInode             uint64 `json:"namespace_inode,string"`
	InitNamespaceDevice        uint64 `json:"init_namespace_device,string"`
	InitNamespaceInode         uint64 `json:"init_namespace_inode,string"`
	JobDepth                   int    `json:"job_depth"`
	OwnedPrefix                string `json:"owned_prefix"`
	QualificationReceiptDigest string `json:"qualification_receipt_digest"`
}

func (p RootProof) Digest() string {
	raw, _ := json.Marshal(p)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// IdentityDigest binds persistent root custody. Mount observations and their
// qualification receipt remain pinned for each process, outside cleanup identity.
func (p RootProof) IdentityDigest() string {
	p.MountID = 0
	p.QualificationReceiptDigest = ""
	return p.Digest()
}
func (p RootProof) validate() error {
	if !identifier.MatchString(p.BootID) || p.MountID == 0 || p.Device == 0 || p.RootInode == 0 || p.MountRoot != "/" || p.MountPoint != RootPath || p.NamespaceDevice == 0 || p.NamespaceInode == 0 || p.NamespaceDevice != p.InitNamespaceDevice || p.NamespaceInode != p.InitNamespaceInode || p.JobDepth != 1 || !ownedPrefix.MatchString(p.OwnedPrefix) || !digestPattern.MatchString(p.QualificationReceiptDigest) {
		return errors.New("a qualified unambiguous root-level cgroup proof is required")
	}
	return nil
}

// BarrierVerifier proves the static helper artifact, barrier pipe, runtime UID/GID,
// capabilities, no-new-privileges and ready read(fd3) observation. Caller flags do
// not establish this proof. The store also checks a stopped single-thread PID.
type BarrierVerifier interface {
	VerifyHeld(context.Context, lifecycle.Binding, lifecycle.HeldProcess) error
}
type RightsVerifier interface {
	VerifyRemoved(context.Context, lifecycle.Binding) error
}
type CounterReader interface {
	ReadCounters(context.Context, lifecycle.Binding) (uint64, uint64, error)
}
type Config struct {
	NodeID          string
	StateDir        string
	Proof           RootProof
	StopTimeout     time.Duration
	BarrierVerifier BarrierVerifier
	RightsVerifier  RightsVerifier
	CounterReader   CounterReader
}
type Reservation struct {
	Binding             lifecycle.Binding      `json:"binding"`
	Proof               RootProof              `json:"root_proof"`
	RootDigest          string                 `json:"root_digest"`
	Name                string                 `json:"name"`
	State               string                 `json:"state"`
	Revision            uint64                 `json:"revision,string"`
	TerminationReadback string                 `json:"termination_readback,omitempty"`
	TerminationEvents   []byte                 `json:"termination_events,omitempty"`
	TerminationMonoNS   uint64                 `json:"termination_mono_ns,string,omitempty"`
	Process             *lifecycle.HeldProcess `json:"process,omitempty"`
}
type Placement struct {
	Binding        lifecycle.Binding     `json:"binding"`
	Process        lifecycle.HeldProcess `json:"process"`
	ReadbackDigest string                `json:"readback_digest"`
}
type OrphanReceipt struct {
	RootDigest     string `json:"root_digest"`
	Name           string `json:"name"`
	CgroupID       uint64 `json:"cgroup_id,string"`
	Terminated     bool   `json:"terminated"`
	Empty          bool   `json:"empty"`
	PinsRetained   bool   `json:"pins_retained"`
	ReadbackDigest string `json:"readback_digest"`
}

func reservationName(prefix string, b lifecycle.Binding) string {
	b.CgroupID = 0
	raw, _ := json.Marshal(b)
	sum := sha256.Sum256(append([]byte("agentgate-domain-name-v1\n"), raw...))
	return prefix + hex.EncodeToString(sum[:])
}
func reservationFile(node, run string) string {
	sum := sha256.Sum256([]byte(node + "\n" + run))
	return "r-" + hex.EncodeToString(sum[:]) + ".json"
}
