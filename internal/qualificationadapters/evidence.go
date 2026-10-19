// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"alloyium.local/kernel-poc/internal/execbroker"
	"alloyium.local/kernel-poc/internal/fsrules"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/netrules"
	"alloyium.local/kernel-poc/internal/openrules"
	"alloyium.local/kernel-poc/internal/processrules"
	"alloyium.local/kernel-poc/internal/qualification"
)

const candidateReceiptVersion = "agentgate.candidate-denial-receipt.v3"
const qualificationBootstrapRole = "agentgate.qualification.fixture-bootstrap.v1"
const listenerBootstrapMode = "agentgate.qualification.listener-bootstrap.v1"

type processSnapshot struct {
	PID              int                  `json:"pid"`
	StartTimeTicks   uint64               `json:"start_time_ticks,string"`
	Executable       string               `json:"executable"`
	ExecutableSHA256 string               `json:"executable_sha256"`
	Status           string               `json:"status"`
	Cgroup           string               `json:"cgroup"`
	Tasks            []string             `json:"tasks"`
	Children         string               `json:"children"`
	MonoNS           uint64               `json:"mono_ns,string"`
	Descriptors      []descriptorSnapshot `json:"descriptors,omitempty"`
}
type descriptorSnapshot struct {
	Number         string `json:"number"`
	Target         string `json:"target"`
	Device         uint64 `json:"device,string"`
	Inode          uint64 `json:"inode,string"`
	Mode, UID, GID uint32
	Links          uint64 `json:"links,string"`
}
type custodyState struct{ Generation, ExpiresNS uint64 }
type mapSnapshot struct {
	Files          fsrules.State        `json:"files"`
	Nodes          []openrules.Entry    `json:"nodes"`
	Peers          netrules.Policy      `json:"peers"`
	Sockets        netrules.SocketPlan  `json:"sockets"`
	Custody        custodyState         `json:"custody"`
	Process        processrules.State   `json:"process"`
	Owned          map[string]uint32    `json:"owned"`
	SharedMaps     map[string][2]uint32 `json:"shared_maps"`
	ReadbackSHA256 string               `json:"readback_sha256"`
}
type scalarRecord struct {
	ID       uint32 `json:"id"`
	Error    uint32 `json:"errno"`
	Result   int64  `json:"result"`
	PID      uint32 `json:"pid"`
	Reserved uint32 `json:"reserved"`
}
type listenerReceipt struct {
	Data           []byte `json:"data"`
	Control        []byte `json:"control"`
	Flags          int    `json:"flags"`
	FD             int    `json:"fd"`
	FDFlags        int    `json:"fd_flags"`
	FDTarget       string `json:"fd_target"`
	IDValidErrno   int    `json:"id_valid_errno"`
	ReceivedMonoNS uint64 `json:"received_mono_ns,string"`
}
type brokerReceipt struct {
	Config                     execbroker.Config `json:"config"`
	Process                    processSnapshot   `json:"process"`
	Audit                      []byte            `json:"audit"`
	Diagnostic                 []byte            `json:"diagnostic"`
	ParentListenerClosedErrno  int               `json:"parent_listener_closed_errno"`
	ParentListenerClosedMonoNS uint64            `json:"parent_listener_closed_mono_ns,string"`
	StoppedMonoNS              uint64            `json:"stopped_mono_ns,string"`
	ProcessGoneErrno           int               `json:"process_gone_errno"`
	ExitStatus                 uint32            `json:"exit_status"`
}
type expiryReceipt struct {
	Held          processSnapshot `json:"held"`
	Maps          mapSnapshot     `json:"maps"`
	MapsMonoNS    uint64          `json:"maps_mono_ns,string"`
	ResumedMonoNS uint64          `json:"resumed_mono_ns,string"`
}
type candidateReceipt struct {
	Protocol             string                     `json:"protocol"`
	Binding              qualification.Binding      `json:"binding"`
	BootstrapRole        string                     `json:"bootstrap_role"`
	BootstrapMode        string                     `json:"bootstrap_mode,omitempty"`
	ManagerPID           int                        `json:"manager_pid,omitempty"`
	BootstrapReady       processSnapshot            `json:"bootstrap_ready"`
	ExecutedPolicyDigest string                     `json:"executed_policy_digest"`
	Artifacts            map[string]string          `json:"artifacts"`
	Hooks                map[string][]string        `json:"hooks"`
	Domain               string                     `json:"domain"`
	DomainID             uint64                     `json:"domain_id,string"`
	Generation           uint64                     `json:"generation,string"`
	DeadlineNS           uint64                     `json:"deadline_ns,string"`
	PlanSHA256           string                     `json:"plan_sha256"`
	FilterSHA256         string                     `json:"filter_sha256"`
	Network              candidateNetworkReceipt    `json:"network"`
	SetupFilterSHA256    string                     `json:"setup_filter_sha256,omitempty"`
	FinalFilterSHA256    string                     `json:"final_filter_sha256,omitempty"`
	Listener             listenerReceipt            `json:"listener"`
	Broker               brokerReceipt              `json:"broker"`
	Expiry               *expiryReceipt             `json:"expiry,omitempty"`
	HeldBefore           processSnapshot            `json:"held_before"`
	HeldPlaced           processSnapshot            `json:"held_placed"`
	HeldInstalled        processSnapshot            `json:"held_installed"`
	Active               processSnapshot            `json:"active"`
	FinalActive          processSnapshot            `json:"final_active"`
	ActiveMembers        string                     `json:"active_members"`
	FinalMembers         string                     `json:"final_members"`
	Before               mapSnapshot                `json:"before"`
	After                mapSnapshot                `json:"after"`
	Records              []scalarRecord             `json:"records"`
	RawRecords           []byte                     `json:"raw_records"`
	Streams              map[string][][]byte        `json:"streams"`
	Counters             map[string]kernel.Counters `json:"counters"`
	ExitStatus           uint32                     `json:"exit_status"`
	EmptyReadback        string                     `json:"empty_readback"`
	DomainRemovalErrno   int                        `json:"domain_removal_errno"`
	PinRemovalErrno      map[string]int             `json:"pin_removal_errno"`
}

func digestJSON(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func digestBytes(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
