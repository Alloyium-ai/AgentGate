// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package execbroker resumes explicit exec and heap calls under a live binding.
// It makes no pathname or approval decision from mutable agent memory.
package execbroker

import (
	"alloyium.local/kernel-poc/internal/fsrules"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/unix"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Protocol      string        `json:"protocol"`
	Domain        string        `json:"domain"`
	DomainID      uint64        `json:"domain_id,string"`
	Generation    uint64        `json:"generation,string"`
	DeadlineNS    uint64        `json:"deadline_ns,string"`
	BootID        string        `json:"boot_id"`
	PolicyDigest  string        `json:"policy_digest"`
	ExecLink      string        `json:"exec_link"`
	ExecProgramID uint32        `json:"exec_program_id"`
	Files         fsrules.State `json:"file_state"`
}
type Data struct {
	Number       int32
	Architecture uint32
	IP           uint64
	Arguments    [6]uint64
}
type Notification struct {
	ID         uint64
	PID, Flags uint32
	Data       Data
}
type Response struct {
	ID    uint64
	Value int64
	Error int32
	Flags uint32
}
type Decision struct {
	Protocol                                        string `json:"protocol"`
	Domain, Generation, NotificationID, MonotonicNS uint64
	PID                                             uint32
	Syscall                                         int32
	Continued                                       bool
	Reason                                          string
}

func (c Config) Validate() error {
	digest, err := hex.DecodeString(c.PolicyDigest)
	if c.Protocol != "agentgate.exec-broker.v1" || err != nil || len(digest) != 32 || c.PolicyDigest != strings.ToLower(c.PolicyDigest) || c.BootID == "" || c.DomainID == 0 || c.Generation == 0 || c.DeadlineNS == 0 || c.ExecProgramID == 0 {
		return errors.New("the exec broker requires an exact boot and policy binding")
	}
	if filepath.Clean(c.Domain) != c.Domain || filepath.Dir(c.Domain) != "/sys/fs/cgroup" || !strings.HasPrefix(filepath.Base(c.Domain), "alloyium-poc-") {
		return errors.New("the exec broker requires an owned root job domain")
	}
	pins := filepath.Join("/sys/fs/bpf", filepath.Base(c.Domain)+"-files")
	suffix := strings.TrimPrefix(filepath.Base(c.ExecLink), "link-")
	index, indexErr := strconv.Atoi(suffix)
	if filepath.Dir(c.ExecLink) != pins || !strings.HasPrefix(filepath.Base(c.ExecLink), "link-") || indexErr != nil || index < 0 || index > 127 || strconv.Itoa(index) != suffix {
		return errors.New("the exec broker requires its exact pinned file hook")
	}
	if c.Files.Generation != c.Generation || c.Files.ExpiresNS != c.DeadlineNS {
		return errors.New("the file state differs from the exec broker binding")
	}
	return nil
}

// Check refuses every notification outside the live explicit resource contract.
// A successful result permits the kernel to continue into its resource hooks.
func Check(c Config, n Notification, now uint64, member func(int) error, installed func() error) string {
	if n.ID == 0 || n.PID <= 1 || n.Flags != 0 || n.Data.Architecture != unix.AUDIT_ARCH_X86_64 || (n.Data.Number != unix.SYS_EXECVE && n.Data.Number != unix.SYS_EXECVEAT && n.Data.Number != unix.SYS_BRK) {
		return "unexpected-notification"
	}
	if now == 0 || now >= c.DeadlineNS {
		return "expired-binding"
	}
	if member == nil || member(int(n.PID)) != nil {
		return "domain-membership-differs"
	}
	if installed == nil || installed() != nil {
		return "installed-policy-differs"
	}
	if n.Data.Number == unix.SYS_BRK {
		if c.Files.Memory&32 == 0 {
			return "heap-permission-absent"
		}
		return "continue-live-heap"
	}
	return "continue-to-file-hooks"
}

func continues(reason string) bool {
	return reason == "continue-to-file-hooks" || reason == "continue-live-heap"
}
