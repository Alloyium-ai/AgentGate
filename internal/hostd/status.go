// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"path/filepath"
	"strconv"
	"strings"
)

// LoadConfig reads the protected configuration of a state directory.
func LoadConfig(stateDir string) (Config, error) {
	if err := checkPrivateDir(stateDir); err != nil {
		return Config{}, err
	}
	return loadConfig(stateDir)
}

// ProvisionCommand is the existing appliance bring-up: appliance.py start.
func ProvisionCommand(source, state, policy, tokenFile string, port int) []string {
	argv := []string{"/usr/bin/python3", "-I", filepath.Join(source, "poc/ssh-diagnostic/appliance.py"), "start", "--state", state}
	if policy != "" {
		argv = append(argv, "--policy", policy)
	}
	if tokenFile != "" {
		argv = append(argv, "--token-file", tokenFile)
	}
	if port != 0 {
		argv = append(argv, "--port", strconv.Itoa(port))
	}
	return argv
}

// ReportsReady is true when the bring-up printed its readiness line.
func ReportsReady(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "ready=true" {
			return true
		}
	}
	return false
}

// StatusReport is the local, secret-free view of the host agent.
type StatusReport struct {
	Enrolled   bool   `json:"enrolled"`
	ServiceURL string `json:"service_url,omitempty"`
	TargetID   string `json:"target_id,omitempty"`
	TargetName string `json:"target_name,omitempty"`
	// HostKeyID is the id an administrator approves; HostKeyFingerprint the
	// SHA-256 fingerprint sealing clients pin. Approve says how.
	HostKeyID          string   `json:"host_key_id,omitempty"`
	HostKeyFingerprint string   `json:"host_key_fingerprint,omitempty"`
	Approve            []string `json:"approve,omitempty"`
	Runtime            string   `json:"runtime,omitempty"`
	Sequence           uint64   `json:"sequence"`
	Unfinished         []string `json:"unfinished_jobs"`
	OutboxBytes        int64    `json:"outbox_bytes"`
	OutboxJobs         []string `json:"outbox_pending_jobs"`
	// MountRoots are the host folders this host's operator allows launches
	// to mount (MountRootsFile); MountRootsError says why none apply when
	// the file is unsafe or invalid.
	MountRootsFile  string   `json:"mount_roots_file"`
	MountRoots      []string `json:"mount_roots"`
	MountRootsError string   `json:"mount_roots_error,omitempty"`
	// Broker is the configured credential broker (nil: brokered secrets are
	// off on this host) and SecretRoot the secret store.
	Broker     *BrokerConfig `json:"broker"`
	SecretRoot string        `json:"secret_root"`
}

// Status reads the state directory without changing it.
func Status(stateDir string) (StatusReport, error) {
	return StatusWith(stateDir, DefaultMountRootsFile)
}

// StatusWith is Status with the mount roots file at rootsFile.
func StatusWith(stateDir, rootsFile string) (StatusReport, error) {
	report := StatusReport{Unfinished: []string{}, OutboxJobs: []string{}, MountRoots: []string{}, MountRootsFile: rootsFile}
	cfg, err := LoadConfig(stateDir)
	if err != nil {
		return report, err
	}
	report.Runtime, report.ServiceURL = cfg.Runtime, cfg.ServiceURL
	report.Broker, report.SecretRoot = cfg.Broker, cfg.secretRoot()
	if roots, rootsErr := LoadMountRoots(rootsFile, []string{stateDir, cfg.secretRoot()}); rootsErr != nil {
		report.MountRootsError = rootsErr.Error()
	} else {
		report.MountRoots = roots
	}
	if id, idErr := loadIdentity(stateDir); idErr == nil {
		report.Enrolled, report.TargetID, report.TargetName = true, id.TargetID, id.TargetName
		if key, keyErr := readHostKey(stateDir); keyErr == nil && key.ID == id.HostKeyID {
			report.HostKeyID, report.HostKeyFingerprint, report.Approve = key.ID, key.Fingerprint, ApprovalLines(id, key)
		}
	}
	report.Sequence, _ = newSequence(stateDir).current()
	if ledger, ledgerErr := openLedger(stateDir, nil); ledgerErr == nil {
		if entries, listErr := ledger.Unfinished(); listErr == nil {
			for _, entry := range entries {
				report.Unfinished = append(report.Unfinished, entry.JobID+" "+entry.Type+" "+entry.State)
			}
		}
	}
	if outbox, outboxErr := openOutbox(stateDir); outboxErr == nil {
		report.OutboxBytes = outbox.Bytes()
		report.OutboxJobs = append(report.OutboxJobs, outbox.Pending()...)
	}
	return report, nil
}
