// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualification

import (
	"alloyium.local/kernel-poc/internal/policy"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

type definition struct{ mechanisms, artifacts, cases []string }

// These are behavior obligations, not claims derived from hook availability.
// Empty permission sets still require the deny/lifetime/descendant obligations.
var catalog = map[string]definition{
	"policy.default-deny.v2":          {[]string{"composite-kernel-and-seccomp"}, []string{"files", "peers", "sockets", "custody", "process", "syscalls", "held-helper", "node"}, []string{"unmatched-operation-denied", "missing-managed-policy-denied", "unsupported-control-rejects-admission", "descendant-inherits-denial", "expired-grant-denied"}},
	"fs.rules.v1":                     {[]string{"bpf-lsm-file-custody"}, []string{"files"}, []string{"exact-path-match", "unmatched-path-denied", "missing-policy-denied", "expired-policy-denied", "descendant-denied", "replacement-generation-denied"}},
	"fs.read.v1":                      {[]string{"bpf-lsm-file-open-and-use"}, []string{"files"}, []string{"read-unmatched-denied", "inherited-fd-read-denied", "expired-fd-read-denied", "descendant-read-denied"}},
	"fs.write.v1":                     {[]string{"bpf-lsm-file-open-and-use"}, []string{"files"}, []string{"write-unmatched-denied", "inherited-fd-write-denied", "expired-fd-write-denied", "descendant-write-denied"}},
	"fs.mmap.v1":                      {[]string{"bpf-lsm-mmap-file"}, []string{"files"}, []string{"unmatched-map-denied", "expired-map-denied", "descendant-map-denied"}},
	"fs.map-execute.v1":               {[]string{"bpf-lsm-mmap-file"}, []string{"files"}, []string{"execute-map-unmatched-denied", "execute-map-expired-denied", "writable-execute-map-denied", "descendant-execute-map-denied"}},
	"fs.mprotect.v1":                  {[]string{"bpf-lsm-file-mprotect"}, []string{"files"}, []string{"unmatched-protection-denied", "expired-protection-denied", "writable-execute-protection-denied", "descendant-protection-denied"}},
	"fs.resource-use.v1":              {[]string{"bpf-lsm-file-cookie-use-and-receive"}, []string{"files", "custody"}, []string{"foreign-fd-denied", "received-fd-denied", "same-pointer-new-cookie-denied", "old-generation-denied", "missing-policy-use-denied", "expired-use-denied"}},
	"exec.rules.v1":                   {[]string{"seccomp-exec-broker-and-bpf-lsm-bprm"}, []string{"files", "held-helper", "exec-broker"}, []string{"unmatched-exec-denied", "broker-path-identity-readback", "interpreter-substitution-denied", "expired-exec-denied", "descendant-exec-denied", "broker-loss-stops-domain"}},
	"identity.job.v1":                 {[]string{"signed-full-job-binding"}, []string{"node", "authority"}, []string{"valid-binding-accepted", "wrong-job-denied", "wrong-policy-denied", "wrong-node-denied", "wrong-boot-denied", "generation-replay-denied", "unknown-revocation-denied"}},
	"identity.local-enrollment.v1":    {[]string{"private-uds-peercred-and-request-proof"}, []string{"node", "authority"}, []string{"enrolled-proof-accepted", "unenrolled-subject-denied", "wrong-peer-uid-denied", "proof-replay-denied", "body-substitution-denied", "key-role-reuse-denied"}},
	"process.job-domain.v1":           {[]string{"root-cgroup-v2-and-held-launch"}, []string{"node", "held-helper", "watchdog"}, []string{"held-helper-before-placement", "placement-pid-starttime-readback", "child-in-same-root", "grandchild-in-same-root", "foreign-domain-isolated", "untrusted-parent-placement-denied"}},
	"lifecycle.baseline.v1":           {[]string{"durable-manager-and-independent-watchdog"}, []string{"node", "watchdog"}, []string{"prepare-quarantines", "install-readback-before-release", "lost-prepare-reply-expires", "grant-wall-and-mono-cutoff", "revoked-grant-stops", "node-loss-stops-descendants", "watchdog-loss-stops-descendants", "restart-reconciles-orphans", "incomplete-recovery-terminal"}},
	"lifecycle.terminate.v1":          {[]string{"cgroup-v2-kill-empty-rights-cleanup"}, []string{"node", "watchdog"}, []string{"whole-domain-stop", "child-and-grandchild-terminated", "empty-before-rights-removal", "counter-availability-preserved", "repeat-stop-idempotent", "old-boot-never-kills-reused-id"}},
	"net.rules.v1":                    {[]string{"cgroup-peer-egress-ingress-and-socket-custody"}, []string{"peers", "sockets", "custody"}, []string{"unmatched-ipv4-denied", "unmatched-ipv6-denied", "inherited-foreign-socket-denied", "alternate-udp-destination-denied", "missing-peer-map-denied", "expired-peer-map-denied", "descendant-network-denied"}},
	"net.dns-ttl.v1":                  {[]string{"trusted-dns-leases-and-kernel-expiry"}, []string{"peers", "sockets", "node"}, []string{"direct-agent-resolver-denied", "unresolved-hostname-denied", "ttl-before-refresh-denied", "failed-refresh-full-deny", "expired-write-zero-bytes", "retired-udp-read-zero-bytes", "lease-revision-readback", "cross-job-snapshot-denied"}},
	"socket.rules.v1":                 {[]string{"bpf-lsm-socket-operations-and-packet-gates"}, []string{"sockets", "peers", "custody"}, []string{"every-ungranted-operation-denied", "foreign-socket-read-write-denied", "splice-read-write-denied", "missing-operation-map-denied", "expired-operation-map-denied", "packet-ingress-denied", "packet-egress-denied", "descendant-socket-denied"}},
	"runtime.profile.v1":              {[]string{"measured-held-child-and-staged-runtime"}, []string{"node", "held-helper", "exec-broker"}, []string{"exact-runtime-artifact-readback", "runtime-file-closure-readback", "substituted-runtime-denied", "loader-environment-denied", "no-implicit-startup-rights"}},
	"runtime.managed-unprivileged.v1": {[]string{"uid-gid-capability-nnp-seccomp-baseline"}, []string{"held-helper", "files"}, []string{"uid-gid-groups-readback", "capabilities-empty-readback", "no-new-privileges-readback", "setid-execution-denied", "privilege-escalation-denied", "unmanaged-control-preserved"}},
	"runtime.measured-bootstrap.v1":   {[]string{"pinned-held-helper-barrier-and-exec-listener"}, []string{"node", "held-helper", "exec-broker"}, []string{"exact-helper-digest", "held-pid-starttime-barrier", "no-agent-before-release", "bootstrap-role-permission-denied", "listener-custody-readback", "failed-place-kills-helper", "held-deadline-stops"}},
	"runtime.explicit-memory.v1":      {[]string{"bpf-lsm-memory-and-live-heap-broker"}, []string{"files", "held-helper", "exec-broker"}, []string{"ungranted-anonymous-map-denied", "ungranted-heap-denied", "anonymous-execute-denied", "writable-execute-denied", "expired-allocation-denied", "descendant-memory-denied"}},
	"runtime.explicit-pipes.v1":       {[]string{"scalar-seccomp-and-file-custody"}, []string{"held-helper", "files"}, []string{"ungranted-pipe-create-denied", "ungranted-pipe2-create-denied", "foreign-pipe-read-denied", "foreign-pipe-write-denied", "pipe-transfer-denied"}},
	"runtime.explicit-eventfds.v1":    {[]string{"bpf-lsm-anonymous-file-cookie-and-seccomp"}, []string{"files", "anonymous", "held-helper"}, []string{"legacy-eventfd-denied", "ungranted-eventfd2-denied", "ungranted-eventfd-use-denied", "foreign-eventfd-denied", "anonymous-receive-denied", "cookie-reuse-denied", "expired-eventfd-denied", "missing-policy-allocation-denied", "descendant-eventfd-denied"}},
	"runtime.explicit-signals.v1":     {[]string{"bpf-lsm-task-kill-and-ptrace"}, []string{"process"}, []string{"ungranted-kill-denied", "ungranted-tkill-denied", "ungranted-tgkill-denied", "foreign-job-signal-denied", "unmanaged-target-signal-denied", "ptrace-attach-denied", "ptrace-traceme-denied", "expired-signal-denied"}},
	"runtime.explicit-syscalls.v2":    {[]string{"amd64-scalar-seccomp-default-deny"}, []string{"held-helper"}, []string{"unknown-syscall-denied", "ungranted-known-syscall-denied", "x32-and-wrong-architecture-denied", "clone3-pointer-flags-denied", "fork-inherits-filter", "grandchild-inherits-filter", "seccomp-listener-loss-denied"}},
	"audit.batch.v1":                  {[]string{"raw-kernel-streams-and-signed-durable-audit"}, []string{"files", "peers", "sockets", "custody", "process", "syscalls", "node", "authority"}, []string{"seven-required-streams", "exact-raw-decisions-and-origins", "contiguous-counter-readback", "zero-loss-complete", "forced-loss-stops-and-incomplete", "missing-stream-incomplete", "node-authority-signatures-distinct", "offline-signature-and-binding-check", "expiry-cutoff-proof-before-activity", "runtime-files-proof-before-activity"}},
}

// Contracts derives every obligation for the exact document. Unknown contracts
// fail closed instead of borrowing another capability's evidence.
func Contracts(document policy.Document) ([]Contract, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	if err := document.CheckDeclaredRequirements(); err != nil {
		return nil, err
	}
	if document.Profile != policy.KernelProfile {
		return nil, errors.New("qualification requires a complete kernel policy")
	}
	ids, err := policy.Requirements(document)
	if err != nil {
		return nil, err
	}
	result := make([]Contract, 0, len(ids))
	for _, id := range ids {
		d, ok := catalog[id]
		if !ok {
			return nil, fmt.Errorf("qualification contract unavailable: %s", id)
		}
		c := Contract{id, ContractVersion, append([]string{}, d.cases...), append([]string{}, d.mechanisms...), append([]string{}, d.artifacts...)}
		c.Cases = append(c.Cases, positiveCases(document, id)...)
		sort.Strings(c.Cases)
		sort.Strings(c.ArtifactNames)
		sort.Strings(c.Mechanisms)
		result = append(result, c)
	}
	return result, nil
}

func positiveCases(d policy.Document, capability string) []string {
	var values []any
	if d.Files != nil {
		op := map[string]string{"fs.read.v1": "read", "fs.write.v1": "write", "fs.mmap.v1": "mmap", "fs.map-execute.v1": "map_execute", "fs.mprotect.v1": "mprotect"}[capability]
		for _, rule := range d.Files.Rules {
			if rule.Effect == "allow" {
				for _, operation := range rule.Operations {
					if operation == op {
						values = append(values, rule)
					}
				}
			}
		}
	}
	if d.Programs != nil && capability == "exec.rules.v1" {
		for _, r := range d.Programs.Rules {
			if r.Effect == "allow" {
				values = append(values, r)
			}
		}
	}
	if d.Network != nil && capability == "net.rules.v1" {
		for _, r := range d.Network.Rules {
			if r.Effect == "allow" {
				values = append(values, r)
			}
		}
	}
	if d.Sockets != nil && capability == "socket.rules.v1" {
		for _, r := range d.Sockets.Rules {
			if r.Effect == "allow" {
				values = append(values, r)
			}
		}
	}
	if d.Runtime != nil {
		if capability == "runtime.explicit-syscalls.v2" {
			for _, n := range d.Runtime.Seccomp.AllowSyscalls {
				values = append(values, n)
			}
		}
		if capability == "runtime.explicit-signals.v1" && d.Runtime.Signals != nil {
			for _, n := range *d.Runtime.Signals {
				values = append(values, n)
			}
		}
		if capability == "runtime.measured-bootstrap.v1" && d.Runtime.Bootstrap != nil {
			for _, n := range d.Runtime.Bootstrap.Operations {
				values = append(values, n)
			}
		}
		if capability == "runtime.explicit-memory.v1" && d.Runtime.Memory != nil {
			for _, n := range d.Runtime.Memory.Anonymous {
				values = append(values, n)
			}
			if d.Runtime.Memory.Heap == "allow" {
				values = append(values, "heap")
			}
		}
		if d.Runtime.IPC != nil {
			if capability == "runtime.explicit-pipes.v1" {
				for _, n := range d.Runtime.IPC.Pipes {
					values = append(values, n)
				}
			}
			if capability == "runtime.explicit-eventfds.v1" && d.Runtime.IPC.EventFDs != nil {
				for _, n := range *d.Runtime.IPC.EventFDs {
					values = append(values, n)
				}
			}
		}
	}
	result := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		raw, _ := json.Marshal(value)
		sum := sha256.Sum256(raw)
		id := "explicit-allow:" + hex.EncodeToString(sum[:])
		if !seen[id] {
			result = append(result, id)
			seen[id] = true
		}
	}
	return result
}
