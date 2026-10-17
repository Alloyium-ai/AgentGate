// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package platform

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

const InventoryVersion = "agentgate.target-inventory.v1"

type Attachment struct {
	Loaded   bool   `json:"loaded"`
	Attached bool   `json:"attached"`
	Error    string `json:"error,omitempty"`
}
type HelperProbe struct {
	Helper    string `json:"helper"`
	Parameter string `json:"parameter"`
	Sleepable bool   `json:"sleepable"`
	Attachment
}
type Hook struct {
	Name             string        `json:"name"`
	Family           string        `json:"family"`
	Mechanism        string        `json:"mechanism"`
	ReturnType       string        `json:"return_type"`
	Classification   string        `json:"classification"`
	Reason           string        `json:"reason"`
	Available        bool          `json:"available"`
	Attachment       Attachment    `json:"attachment"`
	Sleepable        Attachment    `json:"sleepable_attachment"`
	Helpers          []HelperProbe `json:"helpers"`
	DecisionVerified bool          `json:"decision_verified"`
	ProductQualified bool          `json:"product_qualified"`
}
type Inventory struct {
	SchemaVersion      string                  `json:"schema_version"`
	Purpose            string                  `json:"purpose"`
	Kernel             string                  `json:"kernel"`
	Architecture       string                  `json:"architecture"`
	Boot               string                  `json:"boot"`
	BTFDigest          string                  `json:"btf_digest"`
	ConfigDigest       string                  `json:"config_digest"`
	KernelConfig       map[string]string       `json:"kernel_config"`
	ProbeDigest        string                  `json:"probe_digest"`
	LSM                string                  `json:"lsm"`
	Hooks              []Hook                  `json:"hooks"`
	Seccomp            map[string]SeccompProbe `json:"seccomp"`
	AdmissionAvailable bool                    `json:"admission_available"`
}

type SeccompProbe struct {
	Available        bool   `json:"available"`
	FilterInstalled  bool   `json:"filter_installed"`
	DecisionVerified bool   `json:"decision_verified"`
	ProductQualified bool   `json:"product_qualified"`
	Error            string `json:"error,omitempty"`
}

func Family(name string) string {
	for _, group := range []struct {
		prefixes []string
		family   string
	}{
		{[]string{"bprm_", "mmap_", "file_mprotect"}, "execution-memory"},
		{[]string{"path_", "inode_", "file_", "dentry_", "d_instantiate", "kernfs_", "quota"}, "filesystem-descriptors"},
		{[]string{"socket_", "sock_", "sk_", "inet_", "sctp_", "netlink_", "tun_", "xfrm_", "secmark_", "unix_", "ib_", "mptcp_", "req_classify"}, "network-sockets"},
		{[]string{"ptrace_", "cap", "task_", "cred_", "kernel_act_as", "kernel_create_files_as", "current_"}, "processes-credentials"},
		{[]string{"ipc_", "msg_", "shm_", "sem_", "binder_"}, "ipc"},
		{[]string{"sb_", "move_mount", "fs_context_", "userns_", "bpf", "perf_", "key_", "watch_key", "post_notification", "uring_", "audit_", "kernel_", "locked_down", "lock_kernel_down", "lockdown", "syslog", "settime", "vm_", "getselfattr", "setselfattr", "getprocattr", "setprocattr", "ismaclabel", "lsmblob_", "secid_", "secctx_", "release_secctx"}, "host-kernel"},
	} {
		for _, prefix := range group.prefixes {
			if strings.HasPrefix(name, prefix) {
				return group.family
			}
		}
	}
	return "other-target-interface"
}

type HookDefinition struct {
	Name  string
	Proto *btf.FuncProto
}

// LSMDefinitions reads the target's BTF. Schema fields do not limit this inventory.
func LSMDefinitions(spec *btf.Spec) ([]HookDefinition, error) {
	var result []HookDefinition
	for typ, err := range spec.All() {
		if err != nil {
			return nil, err
		}
		fn, ok := typ.(*btf.Func)
		if !ok || !strings.HasPrefix(fn.Name, "bpf_lsm_") {
			continue
		}
		proto, ok := btf.UnderlyingType(fn.Type).(*btf.FuncProto)
		if !ok {
			return nil, fmt.Errorf("target function %s has no prototype", fn.Name)
		}
		result = append(result, HookDefinition{strings.TrimPrefix(fn.Name, "bpf_lsm_"), proto})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

// CgroupProgram identifies the relevant attach types from the target enum.
// No success here qualifies an operation decision or a product capability.
func CgroupProgram(name string) (ebpf.ProgramType, bool) {
	switch name {
	case "BPF_CGROUP_INET_INGRESS", "BPF_CGROUP_INET_EGRESS":
		return ebpf.CGroupSKB, true
	case "BPF_CGROUP_INET_SOCK_CREATE", "BPF_CGROUP_INET_SOCK_RELEASE", "BPF_CGROUP_INET4_POST_BIND", "BPF_CGROUP_INET6_POST_BIND":
		return ebpf.CGroupSock, true
	case "BPF_CGROUP_SOCK_OPS":
		return ebpf.SockOps, true
	case "BPF_CGROUP_DEVICE":
		return ebpf.CGroupDevice, true
	case "BPF_CGROUP_SYSCTL":
		return ebpf.CGroupSysctl, true
	case "BPF_CGROUP_GETSOCKOPT", "BPF_CGROUP_SETSOCKOPT":
		return ebpf.CGroupSockopt, true
	}
	if strings.HasPrefix(name, "BPF_CGROUP_INET") || strings.HasPrefix(name, "BPF_CGROUP_UDP") || strings.HasPrefix(name, "BPF_CGROUP_UNIX") {
		return ebpf.CGroupSockAddr, true
	}
	return ebpf.UnspecifiedProgram, false
}
