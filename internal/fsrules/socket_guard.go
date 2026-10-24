// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package fsrules

import (
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/netrules"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// SocketMode states which kernel component decides socket I/O for a plan. The
// file component sees a socket only when its descriptor is read or written
// through the VFS (read(2), write(2) and their vector forms reach
// file_permission). send(2), recv(2), connect, bind, listen and every other
// socket call never cross this component.
type SocketMode string

const (
	// SocketsDenied is the default: the file component refuses VFS reads and
	// writes on socket descriptors. It does not see any other socket call.
	SocketsDenied SocketMode = "denied"
	// SocketsLSMGuard means the complete socket LSM guard (the peer, socket and
	// custody objects) is live on the domain and decides every socket
	// operation. Only EnableSocketDelegation selects it.
	SocketsLSMGuard SocketMode = "socket-lsm-guard"
	// SocketsCgroupNetworkOnly means no socket LSM guard is attached. The file
	// component lets VFS socket reads and writes through, and the only kernel
	// control over sockets is the six cgroup network hooks: IPv4 and IPv6
	// connect, UDP sendmsg, and IP packet egress and ingress, bounded by
	// address. Socket family and type, bind, listen and accept, and AF_UNIX and
	// AF_NETLINK I/O are not controlled. Only WithCgroupNetworkGuardOnly
	// selects it, and only with live evidence of those six hooks.
	SocketsCgroupNetworkOnly SocketMode = "cgroup-network-guard-only"
)

// SocketMode reports how the plan's socket I/O is decided.
func (plan Plan) SocketMode() SocketMode {
	if plan.sockets == "" {
		return SocketsDenied
	}
	return plan.sockets
}

// SocketLSMGuard reports whether a socket LSM guard decides socket operations.
func (plan Plan) SocketLSMGuard() bool { return plan.sockets == SocketsLSMGuard }

// EnableSocketDelegation requires the complete live socket guard on the same domain.
// It permits no socket operation by itself. Every operation still crosses its guard.
func EnableSocketDelegation(plan Plan, peer, socket, custody *kernel.Runtime) (Plan, error) {
	if plan.sockets == SocketsCgroupNetworkOnly {
		return Plan{}, errors.New("socket delegation conflicts with the cgroup-only socket mode")
	}
	for _, r := range []*kernel.Runtime{peer, socket, custody} {
		if r == nil || r.ID != plan.domain || r.Collection == nil || r.Domain == "" {
			return Plan{}, errors.New("socket delegation domain differs")
		}
	}
	require := func(r *kernel.Runtime, names ...string) bool {
		set := map[string]bool{}
		for _, n := range r.Hooks() {
			set[n] = true
		}
		for _, n := range names {
			if !set[n] {
				return false
			}
		}
		return true
	}
	if !require(peer, "net_connect4", "net_connect6", "net_sendmsg4", "net_sendmsg6", "net_egress", "net_ingress") || !require(socket, "operation_create", "operation_post_create", "operation_bind", "operation_listen", "operation_accept", "operation_send", "operation_receive", "operation_local_name", "operation_peer_name", "operation_shutdown", "operation_set_option", "operation_get_option", "operation_file_permission", "operation_ingress", "operation_egress") || !require(custody, "custody_sendmsg", "custody_recvmsg") {
		return Plan{}, errors.New("socket delegation lacks mandatory kernel hooks")
	}
	var peerState netrules.Policy
	var socketState netrules.SocketPlan
	var custodyState struct{ Generation, ExpiresNS uint64 }
	for _, v := range []struct {
		runtime *kernel.Runtime
		name    string
		value   any
	}{{peer, "net_policies", &peerState}, {socket, "sock_policies", &socketState}, {custody, "cust_bindings", &custodyState}} {
		m := v.runtime.Collection.Maps[v.name]
		if m == nil {
			return Plan{}, errors.New("socket delegation lacks a policy map")
		}
		if err := m.Lookup(plan.domain, v.value); err != nil {
			return Plan{}, err
		}
	}
	if peerState.Generation != plan.state.Generation || socketState.Generation != plan.state.Generation || custodyState.Generation != plan.state.Generation || peerState.ExpiresNS != plan.state.ExpiresNS || socketState.ExpiresNS != plan.state.ExpiresNS || custodyState.ExpiresNS != plan.state.ExpiresNS {
		return Plan{}, errors.New("socket delegation generation or deadline differs")
	}
	plan.state.SocketGeneration = plan.state.Generation
	plan.sockets = SocketsLSMGuard
	plan.digest = planDigest(plan)
	return plan, nil
}

// CgroupNetworkHook is one cgroup hook of the SSH POC network guard
// (bpf/network_policy.bpf.c, attached by cmd/pilot-network-diagnostic).
type CgroupNetworkHook struct {
	Program string
	Attach  ebpf.AttachType
	Type    ebpf.ProgramType
}

// CgroupNetworkHooks lists the six hooks that must be attached directly to the
// domain before the cgroup-only socket mode may be selected.
func CgroupNetworkHooks() []CgroupNetworkHook {
	return []CgroupNetworkHook{
		{"net_connect4", ebpf.AttachCGroupInet4Connect, ebpf.CGroupSockAddr},
		{"net_connect6", ebpf.AttachCGroupInet6Connect, ebpf.CGroupSockAddr},
		{"net_sendmsg4", ebpf.AttachCGroupUDP4Sendmsg, ebpf.CGroupSockAddr},
		{"net_sendmsg6", ebpf.AttachCGroupUDP6Sendmsg, ebpf.CGroupSockAddr},
		{"net_egress", ebpf.AttachCGroupInetEgress, ebpf.CGroupSKB},
		{"net_ingress", ebpf.AttachCGroupInetIngress, ebpf.CGroupSKB},
	}
}

// CgroupProgram is one program the kernel reports as attached to a cgroup.
type CgroupProgram struct {
	Attach ebpf.AttachType
	ID     ebpf.ProgramID
	Name   string
	Type   ebpf.ProgramType
}

// CgroupNetworkGuard is evidence that every CgroupNetworkHooks entry is attached
// directly to one domain. Its zero value is no evidence. Only
// NewCgroupNetworkGuard and ObserveCgroupNetworkGuard make one.
type CgroupNetworkGuard struct {
	domain   uint64
	programs []CgroupProgram
}

// Domain is the cgroup ID the evidence was taken for.
func (g CgroupNetworkGuard) Domain() uint64 { return g.domain }

// Programs are the matched programs, one per hook, in CgroupNetworkHooks order.
func (g CgroupNetworkGuard) Programs() []CgroupProgram {
	return append([]CgroupProgram{}, g.programs...)
}

// NewCgroupNetworkGuard checks observed attachments against CgroupNetworkHooks.
// Every hook needs one attached program with its name and program type. Other
// programs on the same hook are ignored: cgroup programs of these types all run,
// and any one of them refusing refuses the operation, so they cannot widen it.
// Production code uses ObserveCgroupNetworkGuard, which reads the attachments
// from the kernel; this constructor keeps that decision testable without one.
func NewCgroupNetworkGuard(domain uint64, attached []CgroupProgram) (CgroupNetworkGuard, error) {
	if domain == 0 {
		return CgroupNetworkGuard{}, errors.New("cgroup network evidence has no domain")
	}
	guard := CgroupNetworkGuard{domain: domain}
	for _, hook := range CgroupNetworkHooks() {
		found := false
		for _, program := range attached {
			if program.Attach == hook.Attach && program.Name == hook.Program && program.Type == hook.Type && program.ID != 0 {
				guard.programs = append(guard.programs, program)
				found = true
				break
			}
		}
		if !found {
			return CgroupNetworkGuard{}, fmt.Errorf("the cgroup network hook %s (%s) is not attached to domain %d", hook.Program, hook.Attach, domain)
		}
	}
	return guard, nil
}

// cgroup2Magic is CGROUP2_SUPER_MAGIC.
const cgroup2Magic = 0x63677270

// ObserveCgroupNetworkGuard asks the kernel which programs are attached directly
// to the cgroup v2 directory and returns evidence only if it is the domain (its
// inode number is the cgroup ID) and every CgroupNetworkHooks entry is present.
func ObserveCgroupNetworkGuard(cgroup string, domain uint64) (CgroupNetworkGuard, error) {
	dir, err := os.Open(cgroup)
	if err != nil {
		return CgroupNetworkGuard{}, err
	}
	defer dir.Close()
	var fs syscall.Statfs_t
	var st syscall.Stat_t
	if err = syscall.Fstatfs(int(dir.Fd()), &fs); err != nil {
		return CgroupNetworkGuard{}, err
	}
	if err = syscall.Fstat(int(dir.Fd()), &st); err != nil {
		return CgroupNetworkGuard{}, err
	}
	if fs.Type != cgroup2Magic || st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Ino != domain {
		return CgroupNetworkGuard{}, errors.New("the cgroup network evidence is not for this cgroup v2 domain")
	}
	attached := []CgroupProgram{}
	for _, hook := range CgroupNetworkHooks() {
		result, queryErr := link.QueryPrograms(link.QueryOptions{Target: int(dir.Fd()), Attach: hook.Attach})
		if queryErr != nil {
			return CgroupNetworkGuard{}, fmt.Errorf("query cgroup hook %s: %w", hook.Attach, queryErr)
		}
		for _, item := range result.Programs {
			program, openErr := ebpf.NewProgramFromID(item.ID)
			if openErr != nil {
				return CgroupNetworkGuard{}, fmt.Errorf("open attached program %d: %w", item.ID, openErr)
			}
			info, infoErr := program.Info()
			_ = program.Close()
			if infoErr != nil {
				return CgroupNetworkGuard{}, fmt.Errorf("inspect attached program %d: %w", item.ID, infoErr)
			}
			attached = append(attached, CgroupProgram{Attach: hook.Attach, ID: item.ID, Name: info.Name, Type: info.Type})
		}
	}
	return NewCgroupNetworkGuard(domain, attached)
}

// WithCgroupNetworkGuardOnly selects SocketsCgroupNetworkOnly: the file
// component stops refusing VFS socket reads and writes, and no socket LSM guard
// takes its place. It permits no pathname right. It requires evidence that the
// six cgroup network hooks are attached to this plan's domain, and the
// installer observes them again on the live domain before it writes the plan.
func (plan Plan) WithCgroupNetworkGuardOnly(guard CgroupNetworkGuard) (Plan, error) {
	if plan.sockets == SocketsLSMGuard {
		return Plan{}, errors.New("the cgroup-only socket mode conflicts with socket LSM delegation")
	}
	if guard.domain == 0 || guard.domain != plan.domain {
		return Plan{}, errors.New("the cgroup network evidence is for another domain")
	}
	if _, err := NewCgroupNetworkGuard(guard.domain, guard.programs); err != nil {
		return Plan{}, err
	}
	plan.state.SocketGeneration = plan.state.Generation
	plan.sockets = SocketsCgroupNetworkOnly
	plan.digest = planDigest(plan)
	return plan, nil
}

// checkSocketMode refuses a socket mark that differs from the plan's mode.
func checkSocketMode(plan Plan) error {
	switch plan.sockets {
	case "", SocketsDenied:
		if plan.state.SocketGeneration != 0 {
			return errors.New("socket I/O is marked delegated without a socket mode")
		}
	case SocketsLSMGuard, SocketsCgroupNetworkOnly:
		if plan.state.SocketGeneration != plan.state.Generation {
			return errors.New("the socket mode differs from the plan generation")
		}
	default:
		return fmt.Errorf("unknown socket mode %q", plan.sockets)
	}
	return nil
}
