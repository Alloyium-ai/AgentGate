// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package fsrules

import (
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/netrules"
	"errors"
)

// EnableSocketDelegation requires the complete live socket guard on the same domain.
// It permits no socket operation by itself. Every operation still crosses its guard.
func EnableSocketDelegation(plan Plan, peer, socket, custody *kernel.Runtime) (Plan, error) {
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
	plan.digest = planDigest(plan)
	return plan, nil
}
