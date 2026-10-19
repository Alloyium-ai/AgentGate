// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package netrules

const MaxSocketOptions = 16

const (
	SocketCreate = uint32(1 << iota)
	SocketBind
	SocketListen
	SocketAccept
	SocketSend
	SocketReceive
	SocketGetLocalName
	SocketGetPeerName
	SocketShutdown
	SocketSetOption
	SocketGetOption
)

// SocketOptionPlan contains scalar authorization only. Values remain opaque.
type SocketOptionPlan struct{ Level, Name uint16 }

// SocketRulePlan is the fixed native-endian socket operation map ABI.
type SocketRulePlan struct {
	Address     [16]byte
	Options     [MaxSocketOptions]SocketOptionPlan
	Operations  uint32
	Index       uint32
	Family      uint16
	Protocol    uint16
	PortFrom    uint16
	PortTo      uint16
	Effect      uint8
	HasLocal    uint8
	OptionCount uint16
}

type SocketPlan struct {
	Generation uint64
	ExpiresNS  uint64
	Count      uint32
	Reserved   uint32
	Rules      [MaxRules]SocketRulePlan
}

type CompiledSockets struct {
	Plan    SocketPlan
	RuleIDs []string
}

type SocketOperation struct {
	Family       uint16
	Protocol     uint16
	Operation    uint32
	LocalAddress [16]byte
	LocalPort    uint16
	HasLocal     bool
	Option       SocketOptionPlan
}

var socketOperationBits = map[string]uint32{
	"create": SocketCreate, "bind": SocketBind, "listen": SocketListen, "accept": SocketAccept,
	"send": SocketSend, "receive": SocketReceive, "get_local_name": SocketGetLocalName,
	"get_peer_name": SocketGetPeerName, "shutdown": SocketShutdown, "set_option": SocketSetOption, "get_option": SocketGetOption,
}

// EvaluateSocket is an ownership-independent operation check. Peer endpoint and
// descriptor ownership checks remain mandatory separate conditions.
func EvaluateSocket(plan SocketPlan, operation SocketOperation, now uint64) Decision {
	if plan.Generation == 0 || now >= plan.ExpiresNS || plan.Count > MaxRules {
		return Decision{Reason: "missing-invalid-or-expired-policy"}
	}
	if (operation.Family != 2 && operation.Family != 10) || (operation.Protocol != TCP && operation.Protocol != UDP) || operation.Operation == 0 || operation.Operation&(operation.Operation-1) != 0 {
		return Decision{Reason: "unsupported-socket-operation"}
	}
	result := Decision{Reason: "unmatched"}
	bestLocal, bestWidth := -1, 65536
	for _, rule := range plan.Rules[:plan.Count] {
		if rule.OptionCount > MaxSocketOptions || rule.Effect > Allow || rule.HasLocal > 1 || rule.PortFrom > rule.PortTo || rule.Index == 0 || rule.Operations == 0 || rule.Operations&^uint32(2047) != 0 {
			return Decision{Reason: "invalid-rule"}
		}
		if rule.Family != operation.Family || rule.Protocol != operation.Protocol || rule.Operations&operation.Operation == 0 {
			continue
		}
		if rule.HasLocal == 1 && (!operation.HasLocal || operation.LocalAddress != rule.Address || operation.LocalPort < rule.PortFrom || operation.LocalPort > rule.PortTo) {
			continue
		}
		if operation.Operation == SocketSetOption || operation.Operation == SocketGetOption {
			if rule.Effect == Allow && operation.Operation == SocketSetOption && operation.Option.Level == 1 &&
				(operation.Option.Name == 3 || operation.Option.Name == 4) {
				continue // SO_TYPE and SO_ERROR are getter-only even in a mixed-operation rule.
			}
			matched := rule.OptionCount == 0 && rule.Effect == Deny
			for _, option := range rule.Options[:rule.OptionCount] {
				if option == operation.Option {
					matched = true
				}
			}
			if !matched {
				continue
			}
		}
		local, width := int(rule.HasLocal), 65535
		if rule.HasLocal == 1 {
			width = int(rule.PortTo - rule.PortFrom)
		}
		if local < bestLocal || (local == bestLocal && width > bestWidth) {
			continue
		}
		if local == bestLocal && width == bestWidth && !result.Allowed {
			continue
		}
		if local == bestLocal && width == bestWidth && rule.Effect == Allow && result.RuleIndex < rule.Index {
			continue
		}
		bestLocal, bestWidth = local, width
		result = Decision{Allowed: rule.Effect == Allow, RuleIndex: rule.Index, Reason: "rule"}
	}
	return result
}
