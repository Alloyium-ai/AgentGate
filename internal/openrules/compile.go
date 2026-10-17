// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package openrules compiles one experimental file-open component.
// The component cannot authorize a full policy or issue a workload grant.
package openrules

import (
	"alloyium.local/kernel-poc/internal/policy"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const Purpose = "agentgate.file-open-prototype.v1"
const MaxPath = 4096
const NameSize = 256
const MaxNodes = 65536
const Allow = uint32(1)
const Deny = uint32(2)

type Action struct{ Effect, Rule uint32 }
type Node struct {
	ID                                       uint32
	SubRead, SubWrite, ExactRead, ExactWrite Action
}
type Key struct {
	Domain, Generation uint64
	Parent             uint32
	Name               [NameSize]byte
	Padding            uint32
}
type Entry struct {
	Key  Key
	Node Node
}
type State struct {
	Generation, ExpiresNS uint64
	Root                  Node
	Padding               uint32
}
type Plan struct {
	domain  uint64
	state   State
	entries []Entry
	rules   []string
	digest  string
}
type buildNode struct {
	node   Node
	parent uint32
	name   string
}

func mergeAction(old, next Action) Action {
	if old.Effect == 0 || (next.Effect == Deny && old.Effect != Deny) {
		return next
	}
	return old
}
func setAction(node *Node, rule policy.FileRule, index uint32) error {
	effect := Deny
	if rule.Effect == "allow" {
		effect = Allow
	}
	for _, op := range rule.Operations {
		var action *Action
		switch op {
		case "read":
			if rule.Selector.Kind == "exact" {
				action = &node.ExactRead
			} else {
				action = &node.SubRead
			}
		case "write":
			if rule.Selector.Kind == "exact" {
				action = &node.ExactWrite
			} else {
				action = &node.SubWrite
			}
		default:
			return fmt.Errorf("the file-open component does not implement operation %s", op)
		}
		*action = mergeAction(*action, Action{effect, index})
	}
	return nil
}

// Compile accepts only file rules. It never drops fields from a full document.
func Compile(rules []policy.FileRule, domain, generation, deadline uint64) (Plan, error) {
	var plan Plan
	if domain == 0 || generation == 0 || deadline == 0 {
		return plan, errors.New("a component requires a domain, generation, and monotonic deadline")
	}
	if err := policy.ValidateFileRules(rules); err != nil {
		return plan, err
	}
	rules = append([]policy.FileRule{}, rules...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	nodes := map[string]*buildNode{"/": {}}
	for i, rule := range rules {
		if len(rule.Selector.Path) >= MaxPath {
			return plan, errors.New("file selector exceeds the target path buffer")
		}
		path := "/"
		parent := nodes[path]
		if rule.Selector.Path != "/" {
			for _, part := range strings.Split(strings.TrimPrefix(rule.Selector.Path, "/"), "/") {
				if len(part) >= NameSize {
					return plan, errors.New("file selector exceeds the target component limit")
				}
				path = filepath.Join(path, part)
				next := nodes[path]
				if next == nil {
					if len(nodes) >= MaxNodes {
						return plan, errors.New("file rules exceed the target node capacity")
					}
					next = &buildNode{node: Node{ID: uint32(len(nodes))}, parent: parent.node.ID, name: part}
					nodes[path] = next
				}
				parent = next
			}
		}
		if err := setAction(&parent.node, rule, uint32(i+1)); err != nil {
			return plan, err
		}
		plan.rules = append(plan.rules, rule.ID)
	}
	plan.domain = domain
	plan.state = State{Generation: generation, ExpiresNS: deadline, Root: nodes["/"].node}
	for path, node := range nodes {
		if path == "/" {
			continue
		}
		key := Key{Domain: domain, Generation: generation, Parent: node.parent}
		copy(key.Name[:], node.name)
		plan.entries = append(plan.entries, Entry{key, node.node})
	}
	sort.Slice(plan.entries, func(i, j int) bool { return plan.entries[i].Node.ID < plan.entries[j].Node.ID })
	plan.digest = planDigest(plan)
	return plan, nil
}
func planDigest(plan Plan) string {
	h := sha256.New()
	h.Write([]byte(Purpose + "\n" + policy.SchemaDigest() + "\n"))
	_ = binary.Write(h, binary.LittleEndian, plan.domain)
	_ = binary.Write(h, binary.LittleEndian, plan.state)
	_ = binary.Write(h, binary.LittleEndian, uint32(len(plan.entries)))
	_ = binary.Write(h, binary.LittleEndian, uint32(len(plan.rules)))
	for _, entry := range plan.entries {
		_ = binary.Write(h, binary.LittleEndian, entry)
	}
	for _, id := range plan.rules {
		_ = binary.Write(h, binary.LittleEndian, uint32(len(id)))
		h.Write([]byte(id))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func candidate(node Node, read bool, exact bool) Action {
	sub := node.SubWrite
	direct := node.ExactWrite
	if read {
		sub = node.SubRead
		direct = node.ExactRead
	}
	if !exact || direct.Effect == 0 {
		return sub
	}
	if sub.Effect == Deny {
		return sub
	}
	return direct
}

// Effect is a reference decoder for the compiled map representation.
func (plan Plan) Effect(path, operation string) string {
	if operation != "read" && operation != "write" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) || len(path) >= MaxPath {
		return "deny"
	}
	read := operation == "read"
	best := candidate(plan.state.Root, read, path == "/")
	if path == "/" {
		if best.Effect == Allow {
			return "allow"
		}
		return "deny"
	}
	lookup := map[Key]Node{}
	for _, entry := range plan.entries {
		lookup[entry.Key] = entry.Node
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	parent := uint32(0)
	for i, part := range parts {
		if len(part) >= NameSize {
			return "deny"
		}
		key := Key{Domain: plan.domain, Generation: plan.state.Generation, Parent: parent}
		copy(key.Name[:], part)
		node, found := lookup[key]
		if !found {
			break
		}
		next := candidate(node, read, i == len(parts)-1)
		if next.Effect != 0 {
			best = next
		}
		parent = node.ID
	}
	if best.Effect == Allow {
		return "allow"
	}
	return "deny"
}

func (plan Plan) Domain() uint64   { return plan.domain }
func (plan Plan) State() State     { return plan.state }
func (plan Plan) Entries() []Entry { return append([]Entry{}, plan.entries...) }
func (plan Plan) Rules() []string  { return append([]string{}, plan.rules...) }
func (plan Plan) Digest() string   { return plan.digest }
