// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package fsrules compiles file and program sections. It does not admit a job.
package fsrules

import (
	"alloyium.local/kernel-poc/internal/openrules"
	"alloyium.local/kernel-poc/internal/policy"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

const Purpose = "agentgate.files-programs-component.v1"
const OperationCount = 14
const AnonymousDelegation = uint64(1) << 63

var operations = [OperationCount]string{"read", "write", "create", "mkdir", "delete", "rename", "hardlink", "symlink", "metadata", "mmap", "descriptor_receive", "execute", "map_execute", "mprotect"}

type State struct {
	Generation, ExpiresNS uint64
	Roots                 [OperationCount]openrules.Node
	Memory                uint64
	Pipes                 uint64
	SocketGeneration      uint64
}
type Plan struct {
	domain          uint64
	state           State
	entries         []openrules.Entry
	rules           []string
	digest          string
	reference       [OperationCount]openrules.Plan
	allowOperations []string
}

// WithAnonymousGuard selects a separate mandatory guard. It grants no right.
// Default access installation refuses this flag without the coupled runtime.
func (plan Plan) WithAnonymousGuard() Plan {
	plan.state.Pipes |= AnonymousDelegation
	plan.digest = planDigest(plan)
	return plan
}

func Compile(files policy.Files, programs policy.Programs, domain, generation, deadline uint64) (Plan, error) {
	var out Plan
	if files.Defaults != (policy.FileDefaults{Read: "deny", Write: "deny"}) || files.ResourceUse != "recheck-and-terminate" {
		return out, errors.New("file sections require explicit deny defaults and strict resource-use semantics")
	}
	if err := policy.ValidateFileRules(files.Rules); err != nil {
		return out, err
	}
	if err := policy.ValidateProgramsSection(programs); err != nil {
		return out, err
	}
	ids := map[string]bool{}
	allows := map[string]bool{}
	for _, rule := range files.Rules {
		ids[rule.ID] = true
		out.rules = append(out.rules, rule.ID)
		if rule.Effect == "allow" {
			for _, operation := range rule.Operations {
				allows[operation] = true
			}
		}
	}
	for _, rule := range programs.Rules {
		if ids[rule.ID] {
			return Plan{}, errors.New("file and program rule IDs must be globally unique")
		}
		if rule.Approval != nil {
			return Plan{}, errors.New("executable approval requires the qualified held-exec broker")
		}
		ids[rule.ID] = true
		out.rules = append(out.rules, rule.ID)
		if rule.Effect == "allow" {
			allows["execute"] = true
		}
	}
	for operation := range allows {
		out.allowOperations = append(out.allowOperations, operation)
	}
	sort.Strings(out.allowOperations)
	sort.Strings(out.rules)
	indexes := map[string]uint32{}
	for i, id := range out.rules {
		indexes[id] = uint32(i + 1)
	}
	out.domain = domain
	out.state.Generation = generation
	out.state.ExpiresNS = deadline
	for operation, name := range operations {
		rules := operationRules(files, programs, name)
		compiled, err := openrules.Compile(rules, domain, generation, deadline)
		if err != nil {
			return Plan{}, fmt.Errorf("%s: %w", name, err)
		}
		out.reference[operation] = compiled
		localRules := compiled.Rules()
		remap := func(node openrules.Node) openrules.Node {
			for _, action := range []*openrules.Action{&node.SubRead, &node.SubWrite, &node.ExactRead, &node.ExactWrite} {
				if action.Rule > 0 {
					action.Rule = indexes[localRules[action.Rule-1]]
				}
			}
			return node
		}
		out.state.Roots[operation] = remap(compiled.State().Root)
		for _, entry := range compiled.Entries() {
			entry.Key.Padding = uint32(operation)
			entry.Node = remap(entry.Node)
			out.entries = append(out.entries, entry)
		}
		if len(out.entries) > openrules.MaxNodes {
			return Plan{}, errors.New("file/program rules exceed the target map capacity")
		}
	}
	out.digest = planDigest(out)
	return out, nil
}

// CompileWithRuntime includes only explicit anonymous memory rights.
func CompileWithRuntime(files policy.Files, programs policy.Programs, runtime policy.Runtime, domain, generation, deadline uint64) (Plan, error) {
	if err := policy.ValidateRuntimeSection(runtime); err != nil {
		return Plan{}, err
	}
	out, err := Compile(files, programs, domain, generation, deadline)
	if err != nil {
		return Plan{}, err
	}
	if runtime.Memory != nil {
		if err = policy.ValidateMemorySection(*runtime.Memory); err != nil {
			return Plan{}, err
		}
		for _, operation := range runtime.Memory.Anonymous {
			switch operation {
			case "read":
				out.state.Memory |= 1
			case "write":
				out.state.Memory |= 2
			case "execute":
				out.state.Memory |= 4
			case "map":
				out.state.Memory |= 8
			case "protect":
				out.state.Memory |= 16
			}
		}
		if runtime.Memory.Heap == "allow" {
			out.state.Memory |= 32
		}
	}
	if runtime.IPC != nil {
		if runtime.IPC.EventFDs != nil {
			for _, operation := range *runtime.IPC.EventFDs {
				switch operation {
				case "create":
					out.state.Pipes |= 8
				case "read":
					out.state.Pipes |= 16
				case "write":
					out.state.Pipes |= 32
				}
			}
		}
		for _, operation := range runtime.IPC.Pipes {
			switch operation {
			case "create":
				out.state.Pipes |= 1
			case "read":
				out.state.Pipes |= 2
			case "write":
				out.state.Pipes |= 4
			}
		}
	}
	out.digest = planDigest(out)
	return out, nil
}

func operationRules(files policy.Files, programs policy.Programs, operation string) []policy.FileRule {
	rules := []policy.FileRule{}
	if operation == "execute" {
		for _, rule := range programs.Rules {
			rules = append(rules, policy.FileRule{ID: rule.ID, Selector: rule.Selector, Operations: []string{"read"}, Effect: rule.Effect})
		}
		return rules
	}
	for _, rule := range files.Rules {
		for _, name := range rule.Operations {
			if name == operation {
				rules = append(rules, policy.FileRule{ID: rule.ID, Selector: rule.Selector, Operations: []string{"read"}, Effect: rule.Effect})
			}
		}
	}
	return rules
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
	_ = binary.Write(h, binary.LittleEndian, uint32(len(plan.allowOperations)))
	for _, operation := range plan.allowOperations {
		_ = binary.Write(h, binary.LittleEndian, uint32(len(operation)))
		h.Write([]byte(operation))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (plan Plan) Effect(path, operation string) string {
	for i, name := range operations {
		if name == operation {
			return plan.reference[i].Effect(path, "read")
		}
	}
	return "deny"
}
func Operations() []string                    { return append([]string{}, operations[:]...) }
func (plan Plan) Domain() uint64              { return plan.domain }
func (plan Plan) State() State                { return plan.state }
func (plan Plan) Entries() []openrules.Entry  { return append([]openrules.Entry{}, plan.entries...) }
func (plan Plan) Rules() []string             { return append([]string{}, plan.rules...) }
func (plan Plan) Digest() string              { return plan.digest }
func (plan Plan) AllowedOperations() []string { return append([]string{}, plan.allowOperations...) }
