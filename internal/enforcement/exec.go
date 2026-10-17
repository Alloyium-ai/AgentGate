// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package enforcement

import (
	"alloyium.local/kernel-poc/internal/execbroker"
	"alloyium.local/kernel-poc/internal/fsrules"
	"errors"
	"fmt"
	"path/filepath"
)

// ExecBrokerConfig binds a broker to the installed file state and actual exec link.
func (g *Group) ExecBrokerConfig(p Plan, bootID string) (execbroker.Config, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var c execbroker.Config
	if g.closed || g.Files == nil || p.domain != g.Files.ID || p.generation != g.generation || !p.syscalls.RequiresExecListener() {
		return c, errors.New("the exec broker requires an installed explicit exec plan")
	}
	var state fsrules.State
	if err := g.Files.Collection.Maps["policies"].Lookup(p.domain, &state); err != nil {
		return c, err
	}
	expected := p.files.State()
	expected.SocketGeneration = p.generation
	if g.Anonymous != nil {
		expected.Pipes |= fsrules.AnonymousDelegation
	}
	if state != expected {
		return c, errors.New("the exec broker file readback differs")
	}
	program := g.Files.Collection.Programs["fs_exec"]
	if program == nil {
		return c, errors.New("the mandatory exec program is absent")
	}
	info, err := program.Info()
	if err != nil {
		return c, err
	}
	id, ok := info.ID()
	if !ok {
		return c, errors.New("the exec program ID is unavailable")
	}
	index := -1
	for i, name := range g.Files.Hooks() {
		if name == "fs_exec" {
			index = i
			break
		}
	}
	if index < 0 {
		return c, errors.New("the mandatory exec link is absent")
	}
	c = execbroker.Config{Protocol: "agentgate.exec-broker.v1", Domain: g.Files.Domain, DomainID: p.domain, Generation: p.generation, DeadlineNS: p.deadline, BootID: bootID, PolicyDigest: p.digest, ExecLink: filepath.Join(g.Files.Pins, fmt.Sprintf("link-%d", index)), ExecProgramID: uint32(id), Files: state}
	return c, c.Validate()
}
