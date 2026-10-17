// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package enforcement

import (
	"alloyium.local/kernel-poc/internal/anonrules"
	"alloyium.local/kernel-poc/internal/fsrules"
	"alloyium.local/kernel-poc/internal/netrules"
	"alloyium.local/kernel-poc/internal/processrules"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// VerifyInstalled checks every immutable resource table under the publication lock.
// DNS readback uses the current validated revision of the unchanged signed rules.
func (g *Group) VerifyInstalled(p Plan) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.verifyInstalledLocked(p)
}
func (g *Group) verifyInstalledLocked(p Plan) (string, error) {
	if g.closed || p.digest == "" || p.generation != g.generation || g.Files == nil || g.Files.ID != p.domain {
		return "", errors.New("the installed composite binding differs")
	}
	for _, r := range g.components() {
		if r == nil || r.Collection == nil {
			return "", errors.New("an installed runtime is absent")
		}
	}
	files, err := fsrules.EnableSocketDelegation(p.files, g.Peers, g.Sockets, g.Custody)
	if err != nil {
		return "", err
	}
	if p.anonymous && g.Anonymous == nil {
		return "", errors.New("the requested anonymous object guard is absent")
	}
	if g.Anonymous != nil {
		if err = anonrules.VerifyCoupling(g.Files, g.Anonymous); err != nil {
			return "", err
		}
		files = files.WithAnonymousGuard()
	}
	if err = fsrules.VerifyAccess(g.Files, files); err != nil {
		return "", err
	}
	wantPeers := p.peers.Policy
	if g.dns != nil {
		if g.dns.binding.Generation != p.generation || g.dns.binding.DomainID != p.domain {
			return "", errors.New("the installed DNS binding differs")
		}
		wantPeers = g.dns.snapshot.Plan()
	}
	var peers netrules.Policy
	var sockets netrules.SocketPlan
	var custody custodyBinding
	var process processrules.State
	if err = g.Peers.Collection.Maps["net_policies"].Lookup(p.domain, &peers); err != nil {
		return "", err
	}
	if err = g.Sockets.Collection.Maps["sock_policies"].Lookup(p.domain, &sockets); err != nil {
		return "", err
	}
	if err = g.Custody.Collection.Maps["cust_bindings"].Lookup(p.domain, &custody); err != nil {
		return "", err
	}
	if err = g.Process.Collection.Maps["proc_policies"].Lookup(p.domain, &process); err != nil {
		return "", err
	}
	if peers != wantPeers || sockets != p.sockets.Plan || custody != (custodyBinding{p.generation, p.deadline}) || process != p.process.State() {
		return "", errors.New("an installed resource table differs")
	}
	for _, entry := range []struct{ component, mapName string }{{"sockets", "sock_managed"}, {"custody", "cust_managed"}, {"process", "proc_managed"}} {
		var marker uint32
		r := g.Sockets
		if entry.component == "custody" {
			r = g.Custody
		}
		if entry.component == "process" {
			r = g.Process
		}
		if r.Collection.Maps[entry.mapName].Lookup(p.domain, &marker) != nil || marker != 1 {
			return "", errors.New("an installed ownership marker differs")
		}
	}
	raw, _ := json.Marshal(struct {
		Plan, Files string
		Peers       netrules.Policy
		Sockets     netrules.SocketPlan
		Custody     custodyBinding
		Process     processrules.State
	}{p.digest, files.Digest(), peers, sockets, custody, process})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
