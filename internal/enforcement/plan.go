// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package enforcement

import (
	"alloyium.local/kernel-poc/internal/fsrules"
	"alloyium.local/kernel-poc/internal/netrules"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/processrules"
	"alloyium.local/kernel-poc/internal/runtimeguard"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
)

type Plan struct {
	files                        fsrules.Plan
	peers                        netrules.Compiled
	sockets                      netrules.CompiledSockets
	syscalls                     runtimeguard.Plan
	process                      processrules.Plan
	domain, generation, deadline uint64
	digest                       string
	bootstrapDigest              string
	bootstrapRead                bool
	bootstrapListener            bool
	bootstrapFinalize            bool
	bootstrapWorkingDirectory    bool
	bootstrapCredentialNamespace bool
	anonymous                    bool
	bootstrapMaxHold             int
	dns                          *dnsState
}

func Compile(document policy.Document, domain, generation, now, deadline uint64, leases []netrules.Lease) (Plan, error) {
	return compile(document, domain, generation, now, deadline, leases, false)
}

// CompileForTarget requires signed qualification before it accepts the optional
// credential namespace setup and explicit eventfd guard. It adds no runtime right.
func CompileForTarget(document policy.Document, domain, generation, now, deadline uint64, leases []netrules.Lease, target policy.VerifiedTarget, wallUnix int64) (Plan, error) {
	if _, err := policy.PreviewForTarget(document, target, wallUnix); err != nil {
		return Plan{}, err
	}
	return compile(document, domain, generation, now, deadline, leases, true)
}
func compile(document policy.Document, domain, generation, now, deadline uint64, leases []netrules.Lease, qualified bool) (Plan, error) {
	var p Plan
	if err := document.Validate(); err != nil {
		return p, err
	}
	if err := document.CheckDeclaredRequirements(); err != nil {
		return p, err
	}
	if document.Profile != policy.KernelProfile || document.Files == nil || document.Programs == nil || document.Network == nil || document.Sockets == nil || document.Runtime == nil || document.Extensions == nil || len(*document.Extensions) != 0 || document.RuntimeTemplates == nil || len(*document.RuntimeTemplates) != 0 {
		return p, errors.New("a complete explicit policy without unsupported extensions or template references is required")
	}
	if domain == 0 || generation == 0 || deadline <= now || deadline-now > uint64(document.Lifecycle.DurationSeconds)*1000000000 {
		return p, errors.New("the prepared policy binding is invalid")
	}
	var err error
	if document.Runtime.Bootstrap != nil {
		for _, operation := range document.Runtime.Bootstrap.Operations {
			if operation == "credential_namespace" {
				if !qualified {
					return Plan{}, errors.New("credential namespace admission requires the qualified helper transport and mount stage")
				}
				p.bootstrapCredentialNamespace = true
			}
		}
	}
	if p.files, err = fsrules.CompileWithRuntime(*document.Files, *document.Programs, *document.Runtime, domain, generation, deadline); err != nil {
		return Plan{}, err
	}
	p.anonymous = document.Runtime.IPC != nil && document.Runtime.IPC.EventFDs != nil && len(*document.Runtime.IPC.EventFDs) > 0
	if p.anonymous {
		if !qualified {
			return Plan{}, errors.New("eventfd admission requires the qualified coupled anonymous object guard")
		}
		p.files = p.files.WithAnonymousGuard()
		err = p.files.CheckAccessWithAnonymous(domain, now)
	} else {
		err = p.files.CheckAccess(domain, now)
	}
	if err != nil {
		return Plan{}, err
	}
	if p.peers, err = netrules.Compile(*document.Network, generation, now, deadline, leases); err != nil {
		return Plan{}, err
	}
	if p.sockets, err = netrules.CompileSockets(*document.Sockets, generation, now, deadline); err != nil {
		return Plan{}, err
	}
	if p.syscalls, err = runtimeguard.Compile(*document.Runtime); err != nil {
		return Plan{}, err
	}
	if p.process, err = processrules.Compile(*document.Runtime, domain, generation, deadline); err != nil {
		return Plan{}, err
	}
	if document.Runtime.Bootstrap != nil {
		p.bootstrapDigest = document.Runtime.Bootstrap.HelperDigest
		p.bootstrapMaxHold = document.Runtime.Bootstrap.MaxHoldSeconds
		for _, op := range document.Runtime.Bootstrap.Operations {
			p.bootstrapRead = p.bootstrapRead || op == "barrier_read"
			p.bootstrapListener = p.bootstrapListener || op == "listener_send"
			p.bootstrapFinalize = p.bootstrapFinalize || op == "filter_finalize"
			p.bootstrapWorkingDirectory = p.bootstrapWorkingDirectory || op == "working_directory"
		}
	}
	if p.bootstrapRead {
		calls := map[string]bool{}
		for _, n := range document.Runtime.Seccomp.AllowSyscalls {
			calls[n] = true
		}
		if !calls["read"] || !calls["close"] {
			return Plan{}, errors.New("bootstrap control reads require explicit read and close syscall permissions")
		}
	}
	p.domain, p.generation, p.deadline = domain, generation, deadline
	raw, _ := json.Marshal(struct {
		Document                     policy.Document
		Domain, Generation, Deadline uint64
		Files                        string
		Peers                        netrules.Compiled
		Sockets                      netrules.CompiledSockets
		Syscalls                     string
		Process                      string
	}{document, domain, generation, deadline, p.files.Digest(), p.peers, p.sockets, p.syscalls.Digest(), p.process.Digest()})
	hash := sha256.Sum256(raw)
	p.digest = hex.EncodeToString(hash[:])
	return p, nil
}
func (p Plan) Digest() string              { return p.digest }
func (p Plan) Syscalls() runtimeguard.Plan { return p.syscalls }

// ValidateChildBootstrap requires each trusted setup action before child launch.
// The final filters remove setup rights before the held barrier acknowledgement.
func (p Plan) ValidateChildBootstrap(helperDigest string) error {
	if p.digest == "" || helperDigest == "" || p.bootstrapDigest != helperDigest || !p.bootstrapRead || !p.bootstrapWorkingDirectory {
		return errors.New("the measured child requires explicit barrier and working directory bootstrap permissions")
	}
	if !p.syscalls.RequiresExecListener() || !p.bootstrapListener || !p.bootstrapFinalize {
		return errors.New("the measured child requires explicit listener transfer and filter finalization permissions")
	}
	calls := map[string]bool{}
	for _, name := range p.syscalls.Names() {
		calls[name] = true
	}
	for _, name := range []string{"read", "write", "close", "openat", "fstat", "dup2", "execve", "exit_group"} {
		if !calls[name] {
			return fmt.Errorf("the measured child requires explicit syscall permission: %s", name)
		}
	}
	return nil
}

// Install requires a live stopped helper verifier before and after all map writes.
// It stops the complete domain on every failed write or readback.
func (g *Group) Install(p Plan, verifyHeld func() error) (err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	defer func() {
		if err != nil {
			_ = g.StopRetain()
		}
	}()
	for _, r := range g.components() {
		if r == nil || r.Collection == nil || r.Domain == "" {
			return errors.New("a mandatory composite runtime is unavailable")
		}
	}
	if p.anonymous && g.Anonymous == nil {
		return errors.New("the requested anonymous object guard is absent")
	}
	if g.closed || verifyHeld == nil || p.digest == "" || p.generation <= g.generation || g.Files == nil || p.domain != g.Files.ID {
		return errors.New("the stopped process or immutable policy binding is missing")
	}
	quiescent := func() error { return g.Files.VerifyQuiescent(verifyHeld) }
	if err = quiescent(); err != nil {
		return err
	}
	if err = processrules.Install(g.Process, p.process, quiescent); err != nil {
		return err
	}
	if p.dns != nil {
		if err = p.dns.check(0); err != nil {
			return err
		}
	}
	for _, v := range []struct {
		r     *ebpf.Map
		value any
	}{{g.Peers.Collection.Maps["net_policies"], p.peers.Policy}, {g.Sockets.Collection.Maps["sock_policies"], p.sockets.Plan}, {g.Custody.Collection.Maps["cust_bindings"], custodyBinding{p.generation, p.deadline}}} {
		if v.r == nil {
			return errors.New("a mandatory composite policy map is absent")
		}
		if err = v.r.Update(p.domain, v.value, ebpf.UpdateExist); err != nil {
			return err
		}
	}
	var peerReadback netrules.Policy
	var socketReadback netrules.SocketPlan
	var custodyReadback custodyBinding
	if err = g.Peers.Collection.Maps["net_policies"].Lookup(p.domain, &peerReadback); err != nil {
		return err
	}
	if err = g.Sockets.Collection.Maps["sock_policies"].Lookup(p.domain, &socketReadback); err != nil {
		return err
	}
	if err = g.Custody.Collection.Maps["cust_bindings"].Lookup(p.domain, &custodyReadback); err != nil {
		return err
	}
	if peerReadback != p.peers.Policy || socketReadback != p.sockets.Plan || custodyReadback != (custodyBinding{p.generation, p.deadline}) {
		return errors.New("composite map readback differs")
	}
	var files fsrules.Plan
	if files, err = fsrules.EnableSocketDelegation(p.files, g.Peers, g.Sockets, g.Custody); err != nil {
		return err
	}
	if g.Anonymous != nil {
		files = files.WithAnonymousGuard()
		err = fsrules.InstallAccessCoupled(g.Files, files, g.Anonymous)
	} else {
		err = fsrules.InstallAccess(g.Files, files)
	}
	if err != nil {
		return err
	}
	if err = quiescent(); err != nil {
		return err
	}
	stats, e := g.Counters()
	if p.dns != nil {
		if err = p.dns.check(0); err != nil {
			return err
		}
	}
	if e != nil {
		return e
	}
	if stats.Lost != 0 {
		return errors.New("composite policy evidence reports loss")
	}
	g.generation = p.generation
	if p.dns != nil {
		copy := *p.dns
		g.dns = &copy
	} else {
		g.dns = nil
	}
	return nil
}
