// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodeapi"
	"alloyium.local/kernel-poc/internal/nodeaudit"
	"alloyium.local/kernel-poc/internal/nodebackend"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"alloyium.local/kernel-poc/internal/watchdogapi"
	"context"
	"errors"
	"os"
	"time"
)

type Authority interface {
	jobgrant.RevocationProvider
	nodebackend.ReceiptAuthority
}
type AuthorityFactory func(*Sources) (Authority, error)
type Node struct {
	fixture   *lifecycle.QualificationFixturePermit
	config    Config
	sources   *Sources
	backend   *nodebackend.Backend
	manager   *lifecycle.Manager
	watchdog  *watchdogapi.Client
	server    *nodeapi.Server
	journal   *lifecycle.SQLiteJournal
	owner     *os.File
	authority interface{ Close() }
}

func NewNode(ctx context.Context, c Config, factory AuthorityFactory) (*Node, error) {
	return newNode(ctx, c, factory, nil)
}

func newNode(ctx context.Context, c Config, factory AuthorityFactory, spec *lifecycle.QualificationFixtureSpec) (out *Node, err error) {
	return newNodeWithQualification(ctx, c, factory, spec, nil)
}

func newNodeWithQualification(ctx context.Context, c Config, factory AuthorityFactory, spec *lifecycle.QualificationFixtureSpec, version *lifecycle.QualificationVersionSpec) (out *Node, err error) {
	if spec != nil && version != nil {
		return nil, errors.New("a node cannot borrow two qualification purposes")
	}
	if factory == nil {
		return nil, errors.New("an authenticated authority transport is required")
	}
	if err = kernel.Preflight(); err != nil {
		return nil, err
	}
	if spec != nil {
		if err = validateQualificationNodePaths(c, *spec); err != nil {
			return nil, err
		}
	}
	if version != nil {
		if err = validateQualificationVersionNodePaths(c, *version); err != nil {
			return nil, err
		}
	}
	n := &Node{config: c}
	if n.owner, err = acquireOwner(c.Journal + ".owner"); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if n.backend != nil {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
				_ = n.backend.Close(cleanup)
				cancel()
			}
			if n.journal != nil {
				_ = n.journal.Close()
			}
			if n.authority != nil {
				n.authority.Close()
			}
			_ = n.owner.Close()
		}
	}()
	if n.sources, err = NewSources(c); err != nil {
		return nil, err
	}
	if spec != nil {
		if n.fixture, err = n.qualificationPermit(ctx, *spec); err != nil {
			return nil, err
		}
	}
	if version != nil {
		if n.fixture, err = n.qualificationVersionPermit(ctx, *version); err != nil {
			return nil, err
		}
	}
	authority, err := factory(n.sources)
	if err != nil {
		return nil, err
	}
	if closer, ok := authority.(interface{ Close() }); ok {
		n.authority = closer
	}
	clock := Clock{}
	stop := time.Duration(c.StopTimeoutMS) * time.Millisecond
	identity := lifecycle.Identity{NodeID: c.NodeID, BootID: n.sources.Proof.BootID}
	if n.journal, err = lifecycle.OpenJournal(c.Journal); err != nil {
		return nil, err
	}
	trust := jobgrant.Config{Authorities: n.sources.AuthorityKeys, Enrollment: n.sources, Qualification: n.sources, Revocation: authority, Clock: clock, MaxLifetime: 24 * time.Hour}
	var verifier *jobgrant.Verifier
	if n.fixture != nil {
		trust.MaxLifetime = 30 * time.Second
		if n.fixture.Purpose() == lifecycle.QualificationVersionPurpose {
			verifier, err = jobgrant.NewQualificationVersionVerifier(trust, n.fixture)
		} else {
			verifier, err = jobgrant.NewQualificationFixtureVerifier(trust, n.fixture)
		}
	} else {
		verifier, err = jobgrant.NewVerifier(trust)
	}
	if err != nil {
		return nil, err
	}
	watchKey, err := n.sources.WatchdogKey()
	if err != nil {
		return nil, err
	}
	start, err := lifecycle.ProcessStartTime(os.Getpid())
	if err != nil {
		return nil, err
	}
	if n.watchdog, err = watchdogapi.NewClient(watchdogapi.ClientConfig{SocketPath: c.WatchdogSocket, Daemon: lifecycle.DaemonIdentity{PID: os.Getpid(), StartTimeTicks: start, InstanceID: c.InstanceID}, PublicKey: watchKey, ArtifactDigest: c.ArtifactDigests["watchdog"], Clock: clock, Timeout: 500 * time.Millisecond, HeartbeatInterval: 250 * time.Millisecond}); err != nil {
		return nil, err
	}
	backendConfig := nodebackend.Config{Domain: domainstore.Config{NodeID: c.NodeID, StateDir: c.DomainState, Proof: n.sources.Proof, StopTimeout: stop}, Artifacts: c.Artifacts, ObservationObject: c.ObservationObject, ObservationProfile: syscallrules.RuntimeProfile(), Helper: c.Helper, Broker: c.Broker, ArtifactDigests: n.sources.Config.ArtifactDigests, CompilerDigest: n.sources.Compiler, ArtifactRoot: c.ArtifactRoot, AuditRoot: c.AuditRoot, OutputLimit: c.OutputLimit, MaxRuns: c.MaxRuns, Limits: c.Limits, Resolver: n.sources.Resolver, Credentials: c.Credentials, PilotTarget: c.PilotTarget, Documents: n.sources, Runtimes: n.sources, Qualification: n.sources, Verifier: verifier, Clock: clock, Signer: n.sources.Signer, NodeKeys: n.sources.NodeKeys, AuthorityKeys: n.sources.AuthorityKeys, Authority: authority, Registry: nodeaudit.Registry()}
	if n.fixture != nil {
		if n.fixture.Purpose() == lifecycle.QualificationVersionPurpose {
			n.backend, err = nodebackend.NewQualificationVersionBackend(ctx, backendConfig, n.fixture)
		} else {
			n.backend, err = nodebackend.NewQualificationFixtureBackend(ctx, backendConfig, n.fixture)
		}
	} else {
		n.backend, err = nodebackend.New(backendConfig)
	}
	if err != nil {
		return nil, err
	}
	if n.fixture != nil {
		if n.fixture.Purpose() == lifecycle.QualificationVersionPurpose {
			n.manager, err = lifecycle.NewQualificationVersionManager(n.backend, verifier, n.journal, clock, identity, stop, n.watchdog, watchKey, n.fixture)
		} else {
			n.manager, err = lifecycle.NewQualificationFixtureManager(n.backend, verifier, n.journal, clock, identity, stop, n.watchdog, watchKey, n.fixture)
		}
	} else {
		n.manager, err = lifecycle.NewGuarded(n.backend, verifier, n.journal, clock, identity, stop, n.watchdog, watchKey)
	}
	if err != nil {
		return nil, err
	}
	if err = n.manager.Recover(ctx); err != nil {
		return nil, err
	}
	if n.fixture != nil {
		return n, nil
	}
	operations, err := nodebackend.NewOperations(nodebackend.OperationsConfig{Backend: n.backend, Manager: n.manager, Generations: n.journal, Target: n.sources.Target, PreparationLease: time.Duration(c.PreparationLeaseMS) * time.Millisecond})
	if err != nil {
		return nil, err
	}
	if n.server, err = nodeapi.New(nodeapi.Config{Identity: identity, SocketPath: c.SocketPath, SocketGID: c.SocketGID, Clock: clock, ReadHeaderTimeout: 5 * time.Second, RequestTimeout: time.Duration(c.RequestTimeoutMS) * time.Millisecond, ShutdownTimeout: stop}, Enrollments{Sources: n.sources}, n.journal, operations); err != nil {
		return nil, err
	}
	return n, nil
}
func (n *Node) Serve(ctx context.Context) error {
	if n.fixture != nil || n.server == nil {
		return errors.New("the fixture node has no normal admission server")
	}
	run, cancel := context.WithCancel(ctx)
	defer cancel()
	watchdog := make(chan error, 1)
	manager := make(chan error, 1)
	server := make(chan error, 1)
	go func() { watchdog <- n.watchdog.Run(run) }()
	if err := n.waitHeartbeat(ctx, watchdog); err != nil {
		cancel()
		return errors.Join(err, n.Close(context.WithoutCancel(ctx)))
	}
	go func() { manager <- n.manager.Watch(run, 100*time.Millisecond) }()
	go func() { server <- n.server.Serve(run) }()
	ended := ""
	var cause error
	select {
	case <-ctx.Done():
	case cause = <-watchdog:
		ended = "watchdog"
		if cause == nil {
			cause = errors.New("the independent watchdog client stopped")
		}
	case cause = <-manager:
		ended = "manager"
		if cause == nil {
			cause = errors.New("the local lifecycle monitor stopped")
		}
	case cause = <-server:
		ended = "server"
	}
	cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(n.config.StopTimeoutMS)*time.Millisecond)
	defer stop()
	stopErr := n.manager.Shutdown(cleanup)
	cancel()
	failures := []error{cause, stopErr}
	for name, result := range map[string]<-chan error{"watchdog": watchdog, "manager": manager, "server": server} {
		if name == ended {
			continue
		}
		select {
		case err := <-result:
			failures = append(failures, err)
		case <-cleanup.Done():
			return errors.Join(errors.Join(failures...), cleanup.Err())
		}
	}
	failures = append(failures, n.Close(cleanup))
	return errors.Join(failures...)
}
func (n *Node) waitHeartbeat(ctx context.Context, result <-chan error) error {
	ready := time.NewTicker(time.Millisecond)
	defer ready.Stop()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for !n.watchdog.Ready() {
		select {
		case err := <-result:
			return errors.Join(errors.New("the independent watchdog client did not start"), err)
		case <-ready.C:
		case <-deadline.C:
			return errors.New("the independent watchdog client did not start")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
func (n *Node) Close(ctx context.Context) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(n.config.StopTimeoutMS)*time.Millisecond)
	defer cancel()
	var failures []error
	if n.manager != nil {
		failures = append(failures, n.manager.Shutdown(cleanup))
	}
	if n.backend != nil {
		failures = append(failures, n.backend.Close(cleanup))
	}
	if n.journal != nil {
		failures = append(failures, n.journal.Close())
	}
	if n.owner != nil {
		failures = append(failures, n.owner.Close())
	}
	if n.authority != nil {
		n.authority.Close()
	}
	return errors.Join(failures...)
}
