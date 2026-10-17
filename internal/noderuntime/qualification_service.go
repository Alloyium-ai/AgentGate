// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"runtime"
	"sync"
	"time"
)

type qualificationListener struct {
	conn     net.Conn
	once     sync.Once
	mu       sync.Mutex
	accepted bool
	done     chan struct{}
}
type qualificationConn struct {
	net.Conn
	owner *qualificationListener
}

func (c *qualificationConn) Close() error {
	err := c.Conn.Close()
	c.owner.once.Do(func() { close(c.owner.done) })
	return err
}
func (l *qualificationListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.accepted {
		l.accepted = true
		l.mu.Unlock()
		return &qualificationConn{Conn: l.conn, owner: l}, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, net.ErrClosed
}
func (l *qualificationListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.conn.Close()
}
func (l *qualificationListener) Addr() net.Addr { return l.conn.LocalAddr() }

// RunQualificationFixture accepts only the sealed start descriptor and two
// root-parent socket pairs. This process exposes no normal admission route.
func RunQualificationFixture(ctx context.Context) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	startFile := os.NewFile(3, "sealed fixed qualification start")
	defer startFile.Close()
	start, err := readQualificationStart(startFile)
	if err != nil {
		return err
	}
	return runQualificationNode(ctx, start, nil)
}

func runQualificationNode(ctx context.Context, start QualificationStart, version *lifecycle.QualificationVersionSpec) error {
	var err error
	if err = verifyQualificationParent(start); err != nil {
		return err
	}
	if err = unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return err
	}
	if err = verifyQualificationParent(start); err != nil {
		return err
	}
	var connections []net.Conn
	defer func() {
		for _, conn := range connections {
			_ = conn.Close()
		}
	}()
	for _, fd := range []uintptr{4, 5} {
		f := os.NewFile(fd, "inherited fixed qualification socket")
		conn, e := inheritedQualificationConn(f, start.Parent)
		_ = f.Close()
		if e != nil {
			return e
		}
		connections = append(connections, conn)
	}
	config, err := ReadConfig(start.NodeConfigFile)
	if err != nil {
		return err
	}
	if err = verifyQualificationParent(start); err != nil {
		return err
	}
	factory := func(s *Sources) (Authority, error) {
		if version != nil {
			return newQualificationAuthorityPurpose(connections[1], s, start.Spec, lifecycle.QualificationVersionPurpose), nil
		}
		return newQualificationAuthority(connections[1], s, start.Spec), nil
	}
	var n *Node
	if version != nil {
		n, err = newNodeWithQualification(ctx, config, factory, nil, version)
	} else {
		n, err = newNode(ctx, config, factory, &start.Spec)
	}
	if err != nil {
		return err
	}
	return n.serveQualificationSession(ctx, start, connections[0], version)
}

func (n *Node) serveQualification(ctx context.Context, start QualificationStart, conn net.Conn) (err error) {
	return n.serveQualificationSession(ctx, start, conn, nil)
}

func (n *Node) serveQualificationSession(ctx context.Context, start QualificationStart, conn net.Conn, version *lifecycle.QualificationVersionSpec) (err error) {
	if n.fixture == nil || n.server != nil {
		return errors.New("the fixed fixture service scope differs")
	}
	if (version != nil) != (n.fixture.Purpose() == lifecycle.QualificationVersionPurpose) {
		return errors.New("the node qualification session purpose differs")
	}
	run, cancel := context.WithCancel(ctx)
	defer cancel()
	session := &qualificationSession{node: n, spec: start.Spec, ctx: run, version: version}
	watchdog := make(chan error, 1)
	manager := make(chan error, 1)
	watchDone, managerDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(watchDone); watchdog <- n.watchdog.Run(run) }()
	go func() { defer close(managerDone); manager <- n.manager.Watch(run, 100*time.Millisecond) }()
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(n.config.StopTimeoutMS)*time.Millisecond)
		defer stop()
		err = errors.Join(err, n.manager.Shutdown(cleanup))
		cancel()
		session.mu.Lock()
		done := session.waitDone
		session.mu.Unlock()
		if done != nil {
			select {
			case <-done:
			case <-cleanup.Done():
				err = errors.Join(err, cleanup.Err())
			}
		}
		for _, done := range []<-chan struct{}{watchDone, managerDone} {
			select {
			case <-done:
			case <-cleanup.Done():
				err = errors.Join(err, cleanup.Err())
			}
		}
		err = errors.Join(err, n.Close(cleanup))
	}()
	if err = n.waitHeartbeat(run, watchdog); err != nil {
		return err
	}
	listener := &qualificationListener{conn: conn, done: make(chan struct{})}
	server, err := qualificationCommandServer(run, session, n.config.RequestTimeoutMS)
	if err != nil {
		return err
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	defer server.Close()
	defer listener.Close()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-listener.done:
		return errors.New("the fixed fixture parent connection closed")
	case e := <-watchdog:
		return errors.Join(errors.New("the fixed fixture watchdog stopped"), e)
	case e := <-manager:
		return errors.Join(errors.New("the fixed fixture lifecycle monitor stopped"), e)
	case e := <-served:
		return errors.Join(errors.New("the fixed fixture command server stopped"), e)
	}
}
