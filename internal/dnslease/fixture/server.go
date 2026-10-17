// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package fixture supplies an owned loopback TLS DNS server for component
// witnesses. It supplies no production resolver or approved runtime template.
package fixture

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"alloyium.local/kernel-poc/internal/dnslease"
)

type Handler func([]byte) ([]byte, error)
type Server struct {
	listener    net.Listener
	root        []byte
	handler     Handler
	done        chan struct{}
	mu          sync.Mutex
	connections map[net.Conn]bool
	wg          sync.WaitGroup
	queries     atomic.Uint64
}

func Start(handler Handler) (*Server, error) {
	if handler == nil {
		return nil, fmt.Errorf("a synthetic DNS handler is required")
	}
	certificate, root, err := certificates()
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{listener: tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}), root: root, handler: handler, done: make(chan struct{}), connections: map[net.Conn]bool{}}
	go s.accept()
	return s, nil
}

func (s *Server) Config(timeout time.Duration) dnslease.TLSConfig {
	return dnslease.TLSConfig{Address: netip.MustParseAddrPort(s.listener.Addr().String()), ServerName: "resolver.example.test", RootPEM: append([]byte(nil), s.root...), Timeout: timeout}
}
func (s *Server) Queries() uint64 { return s.queries.Load() }

func (s *Server) Close() {
	_ = s.listener.Close()
	<-s.done
	s.mu.Lock()
	for connection := range s.connections {
		_ = connection.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) accept() {
	defer close(s.done)
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.connections[connection] = true
		s.mu.Unlock()
		s.wg.Add(1)
		go s.serve(connection)
	}
}

func (s *Server) serve(connection net.Conn) {
	defer s.wg.Done()
	defer func() { _ = connection.Close(); s.mu.Lock(); delete(s.connections, connection); s.mu.Unlock() }()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	var header [2]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return
	}
	length := int(binary.BigEndian.Uint16(header[:]))
	if length < 12 || length > dnslease.MaxWire {
		return
	}
	question := make([]byte, length)
	if _, err := io.ReadFull(connection, question); err != nil {
		return
	}
	s.queries.Add(1)
	reply, err := s.handler(question)
	if err != nil || len(reply) > 65535 {
		return
	}
	binary.BigEndian.PutUint16(header[:], uint16(len(reply)))
	if _, err = connection.Write(header[:]); err == nil {
		_, _ = connection.Write(reply)
	}
}

func certificates() (tls.Certificate, []byte, error) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Owned DNS fixture CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, IsCA: true, BasicConstraintsValid: true}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootPublic, rootPrivate)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "resolver.example.test"}, DNSNames: []string{"resolver.example.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, leafPublic, rootPrivate)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafPrivate}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), nil
}
