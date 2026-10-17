// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dnslease_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/dnslease"
	"alloyium.local/kernel-poc/internal/dnslease/fixture"
	"golang.org/x/net/dns/dnsmessage"
)

func tlsQuery(t *testing.T) []byte {
	t.Helper()
	wire, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 72, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("api.example.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
func tlsServer(t *testing.T) *fixture.Server {
	t.Helper()
	server, err := fixture.Start(func(query []byte) ([]byte, error) {
		var q dnsmessage.Message
		if err := q.Unpack(query); err != nil {
			return nil, err
		}
		q.Response = true
		q.RecursionAvailable = true
		q.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 5}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 9}}}}
		return q.Pack()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return server
}

func TestOwnedTLSResolverVerifiesNameAndPinnedRoots(t *testing.T) {
	server := tlsServer(t)
	config := server.Config(time.Second)
	resolver, err := dnslease.NewTLSResolver(config)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := resolver.Exchange(context.Background(), tlsQuery(t))
	if err != nil {
		t.Fatal(err)
	}
	var message dnsmessage.Message
	if err = message.Unpack(reply); err != nil || !message.Response || message.ID != 72 {
		t.Fatal("framed TLS reply differs", err)
	}
	if server.Queries() != 1 || resolver.Evidence().Transport != "tls1.3" || len(resolver.Evidence().RootsSHA256) != 64 {
		t.Fatal("trusted transport evidence absent")
	}
	config.ServerName = "wrong.example.test"
	wrong, err := dnslease.NewTLSResolver(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrong.Exchange(context.Background(), tlsQuery(t)); err == nil {
		t.Fatal("wrong TLS server name accepted")
	}
	other := tlsServer(t)
	config = other.Config(time.Second)
	config.Address = server.Config(time.Second).Address
	wrong, err = dnslease.NewTLSResolver(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrong.Exchange(context.Background(), tlsQuery(t)); err == nil {
		t.Fatal("another fixture's CA authorized this resolver")
	}
	if server.Queries() != 1 {
		t.Fatal("unverified transport forwarded a DNS query")
	}
}

func TestTLSResolverRejectsImplicitTrustAndOversizedFrames(t *testing.T) {
	server := tlsServer(t)
	for name, change := range map[string]func(*dnslease.TLSConfig){"no-roots": func(c *dnslease.TLSConfig) { c.RootPEM = nil }, "bad-roots": func(c *dnslease.TLSConfig) { c.RootPEM = []byte("not a certificate") }, "no-timeout": func(c *dnslease.TLSConfig) { c.Timeout = 0 }, "large-timeout": func(c *dnslease.TLSConfig) { c.Timeout = 6 * time.Second }, "no-name": func(c *dnslease.TLSConfig) { c.ServerName = "" }} {
		t.Run(name, func(t *testing.T) {
			config := server.Config(time.Second)
			change(&config)
			if _, err := dnslease.NewTLSResolver(config); err == nil {
				t.Fatal("implicit resolver setting accepted")
			}
		})
	}
	large, err := fixture.Start(func([]byte) ([]byte, error) { return []byte(strings.Repeat("x", dnslease.MaxWire+1)), nil })
	if err != nil {
		t.Fatal(err)
	}
	defer large.Close()
	resolver, err := dnslease.NewTLSResolver(large.Config(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = resolver.Exchange(context.Background(), tlsQuery(t)); err == nil {
		t.Fatal("oversized TLS DNS frame accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = resolver.Exchange(ctx, tlsQuery(t)); err == nil {
		t.Fatal("cancelled DNS query proceeded")
	}
}
