// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/dnslease"
	"alloyium.local/kernel-poc/internal/dnslease/fixture"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"golang.org/x/net/dns/dnsmessage"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func resolverConfig(t *testing.T) (Config, *fixture.Server) {
	t.Helper()
	server, err := fixture.Start(func(raw []byte) ([]byte, error) {
		var m dnsmessage.Message
		if err := m.Unpack(raw); err != nil {
			return nil, err
		}
		m.Response = true
		return m.Pack()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	tls := server.Config(time.Second)
	path := filepath.Join(t.TempDir(), "resolver-ca.crt")
	if err = os.WriteFile(path, tls.RootPEM, 0644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(tls.RootPEM)
	resolver, err := dnslease.NewTLSResolver(tls)
	if err != nil {
		t.Fatal(err)
	}
	return Config{Resolver: &ResolverConfig{Address: tls.Address.String(), ServerName: tls.ServerName, RootsFile: path, RootsFileSHA256: hex.EncodeToString(sum[:]), TimeoutMS: 1000}, ArtifactDigests: map[string]string{"resolver": ResolverDigest(resolver.Evidence())}}, server
}
func TestConfiguredResolverUsesOnlyItsPinnedTLSSettings(t *testing.T) {
	c, server := resolverConfig(t)
	resolver, err := configuredResolver(c)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 42}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("api.example.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = resolver.Exchange(context.Background(), wire); err != nil {
		t.Fatal(err)
	}
	if server.Queries() != 1 || ResolverDigest(resolver.Evidence()) != c.ArtifactDigests["resolver"] {
		t.Fatal("the configured endpoint or trust changed")
	}
	if resolver, err = configuredResolver(Config{}); err != nil || resolver != nil {
		t.Fatal("an absent resolver gained an implicit transport")
	}
}
func TestConfiguredResolverRejectsChangedOrImplicitCustody(t *testing.T) {
	for name, change := range map[string]func(*Config){"hostname-address": func(c *Config) { c.Resolver.Address = "resolver.example.test:853" }, "missing-root-digest": func(c *Config) { c.Resolver.RootsFileSHA256 = "" }, "changed-root": func(c *Config) { c.Resolver.RootsFileSHA256 = strings.Repeat("0", 64) }, "missing-artifact": func(c *Config) { delete(c.ArtifactDigests, "resolver") }, "wrong-artifact": func(c *Config) { c.ArtifactDigests["resolver"] = strings.Repeat("0", 64) }, "timeout": func(c *Config) { c.Resolver.TimeoutMS = 5001 }, "wrong-name": func(c *Config) { c.Resolver.ServerName = "other.example.test" }, "missing-config": func(c *Config) { c.Resolver = nil }, "linked-roots": func(c *Config) {
		link := c.Resolver.RootsFile + ".link"
		if err := os.Symlink(c.Resolver.RootsFile, link); err != nil {
			t.Fatal(err)
		}
		c.Resolver.RootsFile = link
	}, "writable-roots": func(c *Config) {
		if err := os.Chmod(c.Resolver.RootsFile, 0666); err != nil {
			t.Fatal(err)
		}
	}} {
		t.Run(name, func(t *testing.T) {
			c, _ := resolverConfig(t)
			change(&c)
			if _, err := configuredResolver(c); err == nil {
				t.Fatal("changed or implicit resolver custody passed")
			}
		})
	}
}
