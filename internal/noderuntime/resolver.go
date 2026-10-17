// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/dnslease"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"time"
)

// ResolverDigest binds the immutable TLS endpoint, trust roots and query timeout.
// It grants no DNS socket operation to the agent.
func ResolverDigest(e dnslease.ResolverEvidence) string {
	raw, _ := json.Marshal(e)
	sum := sha256.Sum256(append([]byte("AGENTGATE_NODE_RESOLVER_V1\n"), raw...))
	return hex.EncodeToString(sum[:])
}
func configuredResolver(c Config) (dnslease.Resolver, error) {
	if c.Resolver == nil {
		if c.ArtifactDigests["resolver"] != "" {
			return nil, errors.New("the pinned resolver has no explicit node configuration")
		}
		return nil, nil
	}
	r := c.Resolver
	address, err := netip.ParseAddrPort(r.Address)
	if err != nil || address.String() != r.Address || !hash64.MatchString(r.RootsFileSHA256) || r.TimeoutMS < 1 || r.TimeoutMS > 5000 {
		return nil, errors.New("the literal TLS resolver configuration is invalid")
	}
	roots, err := readOwned(r.RootsFile, 128*1024, false)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(roots)
	if hex.EncodeToString(sum[:]) != r.RootsFileSHA256 {
		return nil, errors.New("the resolver CA file differs from its explicit digest")
	}
	resolver, err := dnslease.NewTLSResolver(dnslease.TLSConfig{Address: address, ServerName: r.ServerName, RootPEM: roots, Timeout: time.Duration(r.TimeoutMS) * time.Millisecond})
	if err != nil {
		return nil, err
	}
	if c.ArtifactDigests["resolver"] != ResolverDigest(resolver.Evidence()) {
		return nil, errors.New("the resolver differs from the signed node artifact registry")
	}
	return resolver, nil
}
