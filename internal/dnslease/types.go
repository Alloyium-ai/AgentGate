// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package dnslease validates trusted DNS replies for one immutable job binding.
// It grants no agent DNS operation and publishes no kernel map by itself.
package dnslease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"

	"alloyium.local/kernel-poc/internal/netrules"
	"alloyium.local/kernel-poc/internal/policy"
)

const (
	MaxWire          = 4096
	MaxAnswers       = 64
	MaxChain         = 9
	MaxLeaseRevision = uint64(^uint32(0))
)

// Binding comes from the trusted grant owner. PolicySHA256 names the signed
// policy document; NetworkDigest separately identifies the unchanged rules.
type Binding struct {
	JobID                            string
	DomainID, Generation, DeadlineNS uint64
	PolicySHA256                     string
}

type ResolverEvidence struct {
	Transport, Address, ServerName, RootsSHA256 string
	TimeoutMS                                   int64
}

// Resolver is a trusted dependency, not an agent-provided resolver selection.
type Resolver interface {
	Exchange(context.Context, []byte) ([]byte, error)
	Evidence() ResolverEvidence
}

type Clock func() (uint64, error)

type Config struct {
	Binding  Binding
	Network  policy.Network
	Resolver Resolver
	Now      Clock
}

type Record struct {
	RuleID, Hostname string
	Address          netip.Addr
	Chain            []string
	ExpiresNS        uint64
	ReplySHA256      string
	Resolver         ResolverEvidence
}

// Outcome always requires publishing a nonzero-revision Snapshot when Changed
// is true, including an authorized query failure. Error describes that failure.
type Outcome struct {
	Changed  bool
	Fatal    bool
	Snapshot Snapshot
	Response []byte
	Error    string
}

func NetworkDigest(network policy.Network) string {
	raw, _ := json.Marshal(network)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func digestString(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func canonicalHostname(value string) bool {
	if len(value) == 0 || len(value) > 253 || value != strings.ToLower(value) {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

func cloneRecords(records []Record) []Record {
	out := append([]Record(nil), records...)
	for i := range out {
		out[i].Chain = append([]string(nil), out[i].Chain...)
	}
	return out
}

func leases(records []Record) []netrules.Lease {
	out := make([]netrules.Lease, 0, len(records))
	for _, record := range records {
		out = append(out, netrules.Lease{RuleID: record.RuleID, Hostname: record.Hostname, Address: record.Address, Chain: append([]string(nil), record.Chain...), ExpiresNS: record.ExpiresNS})
	}
	return out
}
