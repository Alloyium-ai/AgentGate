// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dnslease

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type ownerSet struct {
	alias     string
	addresses []netip.Addr
	ttl       uint32
}

type validatedReply struct {
	message   dnsmessage.Message
	addresses []netip.Addr
	chain     []string
	expires   uint64
	digest    string
}

func validateReply(query dnsmessage.Message, wire []byte, start, now, deadline uint64) (validatedReply, error) {
	var out validatedReply
	if err := boundedWire(wire); err != nil {
		return out, err
	}
	if err := out.message.Unpack(wire); err != nil {
		return out, fmt.Errorf("invalid DNS reply: %w", err)
	}
	m := out.message
	if !m.Response || m.ID != query.ID || m.OpCode != 0 || m.Truncated || binary.BigEndian.Uint16(wire[2:4])&0x40 != 0 || m.RecursionDesired != query.RecursionDesired || len(m.Questions) != 1 || m.Questions[0] != query.Questions[0] || len(m.Authorities) != 0 || len(m.Additionals) != 0 {
		return out, fmt.Errorf("DNS reply does not match the authorized question")
	}
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) == 0 {
		return out, fmt.Errorf("negative or empty DNS reply")
	}
	sets, err := answerSets(m)
	if err != nil {
		return out, err
	}
	chain, addresses, ttl, err := completeChain(query.Questions[0].Name.String(), sets)
	if err != nil {
		return out, err
	}
	if start > now || now >= deadline {
		return out, fmt.Errorf("DNS reply arrived outside the job deadline")
	}
	duration := uint64(ttl) * uint64(time.Second)
	out.expires = deadline
	if duration < deadline-start {
		out.expires = start + duration
	}
	if out.expires <= now {
		return out, fmt.Errorf("DNS reply TTL already expired")
	}
	out.chain, out.addresses = chain, addresses
	sum := sha256.Sum256(wire)
	out.digest = hex.EncodeToString(sum[:])
	remaining := uint32((out.expires - now) / uint64(time.Second))
	for i := range out.message.Answers {
		out.message.Answers[i].Header.TTL = remaining
	}
	return out, nil
}

func answerSets(message dnsmessage.Message) (map[string]*ownerSet, error) {
	sets := map[string]*ownerSet{}
	for _, resource := range message.Answers {
		name := resource.Header.Name.String()
		if !canonicalDNSName(name) || resource.Header.Class != dnsmessage.ClassINET || resource.Header.TTL == 0 {
			return nil, fmt.Errorf("unsupported DNS answer owner, class, or zero TTL")
		}
		set := sets[name]
		if set == nil {
			set = &ownerSet{ttl: resource.Header.TTL}
			sets[name] = set
		}
		if resource.Header.TTL < set.ttl {
			set.ttl = resource.Header.TTL
		}
		if err := addResource(set, resource, message.Questions[0].Type); err != nil {
			return nil, err
		}
	}
	return sets, nil
}

func addResource(set *ownerSet, resource dnsmessage.Resource, questionType dnsmessage.Type) error {
	var address netip.Addr
	switch body := resource.Body.(type) {
	case *dnsmessage.CNAMEResource:
		if resource.Header.Type != dnsmessage.TypeCNAME || set.alias != "" || len(set.addresses) != 0 || !canonicalDNSName(body.CNAME.String()) {
			return fmt.Errorf("ambiguous or unsupported CNAME answer")
		}
		set.alias = body.CNAME.String()
		return nil
	case *dnsmessage.AResource:
		if questionType != dnsmessage.TypeA || resource.Header.Type != dnsmessage.TypeA {
			return fmt.Errorf("DNS answer address family differs")
		}
		address = netip.AddrFrom4(body.A)
	case *dnsmessage.AAAAResource:
		if questionType != dnsmessage.TypeAAAA || resource.Header.Type != dnsmessage.TypeAAAA {
			return fmt.Errorf("DNS answer address family differs")
		}
		address = netip.AddrFrom16(body.AAAA)
	default:
		return fmt.Errorf("unsupported DNS answer type")
	}
	if set.alias != "" || address.IsUnspecified() || address.IsMulticast() || address.Is4In6() || address.IsLinkLocalUnicast() || address == netip.MustParseAddr("255.255.255.255") {
		return fmt.Errorf("unsupported or ambiguous DNS address")
	}
	set.addresses = append(set.addresses, address)
	return nil
}

func completeChain(question string, sets map[string]*ownerSet) ([]string, []netip.Addr, uint32, error) {
	name := question
	seen := map[string]bool{}
	chain := []string{}
	ttl := ^uint32(0)
	for len(chain) < MaxChain {
		if seen[name] {
			return nil, nil, 0, fmt.Errorf("cyclic CNAME chain")
		}
		seen[name] = true
		chain = append(chain, strings.TrimSuffix(name, "."))
		set := sets[name]
		if set == nil {
			return nil, nil, 0, fmt.Errorf("incomplete CNAME chain")
		}
		if set.ttl < ttl {
			ttl = set.ttl
		}
		if set.alias != "" {
			name = set.alias
			continue
		}
		if len(set.addresses) == 0 || len(seen) != len(sets) {
			return nil, nil, 0, fmt.Errorf("unrelated or absent terminal DNS answer")
		}
		sort.Slice(set.addresses, func(i, j int) bool { return set.addresses[i].Less(set.addresses[j]) })
		addresses := set.addresses[:0]
		for _, address := range set.addresses {
			if len(addresses) == 0 || addresses[len(addresses)-1] != address {
				addresses = append(addresses, address)
			}
		}
		return chain, addresses, ttl, nil
	}
	return nil, nil, 0, fmt.Errorf("CNAME depth exceeds the target limit")
}

func canonicalDNSName(name string) bool {
	return strings.HasSuffix(name, ".") && canonicalHostname(strings.TrimSuffix(name, "."))
}
