// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodedns

import (
	"context"
	"errors"
	"sort"

	"alloyium.local/kernel-poc/internal/dnslease"
	"alloyium.local/kernel-poc/internal/policy"
	"golang.org/x/net/dns/dnsmessage"
)

func questions(network policy.Network) ([][]byte, error) {
	type question struct {
		name string
		kind dnsmessage.Type
	}
	values := []question{}
	seen := map[question]bool{}
	for _, rule := range network.Rules {
		if rule.Destination.Kind != "hostname" {
			continue
		}
		kind := dnsmessage.TypeA
		if rule.Family == "ipv6" {
			kind = dnsmessage.TypeAAAA
		}
		q := question{rule.Destination.Value + ".", kind}
		if !seen[q] {
			seen[q] = true
			values = append(values, q)
		}
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].name != values[j].name {
			return values[i].name < values[j].name
		}
		return values[i].kind < values[j].kind
	})
	out := make([][]byte, 0, len(values))
	for _, value := range values {
		name, err := dnsmessage.NewName(value.name)
		if err != nil {
			return nil, err
		}
		message := dnsmessage.Message{Header: dnsmessage.Header{ID: 1, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: value.kind, Class: dnsmessage.ClassINET}}}
		wire, err := message.Pack()
		if err != nil {
			return nil, err
		}
		out = append(out, wire)
	}
	return out, nil
}
func (c *Coordinator) resolve(ctx context.Context, last dnslease.Snapshot, publish func(dnslease.Snapshot) error) (dnslease.Snapshot, error, bool) {
	var failures []error
	for _, wire := range c.questions {
		if err := ctx.Err(); err != nil {
			return last, err, true
		}
		now, err := c.live()
		if err != nil {
			return last, err, true
		}
		remaining := c.binding.DeadlineNS - now
		timeout := uint64(5e9)
		if remaining < timeout {
			timeout = remaining
		}
		queryCtx, cancel := context.WithTimeout(ctx, timeDuration(timeout))
		out := c.manager.Forward(queryCtx, c.binding, wire)
		cancel()
		if out.Changed {
			last = out.Snapshot
			if publish != nil {
				if err = publish(last); err != nil {
					return last, err, true
				}
			}
		}
		if out.Fatal {
			return last, errors.New(out.Error), true
		}
		if err = c.clock.failure(); err != nil {
			return last, err, true
		}
		if err = c.resolver.failure(); err != nil {
			return last, err, true
		}
		if !out.Changed {
			return last, errors.New("the declared DNS query returned no replacement snapshot"), true
		}
		if out.Error != "" {
			failures = append(failures, errors.New(out.Error))
		}
	}
	if err := ctx.Err(); err != nil {
		return last, err, true
	}
	return last, errors.Join(failures...), false
}
