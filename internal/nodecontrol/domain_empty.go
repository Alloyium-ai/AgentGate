// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodecontrol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

type DomainEmpty struct {
	Events         []byte `json:"events"`
	ReadbackDigest string `json:"readback_digest"`
	ObservedMonoNS uint64 `json:"observed_mono_ns,string"`
}

func (p DomainEmpty) Validate() error {
	if len(p.Events) == 0 || len(p.Events) > 4096 || p.ObservedMonoNS == 0 {
		return errors.New("the empty-domain raw readback is absent")
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(p.Events)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || seen[fields[0]] || (fields[0] != "populated" && fields[0] != "frozen") || (fields[1] != "0" && fields[1] != "1") {
			return errors.New("the empty-domain control differs")
		}
		seen[fields[0]] = true
		if fields[0] == "populated" && fields[1] != "0" {
			return errors.New("the domain remains populated")
		}
	}
	if !seen["populated"] {
		return errors.New("the domain population is absent")
	}
	sum := sha256.Sum256(append([]byte("agentgate-domain-empty-v1\n"), p.Events...))
	if hex.EncodeToString(sum[:]) != p.ReadbackDigest {
		return errors.New("the empty-domain digest differs")
	}
	return nil
}
