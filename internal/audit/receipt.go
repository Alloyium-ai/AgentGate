// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package audit

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"strings"

	"alloyium.local/kernel-poc/internal/grant"
)

func Countersign(dir string, authority ed25519.PrivateKey, node ed25519.PublicKey) (Seal, error) {
	var seal Seal
	token, err := readBounded(filepath.Join(dir, "grant.jws"))
	if err != nil {
		return seal, err
	}
	c, err := trustedClaims(string(token), authority.Public().(ed25519.PublicKey))
	if err != nil {
		return seal, err
	}
	data, err := readBounded(filepath.Join(dir, "terminal.json"))
	if err != nil {
		return seal, err
	}
	if err = json.Unmarshal(data, &seal); err != nil {
		return seal, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(seal.NodeSignature)
	if err != nil || !ed25519.Verify(node, manifestBytes(seal.Manifest), sig) {
		return seal, errors.New("node terminal signature failed")
	}
	m := seal.Manifest
	if m.Version != "alloyium-audit-v1" || m.GrantDigest != grant.Digest(token) || m.Generation != c.Generation || m.Boot != c.Boot {
		return seal, errors.New("terminal admission binding differs")
	}
	data, err = readBounded(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return seal, err
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		return seal, errors.New("truncated evidence")
	}
	head := grant.Digest(token)
	count, last := uint64(0), uint64(0)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		var entry Entry
		if err = json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return seal, err
		}
		n, err := strconv.ParseUint(entry.Decision.Sequence, 10, 64)
		if err != nil || n <= last {
			return seal, errors.New("invalid kernel sequence")
		}
		d := entry.Decision
		if d.Generation != c.Generation || d.Agent != c.Agent || d.Run != c.Run || d.Cgroup != c.Domain || entry.Previous != head || entry.Hash != chainHash(head, d) {
			return seal, errors.New("event admission binding or chain differs")
		}
		head = entry.Hash
		last = n
		count++
	}
	if err = scanner.Err(); err != nil {
		return seal, err
	}
	decisions, err := strconv.ParseUint(m.Decisions, 10, 64)
	if err != nil {
		return seal, err
	}
	lost, err := strconv.ParseUint(m.Lost, 10, 64)
	if err != nil {
		return seal, err
	}
	if m.Count != decimal(count) || m.Head != head || decisions < count || decisions-count != lost || last > decisions {
		return seal, errors.New("terminal completeness or declared loss differs")
	}
	seal.Receipt = base64.RawURLEncoding.EncodeToString(ed25519.Sign(authority, receiptBytes(seal)))
	return seal, nil
}
