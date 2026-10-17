// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package audit

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"alloyium.local/kernel-poc/internal/grant"
	"alloyium.local/kernel-poc/internal/kernel"
)

const maxBytes = 4 << 20
const Complete = "VALID_COMPLETE"
const Incomplete = "INCOMPLETE"
const Tampered = "TAMPERED"
const UnknownKey = "UNKNOWN_KEY"

type Decision struct {
	Sequence   string `json:"seq"`
	Generation string `json:"generation"`
	Agent      string `json:"agent"`
	Run        string `json:"run"`
	Cgroup     string `json:"cgroup"`
	MonoNS     string `json:"mono_ns"`
	PID        uint32 `json:"pid"`
	UID        uint32 `json:"uid"`
	Hook       uint32 `json:"hook"`
	Allowed    bool   `json:"allowed"`
	Path       string `json:"path"`
	IP         uint32 `json:"ip"`
	Port       uint32 `json:"port"`
}
type Entry struct {
	Decision Decision `json:"decision"`
	Previous string   `json:"prev"`
	Hash     string   `json:"hash"`
}
type Manifest struct {
	Version      string `json:"version"`
	GrantDigest  string `json:"grant_sha256"`
	Generation   string `json:"generation"`
	Boot         string `json:"boot"`
	Count        string `json:"count"`
	Decisions    string `json:"decisions"`
	Lost         string `json:"lost"`
	Head         string `json:"head"`
	Outcome      string `json:"outcome"`
	ObjectDigest string `json:"bpf_sha256"`
}
type Seal struct {
	Manifest      Manifest `json:"manifest"`
	NodeSignature string   `json:"node_signature"`
	Receipt       string   `json:"authority_receipt"`
}

func decimal(n uint64) string { return strconv.FormatUint(n, 10) }
func chainHash(previous string, d Decision) string {
	body, _ := json.Marshal(d)
	return grant.Digest([]byte("alloyium-audit-event-v1\n" + previous + "\n" + string(body)))
}
func manifestBytes(m Manifest) []byte {
	body, _ := json.Marshal(m)
	return append([]byte("alloyium-audit-terminal-v1\n"), body...)
}
func receiptBytes(s Seal) []byte {
	return append(manifestBytes(s.Manifest), []byte("\n"+s.NodeSignature)...)
}

func durable(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

func Save(dir, token string, c grant.Claims, events []kernel.Event, stats kernel.Counters, keys grant.Keys, objectDigest, outcome string) error {
	if len(events) > 10000 {
		return errors.New("audit saturation: event count exceeded")
	}
	if err := durable(filepath.Join(dir, "grant.jws"), []byte(token)); err != nil {
		return err
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Sequence < events[j].Sequence })
	head := grant.Digest([]byte(token))
	var stream strings.Builder
	for _, e := range events {
		d := Decision{decimal(e.Sequence), decimal(e.Generation), c.Agent, c.Run, decimal(e.Cgroup), decimal(e.MonoNS), e.PID, e.UID, e.Hook, e.Allowed == 1, strings.TrimRight(string(e.Path[:]), "\x00"), e.IP, e.Port}
		entry := Entry{d, head, chainHash(head, d)}
		body, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		stream.Write(body)
		stream.WriteByte('\n')
		head = entry.Hash
		if stream.Len() > maxBytes {
			return errors.New("audit saturation: spool byte limit exceeded")
		}
	}
	if err := durable(filepath.Join(dir, "events.jsonl"), []byte(stream.String())); err != nil {
		return err
	}
	m := Manifest{"alloyium-audit-v1", grant.Digest([]byte(token)), c.Generation, c.Boot, decimal(uint64(len(events))), decimal(stats.Decisions), decimal(stats.Lost), head, outcome, objectDigest}
	seal := Seal{Manifest: m}
	seal.NodeSignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(keys.Node, manifestBytes(m)))
	// The pinned local authority binds its receipt to the exact node commitment.
	if len(keys.Authority) == ed25519.PrivateKeySize {
		seal.Receipt = base64.RawURLEncoding.EncodeToString(ed25519.Sign(keys.Authority, receiptBytes(seal)))
	}
	body, err := json.Marshal(seal)
	if err != nil {
		return err
	}
	if err = durable(filepath.Join(dir, "terminal.json"), body); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func readBounded(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > maxBytes {
		return nil, errors.New("audit artifact exceeds limit")
	}
	return os.ReadFile(path)
}

func trustedClaims(token string, key ed25519.PublicKey) (grant.Claims, error) {
	var c grant.Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, errors.New("malformed grant")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(body, &c); err != nil {
		return c, err
	}
	// Historic evidence remains verifiable after expiry. Verify validity at issuance.
	return grant.Verify(token, key, c, c.Issued)
}

func Verify(dir string, trust grant.Trust) (string, error) {
	authority, err := grant.Public(trust.Authority)
	if err != nil {
		return UnknownKey, err
	}
	node, err := grant.Public(trust.Node)
	if err != nil {
		return UnknownKey, err
	}
	token, err := readBounded(filepath.Join(dir, "grant.jws"))
	if err != nil {
		return Incomplete, err
	}
	c, err := trustedClaims(string(token), authority)
	if err != nil {
		return Tampered, err
	}
	data, err := readBounded(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return Incomplete, err
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		return Incomplete, errors.New("truncated final audit entry")
	}
	head := grant.Digest(token)
	count := uint64(0)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		var entry Entry
		if err = json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return Tampered, err
		}
		count++
		d := entry.Decision
		if d.Sequence != decimal(count) {
			return Incomplete, errors.New("kernel decision sequence gap")
		}
		if d.Generation != c.Generation || d.Agent != c.Agent || d.Run != c.Run || d.Cgroup != c.Domain {
			return Tampered, errors.New("cross-run audit entry")
		}
		if entry.Previous != head || entry.Hash != chainHash(head, d) {
			return Tampered, fmt.Errorf("chain differs at sequence %d", count)
		}
		head = entry.Hash
	}
	if err = scanner.Err(); err != nil {
		return Incomplete, err
	}
	terminal, err := readBounded(filepath.Join(dir, "terminal.json"))
	if err != nil {
		return Incomplete, errors.New("terminal seal absent")
	}
	var seal Seal
	if err = json.Unmarshal(terminal, &seal); err != nil {
		return Tampered, err
	}
	nodeSig, err := base64.RawURLEncoding.DecodeString(seal.NodeSignature)
	if err != nil || !ed25519.Verify(node, manifestBytes(seal.Manifest), nodeSig) {
		return Tampered, errors.New("node terminal signature failed")
	}
	receipt, err := base64.RawURLEncoding.DecodeString(seal.Receipt)
	if err != nil || !ed25519.Verify(authority, receiptBytes(seal), receipt) {
		return Tampered, errors.New("authority receipt failed")
	}
	m := seal.Manifest
	if m.Version != "alloyium-audit-v1" || m.GrantDigest != grant.Digest(token) || m.Generation != c.Generation || m.Boot != c.Boot {
		return Tampered, errors.New("terminal run binding differs")
	}
	if m.Count != decimal(count) || m.Head != head {
		return Incomplete, errors.New("retained suffix differs from terminal commitment")
	}
	if m.Lost != "0" || m.Decisions != m.Count || m.Outcome != "completed" {
		return Incomplete, errors.New("terminal reports evidence loss or an incomplete lifecycle")
	}
	return Complete, nil
}
