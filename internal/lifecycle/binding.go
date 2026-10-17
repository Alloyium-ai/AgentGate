// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var capabilityID = regexp.MustCompile(`^[a-z][a-z0-9_.-]+\.v[1-9][0-9]*$`)
var ErrConflict = errors.New("lifecycle journal revision conflict")
var ErrReplay = errors.New("lifecycle generation or run replay")
var ErrNotFound = errors.New("lifecycle run is unknown")
var ErrNotReady = errors.New("lifecycle reconciliation is required")

type Identity struct{ NodeID, BootID string }

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(raw) == value
}

func (b Binding) validate(preparing bool) error {
	for _, id := range []string{b.AgentID, b.GrantID, b.RunID, b.NodeID, b.BootID} {
		if !identifier.MatchString(id) {
			return errors.New("lifecycle identity is missing or invalid")
		}
	}
	key, err := base64.RawURLEncoding.DecodeString(b.AgentKey)
	if err != nil || len(key) != 32 || base64.RawURLEncoding.EncodeToString(key) != b.AgentKey {
		return errors.New("lifecycle agent key is invalid")
	}
	for _, digest := range []string{b.JobDigest, b.PolicyDigest, b.SchemaDigest, b.CompilerDigest} {
		if !validDigest(digest) {
			return errors.New("lifecycle digest is invalid")
		}
	}
	if len(b.ArtifactDigests) == 0 || len(b.ArtifactDigests) > 64 {
		return errors.New("lifecycle artifact measurements are required")
	}
	for name, digest := range b.ArtifactDigests {
		if !identifier.MatchString(name) || !validDigest(digest) {
			return errors.New("lifecycle artifact measurement is invalid")
		}
	}
	if (!preparing && b.CgroupID == 0) || b.Generation == 0 || b.Generation > math.MaxInt64 || b.DeadlineNS == 0 {
		return errors.New("lifecycle domain, generation and deadline are required")
	}
	return nil
}

func (b Binding) same(other Binding) bool { return reflect.DeepEqual(b, other) }
func clone[T any](value T) T {
	raw, _ := json.Marshal(value)
	var out T
	_ = json.Unmarshal(raw, &out)
	return out
}

// EvidenceDigest binds the complete readback without its digest field.
func EvidenceDigest(e Evidence) string {
	e.Digest = ""
	raw, _ := json.Marshal(e)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func checkEvidence(e Evidence, b Binding, phase string) error {
	if !e.Binding.same(b) || e.Phase != phase {
		return errors.New("lifecycle evidence binding or phase differs")
	}
	if !validDigest(e.ReadbackDigest) || e.Digest != EvidenceDigest(e) {
		return errors.New("lifecycle kernel readback evidence is invalid")
	}
	if phase == "stopped" {
		if b.CgroupID == 0 && !e.NoDomain {
			return errors.New("an unallocated stop requires explicit no-domain proof")
		}
		if !e.Empty || !e.Terminated || !e.RightsRemoved || e.Released {
			return errors.New("lifecycle domain termination is unconfirmed")
		}
		return nil
	}
	if !e.MandatoryHooks || e.RightsRemoved || e.Lost != 0 {
		return errors.New("lifecycle mandatory enforcement or complete evidence is unavailable")
	}
	if (phase == "installed" || phase == "active") && (e.EffectiveDeadlineNS == 0 || e.EffectiveDeadlineNS > b.DeadlineNS) {
		return errors.New("lifecycle effective grant cutoff is absent or widened")
	}
	if phase == "active" || phase == "recovered" {
		if !e.Released || e.Quarantined {
			return errors.New("lifecycle active domain readback differs")
		}
	} else if !e.Quarantined || e.Released {
		return errors.New("lifecycle workload is not held in quarantine")
	}
	return nil
}

func checkCapabilities(e Evidence, required []string) error {
	if len(required) == 0 || len(required) > 64 {
		return errors.New("lifecycle required capabilities are missing")
	}
	seen := map[string]bool{}
	for _, id := range required {
		if !capabilityID.MatchString(id) || seen[id] {
			return errors.New("lifecycle capability declaration is invalid")
		}
		seen[id] = true
		capability, ok := e.Capabilities[id]
		if !ok || capability.State != "qualified" || len(capability.Mechanisms) == 0 || !validDigest(capability.EvidenceDigest) {
			return fmt.Errorf("lifecycle required capability %s is unqualified", id)
		}
	}
	return nil
}

func recordTransition(prior, next Record) error {
	if prior.PreparationDeadlineNS != next.PreparationDeadlineNS {
		return errors.New("the preparation lease is immutable")
	}
	old := prior.Binding
	current := next.Binding
	if old.CgroupID == 0 && ((prior.State == "preparing" && (next.State == "quarantined" || next.State == "stop-pending")) || (prior.State == "stop-pending" && next.State == "stopped" && prior.Authorization == nil && next.Authorization == nil && prior.Process == nil && next.Process == nil)) {
		old.CgroupID = current.CgroupID
	}
	if !old.same(current) {
		return errors.New("lifecycle journal binding is immutable")
	}
	transitions := map[string][]string{
		"preparing": {"quarantined", "stop-pending"}, "quarantined": {"placing", "stop-pending"},
		"placing": {"placed", "stop-pending"}, "placed": {"installing", "stop-pending"},
		"installing": {"installed", "stop-pending"}, "installed": {"release-pending", "stop-pending"},
		"release-pending": {"active", "stop-pending"}, "active": {"active", "stop-pending"},
		"stop-pending": {"stop-pending", "stopped"}, "stopped": {"stopped"},
	}
	allowed := false
	for _, state := range transitions[prior.State] {
		if state == next.State {
			allowed = true
			break
		}
	}
	if !allowed {
		return errors.New("lifecycle journal transition is invalid")
	}
	if prior.Watchdog != nil && !reflect.DeepEqual(prior.Watchdog, next.Watchdog) {
		return errors.New("watchdog custody acknowledgement is immutable")
	}
	if prior.Watchdog == nil && next.Watchdog != nil && (prior.State != "preparing" || next.State != "quarantined") {
		return errors.New("watchdog custody must precede workload placement")
	}
	if prior.Authorization != nil && !reflect.DeepEqual(prior.Authorization, next.Authorization) {
		return errors.New("lifecycle authorization is immutable")
	}
	if prior.Process != nil && !reflect.DeepEqual(prior.Process, next.Process) {
		return errors.New("lifecycle process identity is immutable")
	}
	if len(next.Evidence) < len(prior.Evidence) || !reflect.DeepEqual(next.Evidence[:len(prior.Evidence)], prior.Evidence) {
		return errors.New("lifecycle evidence is append-only")
	}
	return nil
}

// Validate checks a transport binding without authorizing its use.
func (b Binding) Validate(preparing bool) error                { return b.validate(preparing) }
func VerifyReadback(e Evidence, b Binding, phase string) error { return checkEvidence(e, b, phase) }
func RequireCapabilities(e Evidence, required []string) error  { return checkCapabilities(e, required) }
