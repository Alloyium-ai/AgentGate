// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
)

const QualificationScopeVersion = "agentgate.qualification-scope.v1"

// QualificationScope prevents behavior evidence for one policy or artifact set
// from authorizing another policy. The outer target signature binds this scope.
type QualificationScope struct {
	Protocol             string   `json:"protocol"`
	ProducerSHA256       string   `json:"producer_sha256"`
	CompilerSHA256       string   `json:"compiler_sha256"`
	ArtifactsSHA256      string   `json:"artifacts_sha256"`
	PolicyDigests        []string `json:"policy_digests"`
	RequiredCapabilities []string `json:"required_capabilities"`
	ContractsSHA256      string   `json:"contracts_sha256"`
	EvidenceSHA256       string   `json:"evidence_sha256"`
}

func (s QualificationScope) Validate() error {
	if s.Protocol != QualificationScopeVersion || !hash64.MatchString(s.ProducerSHA256) || !hash64.MatchString(s.CompilerSHA256) || !hash64.MatchString(s.ArtifactsSHA256) || !hash64.MatchString(s.ContractsSHA256) || !hash64.MatchString(s.EvidenceSHA256) || len(s.PolicyDigests) == 0 || len(s.PolicyDigests) > 64 || len(s.RequiredCapabilities) == 0 || len(s.RequiredCapabilities) > 64 {
		return errors.New("the qualification scope is absent or invalid")
	}
	for i, d := range s.PolicyDigests {
		if !hash64.MatchString(d) || i > 0 && s.PolicyDigests[i-1] >= d {
			return errors.New("qualification policy digests must be unique and sorted")
		}
	}
	catalog, err := CapabilityIDs()
	if err != nil {
		return err
	}
	for i, id := range s.RequiredCapabilities {
		if !containsSorted(catalog, id) || i > 0 && s.RequiredCapabilities[i-1] >= id {
			return errors.New("qualification capabilities must be registered, unique and sorted")
		}
	}
	return nil
}

func containsSorted(values []string, value string) bool {
	i := sort.SearchStrings(values, value)
	return i < len(values) && values[i] == value
}

func ArtifactSetDigest(artifacts map[string]string) (string, error) {
	if len(artifacts) == 0 || len(artifacts) > 64 {
		return "", errors.New("qualification artifacts are absent or exceed the bound")
	}
	for name, digest := range artifacts {
		if name == "" || len(name) > 128 || !hash64.MatchString(digest) {
			return "", errors.New("qualification artifact identity is invalid")
		}
	}
	raw, err := json.Marshal(artifacts)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("AGENTGATE_QUALIFICATION_ARTIFACTS_V1\n"), raw...))
	return hex.EncodeToString(sum[:]), nil
}

// CheckQualificationScope is mandatory at the production trust boundary.
// Legacy inspection reports cannot authorize an enforced production capability.
func (t VerifiedTarget) CheckQualificationScope(policies []string, compiler string, artifacts map[string]string) error {
	s := t.report.Qualification
	if s == nil || s.Validate() != nil {
		return errors.New("production qualification requires a behavior evidence scope")
	}
	digest, err := ArtifactSetDigest(artifacts)
	if err != nil || digest != s.ArtifactsSHA256 || compiler != s.CompilerSHA256 || artifacts["qualification"] != s.ProducerSHA256 {
		return errors.New("the qualification compiler, producer or artifact set differs")
	}
	expected := append([]string{}, policies...)
	sort.Strings(expected)
	if !reflect.DeepEqual(expected, s.PolicyDigests) {
		return errors.New("the qualification approved policy set differs")
	}
	if len(t.report.Capabilities) != len(s.RequiredCapabilities) {
		return errors.New("the qualification capability set differs")
	}
	for _, id := range s.RequiredCapabilities {
		c, ok := t.report.Capabilities[id]
		if !ok || c.State != "enforced" || len(c.Mechanisms) == 0 || !hash64.MatchString(c.ReceiptSHA256) {
			return errors.New("the qualification required capability lacks behavior evidence")
		}
	}
	return nil
}

func (t VerifiedTarget) CheckQualificationPolicy(digest, compiler string, artifacts map[string]string) error {
	s := t.report.Qualification
	if s == nil || !containsSorted(s.PolicyDigests, digest) {
		return errors.New("the exact policy lacks production qualification")
	}
	return t.CheckQualificationScope(s.PolicyDigests, compiler, artifacts)
}
