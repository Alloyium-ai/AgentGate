// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func manifestFixture() Manifest {
	input := sha256.Sum256([]byte("bounded test prompt"))
	return Manifest{Protocol: "agentgate.job.manifest.v1", AgentKind: "codex", RuntimeVersion: "fixture-version", Executable: "/opt/agent/bin/codex", ExecutableDigest: strings.Repeat("a", 64), ImageDigest: "sha256:" + strings.Repeat("b", 64), Arguments: []string{"exec", "-"}, Workspace: "/work/job", Environment: map[string]string{"TMPDIR": "/work/job/cache", "HOME": "/work/job", "PATH": "/opt/agent/bin:/usr/bin:/bin"}, InputDigest: hex.EncodeToString(input[:])}
}
func TestManifestBindsActualInputCommandEnvironmentAndArtifact(t *testing.T) {
	manifest := manifestFixture()
	digest, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	binding := fixtureBinding()
	binding.CgroupID = 101
	binding.JobDigest = digest
	request := RunRequest{Protocol: RunProtocol, Manifest: manifest, Authorization: Authorization{Binding: binding}, Input: []byte("bounded test prompt")}
	if err = request.Validate(); err != nil {
		t.Fatal(err)
	}
	changed := clone(request)
	changed.Input = []byte("different prompt")
	if err = changed.Validate(); err == nil {
		t.Fatal("changed prompt accepted")
	}
	changed = clone(request)
	changed.Manifest.Arguments = append(changed.Manifest.Arguments, "--unapproved")
	if err = changed.Validate(); err == nil {
		t.Fatal("changed arguments accepted")
	}
	changed = clone(request)
	changed.Manifest.Environment["HOME"] = "/work/another-job"
	if err = changed.Validate(); err == nil {
		t.Fatal("changed environment accepted")
	}
	changed = clone(request)
	changed.Manifest.ExecutableDigest = strings.Repeat("f", 64)
	if err = changed.Validate(); err == nil {
		t.Fatal("changed runtime artifact accepted")
	}
}
func TestManifestRejectsUnknownRuntimeUnpinnedImageAndInheritedEnvironment(t *testing.T) {
	for _, failure := range []string{"kind", "image", "environment", "path", "utf8"} {
		t.Run(failure, func(t *testing.T) {
			m := manifestFixture()
			switch failure {
			case "kind":
				m.AgentKind = "synthetic"
			case "image":
				m.ImageDigest = "latest"
			case "environment":
				m.Environment = nil
			case "path":
				m.Workspace = "/work/../outside"
			case "utf8":
				m.Arguments = []string{string([]byte{0xff})}
			}
			if err := m.Validate(); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
}
func TestTransportPreservesFullUint64Identity(t *testing.T) {
	binding := fixtureBinding()
	binding.CgroupID = 18446744073709551615
	binding.DeadlineNS = 18446744073709551614
	raw, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"cgroup_id":"18446744073709551615"`) {
		t.Fatal("cgroup identity lost decimal-string encoding")
	}
	var roundtrip Binding
	if err = json.Unmarshal(raw, &roundtrip); err != nil || !binding.same(roundtrip) {
		t.Fatal("binding lost numeric identity", err)
	}
}

func TestTransportRejectsAmbiguousOrUnknownFields(t *testing.T) {
	for _, source := range []string{
		`{"protocol":"agentgate.job.run.v1","protocol":"changed"}`,
		`{"protocol":"agentgate.job.run.v1","unknown":true}`,
		`{"authorization":{"binding":{"node_id":"one","node_id":"two"}}}`,
		`{"protocol":"agentgate.job.run.v1"} {}`,
	} {
		var request RunRequest
		if err := DecodeTransport(strings.NewReader(source), &request); err == nil {
			t.Fatal("ambiguous request accepted", source)
		}
	}
}

func TestManifestDigestMatchesGatewayVector(t *testing.T) {
	raw := []byte(manifestVectorJSON)
	var err error
	var vector struct {
		Manifest   Manifest `json:"manifest"`
		Serialized string   `json:"serialized"`
		Digest     string   `json:"digest"`
	}
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	digest, err := vector.Manifest.Digest()
	if err != nil || digest != vector.Digest {
		t.Fatal("gateway manifest digest differs", digest, err)
	}
	canonical, err := json.Marshal(vector.Manifest)
	if err != nil || string(canonical) != vector.Serialized {
		t.Fatal("gateway canonical bytes differ", err)
	}
}
