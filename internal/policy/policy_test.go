// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func selectedJSON(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(NewSelected(Selected{true, "127.0.0.1", 19081}))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestJSONYAMLRoundTripAndExactCapabilitySet(t *testing.T) {
	raw := selectedJSON(t)
	document, err := Parse(raw, "json")
	if err != nil {
		t.Fatal(err)
	}
	yaml := []byte("schema_version: agentgate.policy.v2\nprofile: selected-inspection.v2\nrequired_capabilities: [fs.selected-write-open.v1, net.selected-connect4.v1]\nselected:\n  workspace_write: true\n  tcp_address: 127.0.0.1\n  tcp_port: 19081\n")
	other, err := Parse(yaml, "yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(document, other) {
		t.Fatal("the JSON and YAML editors changed policy fields")
	}
	if err = document.CheckDeclaredRequirements(); err != nil {
		t.Fatal(err)
	}
	document.RequiredCapabilities = []string{"fs.selected-write-open.v1"}
	if err = document.CheckDeclaredRequirements(); err == nil {
		t.Fatal("the declared set omitted a network requirement")
	}
}
func TestRejectAmbiguousAndUnregisteredInputs(t *testing.T) {
	raw := string(selectedJSON(t))
	cases := []struct{ format, source string }{
		{"json", strings.Replace(raw, `"tcp_port":19081`, `"tcp_port":19081,"tcp_port":19082`, 1)},
		{"json", strings.Replace(raw, `"tcp_port":19081`, `"tcp_port":19081,"udp_port":53`, 1)},
		{"json", strings.Replace(raw, "agentgate.policy.v2", "agentgate.policy.v99", 1)},
		{"json", raw + raw},
		{"json", strings.Replace(raw, `"tcp_port":19081`, `"tcp_port":1e400`, 1)},
		{"json", strings.Replace(raw, "127.0.0.1", "255.255.255.255", 1)},
		{"yaml", "value: &node [*node]"},
		{"yaml", "value: !unsafe text"},
		{"yaml", "value: {a: 1, a: 2}"},
		{"yaml", "value: true\n---\nvalue: false"},
		{"yaml", strings.Replace(raw, `"tcp_port":19081`, `"tcp_port":0x20`, 1)},
		{"yaml", strings.Replace(raw, `"workspace_write":true`, `"workspace_write":yes`, 1)},
	}
	for _, test := range cases {
		if _, err := Parse([]byte(test.source), test.format); err == nil {
			t.Fatalf("accepted ambiguous or unsupported %s input", test.format)
		}
	}
	if _, err := Parse([]byte(strings.Repeat(" ", MaxBytes+1)), "json"); err == nil {
		t.Fatal("accepted an oversized document")
	}
	nested := strings.Repeat("[", maxDepth+2) + "0" + strings.Repeat("]", maxDepth+2)
	if _, err := parseValue([]byte(nested), "json"); err == nil {
		t.Fatal("accepted excessive nesting")
	}
}
func TestFilePrecedenceUsesOperationsAndComponentBoundaries(t *testing.T) {
	files := Files{Defaults: FileDefaults{"deny", "deny"}, Rules: []FileRule{
		{ID: "secrets", Selector: Selector{"subtree", "/run/secrets"}, Operations: []string{"read"}, Effect: "deny"},
		{ID: "own", Selector: Selector{"exact", "/run/secrets/own.seed"}, Operations: []string{"read"}, Effect: "allow"},
		{ID: "work", Selector: Selector{"subtree", "/work"}, Operations: []string{"write", "rename"}, Effect: "allow"},
		{ID: "blocked", Selector: Selector{"exact", "/work/blocked"}, Operations: []string{"write"}, Effect: "deny"},
		{ID: "equal", Selector: Selector{"exact", "/work/blocked"}, Operations: []string{"write"}, Effect: "allow"},
	}}
	for _, test := range []struct{ path, operation, effect string }{{"/run/secrets/own.seed", "read", "allow"}, {"/run/secrets/other.seed", "read", "deny"}, {"/run/secrets-other/value", "read", "deny"}, {"/work/file", "write", "allow"}, {"/workspace/file", "write", "deny"}, {"/work/blocked", "write", "deny"}, {"/work/blocked", "rename", "allow"}, {"/work/file", "delete", "deny"}} {
		if got := FileEffect(files, test.path, test.operation); got != test.effect {
			t.Fatalf("%s %s: got%s want%s", test.operation, test.path, got, test.effect)
		}
	}
	for _, path := range []string{"relative", "/work/../outside", "/work/\x00file"} {
		if FileEffect(files, path, "read") != "deny" {
			t.Fatal("unresolved file identity inherited the read allowance")
		}
	}
}
func targetFixture(t *testing.T, state string) ([]byte, ed25519.PublicKey, TargetBinding) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := TargetBinding{"owned-node", "owned-boot", "owned-challenge"}
	capability := Capability{state, []string{"qualified-selected-hook"}, strings.Repeat("a", 64)}
	capabilities := map[string]Capability{}
	required, _ := Requirements(fullFixture())
	for _, id := range required {
		capabilities[id] = capability
	}
	report := CapabilityReport{SchemaVersion: CapabilityVersion, Node: binding.Node, Boot: binding.Boot, Challenge: binding.Challenge, Kernel: "6.8.0-142-generic", Architecture: "x86_64", SourceRevision: strings.Repeat("b", 40), ArtifactSHA256: strings.Repeat("c", 64), PolicySchemaDigest: SchemaDigest(), IssuedAt: 100, ValidUntil: 200, Capabilities: capabilities, Probes: []HookProbe{{Hook: "file_open", Helper: "bpf_d_path", Loaded: true, Attached: true}}}
	report.InventorySHA256 = strings.Repeat("d", 64)
	report.BTFSHA256 = strings.Repeat("e", 64)
	report.KernelConfigSHA256 = strings.Repeat("f", 64)
	digest, err := fullFixture().Digest()
	if err != nil {
		t.Fatal(err)
	}
	report.Qualification = &QualificationScope{
		Protocol: QualificationScopeVersion, ProducerSHA256: strings.Repeat("1", 64),
		CompilerSHA256: strings.Repeat("2", 64), ArtifactsSHA256: strings.Repeat("3", 64),
		PolicyDigests: []string{digest}, RequiredCapabilities: required,
		ContractsSHA256: strings.Repeat("4", 64), EvidenceSHA256: strings.Repeat("5", 64),
	}
	raw, err := SignReport(report, key)
	if err != nil {
		t.Fatal(err)
	}
	return raw, pub, binding
}
func TestFullPreviewRequiresExactSignedQualificationScope(t *testing.T) {
	raw, pub, binding := targetFixture(t, "enforced")
	target, err := VerifyTarget(raw, pub, binding, 150)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = PreviewForTarget(fullFixture(), target, 150); err != nil {
		t.Fatal(err)
	}
	target.report.Qualification = nil
	if _, err = PreviewForTarget(fullFixture(), target, 150); err == nil {
		t.Fatal("an unscoped enforced report supplied a full-policy preview")
	}
	target, err = VerifyTarget(raw, pub, binding, 150)
	if err != nil {
		t.Fatal(err)
	}
	target.report.Qualification.PolicyDigests[0] = strings.Repeat("6", 64)
	if _, err = PreviewForTarget(fullFixture(), target, 150); err == nil {
		t.Fatal("another policy's qualification supplied a preview")
	}
	target, err = VerifyTarget(raw, pub, binding, 150)
	if err != nil {
		t.Fatal(err)
	}
	target.report.Qualification.RequiredCapabilities = target.report.Qualification.RequiredCapabilities[:1]
	if _, err = PreviewForTarget(fullFixture(), target, 150); err == nil {
		t.Fatal("an incomplete capability set supplied a preview")
	}
}
func TestProbeAvailabilityCannotGrantEnforcementCapability(t *testing.T) {
	raw, pub, binding := targetFixture(t, "probe-only")
	target, err := VerifyTarget(raw, pub, binding, 150)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = PreviewForTarget(fullFixture(), target, 150); err == nil {
		t.Fatal("loaded and attached probes became enforced rights")
	}
	raw, pub, binding = targetFixture(t, "enforced")
	target, err = VerifyTarget(raw, pub, binding, 150)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := PreviewForTarget(fullFixture(), target, 150)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Purpose != "validation-preview" || preview.SchemaDigest != SchemaDigest() || len(preview.PolicyDigest) != 64 {
		t.Fatal("the preview lost its exact contract binding")
	}
	if _, err = PreviewForTarget(fullFixture(), target, 200); err == nil {
		t.Fatal("an expired target report retained rights")
	}
}
func TestCapabilityTrustAndReplayBindings(t *testing.T) {
	raw, pub, binding := targetFixture(t, "enforced")
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyTarget(raw, other, binding, 150); err == nil {
		t.Fatal("another node key verified")
	}
	for _, wrong := range []TargetBinding{{"other-node", binding.Boot, binding.Challenge}, {binding.Node, "other-boot", binding.Challenge}, {binding.Node, binding.Boot, "old-challenge"}} {
		if _, err = VerifyTarget(raw, pub, wrong, 150); err == nil {
			t.Fatal("another target or stale challenge verified")
		}
	}
	if _, err = VerifyTarget(raw, pub, binding, 200); err == nil {
		t.Fatal("expired capability evidence verified")
	}
	duplicate := strings.Replace(string(raw), `"kernel":"6.8.0-142-generic"`, `"kernel":"6.8.0-142-generic","kernel":"other"`, 1)
	if _, err = VerifyTarget([]byte(duplicate), pub, binding, 150); err == nil {
		t.Fatal("duplicate report fields verified")
	}
	var envelope CapabilityEnvelope
	if err = json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Report.IssuedAt = -9223372036854775808
	envelope.Report.ValidUntil = 9223372036854775807
	if err = checkReport(envelope.Report, binding, 150); err == nil {
		t.Fatal("an overflow extended the report lifetime")
	}
}

func TestFullPreviewRequiresBoundInventoryMeasurements(t *testing.T) {
	raw, pub, binding := targetFixture(t, "enforced")
	target, err := VerifyTarget(raw, pub, binding, 150)
	if err != nil {
		t.Fatal(err)
	}
	copy := target.Report()
	copy.Capabilities["fs.read.v1"] = Capability{State: "unavailable"}
	if _, err = PreviewForTarget(fullFixture(), target, 150); err != nil {
		t.Fatal("a report reader changed verified capability state")
	}
	target.report.InventorySHA256 = ""
	if _, err = PreviewForTarget(fullFixture(), target, 150); err == nil {
		t.Fatal("a full preview accepted an unmeasured inventory")
	}
}

func fullFixture() Document {
	extensions := map[string]json.RawMessage{}
	templates := []string{}
	document := Document{SchemaVersion: Version, Profile: KernelProfile, RequiredCapabilities: []string{}, Defaults: &Defaults{"deny", "deny", "deny"}, RuntimeTemplates: &templates,
		Files:     &Files{Defaults: FileDefaults{"deny", "deny"}, ResourceUse: "recheck-and-terminate", Rules: []FileRule{{ID: "workspace", Selector: Selector{"subtree", "/work"}, Operations: []string{"read", "write", "create", "rename"}, Effect: "allow"}}},
		Programs:  &Programs{Default: "deny", Rules: []ProgramRule{{ID: "git", Selector: Selector{"exact", "/usr/bin/git"}, Effect: "allow", Approval: &Approval{[]string{"push"}, 120, "one-shot-actual-executable", "observed"}}}},
		Network:   &Network{Default: "deny", Rules: []NetworkRule{{ID: "dns-aware", Family: "ipv6", Protocol: "udp", Destination: Destination{"hostname", "code.example.test"}, PortFrom: 443, PortTo: 443, Effect: "allow"}}, DNS: DNS{"trusted-forwarder.v1", "validate-chain", "remove-expired-authorization"}},
		Sockets:   &SocketPolicy{Default: "deny", Rules: []SocketRule{}},
		Identity:  &Identity{"local-enrollment", true, true, true, true, "job-cgroup", "inherit"},
		Runtime:   &Runtime{Profile: "managed-unprivileged.v1", UID: 65534, GID: 65534, SupplementaryGroups: []int{}, Capabilities: []string{}, NoNewPrivileges: true, Seccomp: Seccomp{"explicit-allowlist-notify.v2", "x86_64", "deny", []string{}}},
		Lifecycle: &Lifecycle{"owned-baseline", 20, "restore-baseline", "terminate-job", "pinned-generation-reconcile"},
		Evidence:  &Evidence{"node-chain-authority-batch.v1", 0, 500, 5}, Extensions: &extensions,
	}
	document.RequiredCapabilities, _ = Requirements(document)
	return document
}
func TestFullContractPreservesEveryFieldAndRejectsUnsupportedTarget(t *testing.T) {
	document := fullFixture()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(raw, "json")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(document, parsed) {
		t.Fatal("full contract fields disappeared during parsing")
	}
	required, err := Requirements(parsed)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"fs.read.v1", "fs.write.v1", "fs.create.v1", "fs.rename.v1", "fs.resource-use.v1", "exec.approval.v1", "net.ipv6.v1", "net.udp.v1", "net.dns-ttl.v1", "runtime.explicit-syscalls.v2", "lifecycle.terminate.v1"} {
		if !hasOperation(required, expected) {
			t.Fatalf("schema omitted capability %s", expected)
		}
	}
	signed, pub, binding := targetFixture(t, "enforced")
	target, err := VerifyTarget(signed, pub, binding, 150)
	if err != nil {
		t.Fatal(err)
	}
	target.report.Capabilities["fs.read.v1"] = Capability{State: "unavailable"}
	if _, err = PreviewForTarget(parsed, target, 150); err == nil {
		t.Fatal("an unavailable required read control accepted full kernel rights")
	}
	parsed.Programs.Rules[0].Effect = "deny"
	if err = parsed.Validate(); err == nil {
		t.Fatal("an approval escaped executable allowance")
	}
	parsed = fullFixture()
	parsed.Network.Rules[0].PortTo = 442
	if err = parsed.Validate(); err == nil {
		t.Fatal("a reversed port range validated")
	}
	parsed = fullFixture()
	parsed.Files.Rules[0].Selector.Path = "/work/../outside"
	if err = parsed.Validate(); err == nil {
		t.Fatal("a noncanonical path validated")
	}
}

func TestDenyAllEmptyMissingUnmatchedAndInspectionProfiles(t *testing.T) {
	document := fullFixture()
	document.Files.Rules = []FileRule{}
	document.Programs.Rules = []ProgramRule{}
	document.Network.Rules = []NetworkRule{}
	document.RequiredCapabilities, _ = Requirements(document)
	if err := document.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"read", "write", "create", "mkdir", "delete", "rename", "hardlink", "symlink", "metadata", "mmap", "descriptor_receive", "unknown"} {
		if FileEffect(*document.Files, "/work/resource", operation) != "deny" {
			t.Fatalf("empty permissions allowed%s", operation)
		}
	}
	files := Files{Defaults: FileDefaults{"allow", "allow"}, Rules: []FileRule{{ID: "unknown", Selector: Selector{"subtree", "/"}, Operations: []string{"unknown"}, Effect: "allow"}}}
	if FileEffect(files, "/work/resource", "read") != "deny" || FileEffect(files, "/work/resource", "unknown") != "deny" {
		t.Fatal("an invalid default or unknown operation granted access")
	}
	document.Files.Rules = []FileRule{{ID: "explicit", Selector: Selector{"exact", "/work/one"}, Operations: []string{"read"}, Effect: "allow"}}
	if FileEffect(*document.Files, "/work/one", "read") != "allow" || FileEffect(*document.Files, "/work/two", "read") != "deny" {
		t.Fatal("explicit allowance leaked to an unmatched resource")
	}
	document.Files.Defaults.Read = "allow"
	if err := document.Validate(); err == nil {
		t.Fatal("the old implicit-read default remained valid")
	}
	document = fullFixture()
	document.RuntimeTemplates = nil
	if err := document.Validate(); err == nil {
		t.Fatal("missing runtime-template declaration validated")
	}
	document = fullFixture()
	document.Defaults = nil
	if err := document.Validate(); err == nil {
		t.Fatal("missing global deny defaults validated")
	}
	document = fullFixture()
	document.Runtime.Seccomp.AllowSyscalls = []string{"unknown_syscall"}
	if err := document.Validate(); err == nil {
		t.Fatal("unregistered runtime permission validated")
	}
	raw, pub, binding := targetFixture(t, "enforced")
	target, err := VerifyTarget(raw, pub, binding, 150)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = PreviewForTarget(NewSelected(Selected{true, "127.0.0.1", 19081}), target, 150); err == nil {
		t.Fatal("a compatibility profile authorized implicit runtime access")
	}
	for _, state := range []string{"audit-only", "unavailable", "not-applicable"} {
		raw, pub, binding = targetFixture(t, state)
		target, err = VerifyTarget(raw, pub, binding, 150)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = PreviewForTarget(fullFixture(), target, 150); err == nil {
			t.Fatalf("%s capability authorized enforcement", state)
		}
	}
}
