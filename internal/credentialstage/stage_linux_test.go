//go:build linux

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package credentialstage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/testpolicy"
	"golang.org/x/sys/unix"
)

func bindingFixture() lifecycle.Binding {
	return lifecycle.Binding{AgentID: "fixture-agent", AgentKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), JobDigest: strings.Repeat("a", 64), GrantID: "fixture-grant", RunID: "fixture-run", NodeID: "fixture-node", BootID: "fixture-boot", PolicyDigest: strings.Repeat("b", 64), SchemaDigest: policy.SchemaDigest(), CompilerDigest: strings.Repeat("d", 64), ArtifactDigests: map[string]string{"credential.provider": strings.Repeat("e", 64)}, CgroupID: 123, Generation: 1, DeadlineNS: 1000}
}

func fixture(t *testing.T) (Config, lifecycle.Authorization, lifecycle.Manifest, []lifecycle.CredentialReference) {
	t.Helper()
	d := testpolicy.Deny()
	d.Runtime.Bootstrap = &policy.BootstrapPolicy{Profile: "measured-held-exec.v1", HelperDigest: strings.Repeat("9", 64), Operations: []string{"credential_namespace"}, MaxHoldSeconds: 1}
	d.Files.Rules = []policy.FileRule{{ID: "own-credential", Selector: policy.Selector{Kind: "exact", Path: "/owned/job/auth.json"}, Operations: []string{"read"}, Effect: "allow"}}
	d.RequiredCapabilities, _ = policy.Requirements(d)
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	m := lifecycle.Manifest{Protocol: "agentgate.job.manifest.v1", AgentKind: "codex", RuntimeVersion: "synthetic-credential-test.v1", Executable: "/owned/runtime", ExecutableDigest: strings.Repeat("a", 64), ImageDigest: "sha256:" + strings.Repeat("b", 64), Workspace: "/owned/job", Arguments: []string{}, Environment: map[string]string{}, InputDigest: strings.Repeat("c", 64)}
	job, err := m.Digest()
	if err != nil {
		t.Fatal(err)
	}
	// Digest checks use the shared schema. This fixture deliberately requires
	// the kernel owner's explicit credential_namespace schema integration.
	digest, err := d.Digest()
	if err != nil {
		t.Fatal("the shared credential namespace schema is required:", err)
	}
	b := bindingFixture()
	b.JobDigest, b.PolicyDigest = job, digest
	c := Config{CredentialPolicy: lifecycle.CredentialPolicy{SourceRoot: "/owned/broker", SourceUID: uint32(os.Geteuid()), RuntimeUID: uint32(d.Runtime.UID)}, CheckRead: func(context.Context, lifecycle.Binding, lifecycle.Manifest, lifecycle.CredentialReference) error {
		return nil
	}, VerifyStopped: func(context.Context, lifecycle.Binding, lifecycle.Evidence) error { return nil }}
	a := lifecycle.Authorization{Binding: b, Grant: "synthetic-component-only", Document: raw, RequiredCapabilities: d.RequiredCapabilities}
	refs := []lifecycle.CredentialReference{{ID: "provider", AgentID: b.AgentID, AgentKind: m.AgentKind, SourcePath: "/owned/broker/auth.json", ExposedPath: "/owned/job/auth.json", Digest: b.ArtifactDigests["credential.provider"]}}
	return c, a, m, refs
}

func changeDocument(t *testing.T, a *lifecycle.Authorization, edit func(*policy.Document)) {
	t.Helper()
	var d policy.Document
	if err := json.Unmarshal(a.Document, &d); err != nil {
		t.Fatal(err)
	}
	edit(&d)
	d.RequiredCapabilities, _ = policy.Requirements(d)
	a.RequiredCapabilities = d.RequiredCapabilities
	a.Document, _ = json.Marshal(d)
	digest, err := d.Digest()
	if err != nil {
		t.Fatal(err)
	}
	a.Binding.PolicyDigest = digest
}

func TestPreparationRejectsUnboundOrImplicitCredentialsBeforeRead(t *testing.T) {
	for _, name := range []string{"no-domain", "wrong-job", "wrong-agent", "wrong-kind", "unbound-bytes", "duplicate-id", "duplicate-path", "no-bootstrap", "empty-bootstrap", "subtree-read", "denied-read", "deny-precedence", "missing-read", "write-only", "wrong-policy", "wrong-schema", "wrong-capabilities", "missing-grant", "missing-read-check", "missing-stop-check", "read-rejected"} {
		t.Run(name, func(t *testing.T) {
			c, a, m, refs := fixture(t)
			reads := 0
			c.CheckRead = func(context.Context, lifecycle.Binding, lifecycle.Manifest, lifecycle.CredentialReference) error {
				reads++
				return errors.New("synthetic rejection")
			}
			switch name {
			case "no-domain":
				a.Binding.CgroupID = 0
			case "wrong-job":
				a.Binding.JobDigest = strings.Repeat("f", 64)
			case "wrong-agent":
				refs[0].AgentID += "-other"
			case "wrong-kind":
				refs[0].AgentKind = "pi"
			case "unbound-bytes":
				delete(a.Binding.ArtifactDigests, "credential.provider")
			case "duplicate-id":
				refs = append(refs, refs[0])
				a.Binding.ArtifactDigests["other"] = strings.Repeat("f", 64)
			case "duplicate-path":
				second := refs[0]
				second.ID = "other"
				refs = append(refs, second)
				a.Binding.ArtifactDigests["credential.other"] = second.Digest
			case "no-bootstrap":
				changeDocument(t, &a, func(d *policy.Document) { d.Runtime.Bootstrap = nil })
			case "empty-bootstrap":
				changeDocument(t, &a, func(d *policy.Document) { d.Runtime.Bootstrap.Operations = []string{} })
			case "subtree-read":
				changeDocument(t, &a, func(d *policy.Document) { d.Files.Rules[0].Selector.Kind = "subtree" })
			case "denied-read":
				changeDocument(t, &a, func(d *policy.Document) { d.Files.Rules[0].Effect = "deny" })
			case "deny-precedence":
				changeDocument(t, &a, func(d *policy.Document) {
					deny := d.Files.Rules[0]
					deny.ID = "explicit-deny"
					deny.Effect = "deny"
					d.Files.Rules = append(d.Files.Rules, deny)
				})
			case "missing-read":
				changeDocument(t, &a, func(d *policy.Document) { d.Files.Rules = []policy.FileRule{} })
			case "write-only":
				changeDocument(t, &a, func(d *policy.Document) { d.Files.Rules[0].Operations = []string{"write"} })
			case "wrong-policy":
				a.Binding.PolicyDigest = strings.Repeat("f", 64)
			case "wrong-schema":
				a.Binding.SchemaDigest = strings.Repeat("f", 64)
			case "wrong-capabilities":
				a.RequiredCapabilities = []string{}
			case "missing-grant":
				a.Grant = ""
			case "missing-read-check":
				c.CheckRead = nil
			case "missing-stop-check":
				c.VerifyStopped = nil
			}
			stage, err := c.Prepare(context.Background(), a, m, refs)
			if stage != nil {
				stage.Abort()
				t.Fatal("invalid preparation exported a stage")
			}
			if err == nil {
				t.Fatal("invalid preparation succeeded")
			}
			want := 0
			if name == "read-rejected" {
				want = 1
			}
			if reads != want {
				t.Fatalf("read checks: got %d want %d", reads, want)
			}
		})
	}
}

func TestExactCredentialAuthorizationPassesValidation(t *testing.T) {
	c, a, m, refs := fixture(t)
	if err := c.validate(a, m, refs); err != nil {
		t.Fatal(err)
	}
}

func TestExportedNamespaceRetainsCustodyUntilFreshExactStop(t *testing.T) {
	a := lifecycle.Authorization{Binding: bindingFixture()}
	file, err := os.Open("/proc/thread-self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	fresh, calls := false, 0
	s := &Stage{namespace: os.NewFile(uintptr(fd), "synthetic-held-namespace"), measurement: Measurement{Binding: snapshot(a.Binding)}, verifyStopped: func(_ context.Context, b lifecycle.Binding, _ lifecycle.Evidence) error {
		calls++
		if !reflect.DeepEqual(b, a.Binding) {
			t.Fatal("stop verifier binding differs")
		}
		if !fresh {
			return errors.New("domain or helper still active")
		}
		return nil
	}}
	defer s.dispose()
	exported, err := s.NamespaceFD()
	if err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(exported.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("namespace export lacks CLOEXEC")
	}
	exported.Close()
	if s.Abort() == nil {
		t.Fatal("namespace export allowed abort")
	}
	e := lifecycle.Evidence{Binding: snapshot(a.Binding), Phase: "stopped", Terminated: true, Empty: true, RightsRemoved: true, ReadbackDigest: strings.Repeat("8", 64)}
	e.Digest = lifecycle.EvidenceDigest(e)
	wrong := snapshot(e)
	wrong.Binding.Generation++
	wrong.Digest = lifecycle.EvidenceDigest(wrong)
	if s.Close(context.Background(), wrong) == nil || calls != 0 {
		t.Fatal("wrong stop binding reached independent verification")
	}
	if s.Close(context.Background(), e) == nil || s.closed {
		t.Fatal("unconfirmed helper stop released custody")
	}
	fresh = true
	if s.Close(context.Background(), e) != nil || !s.closed || calls != 2 {
		t.Fatal("fresh exact stop did not release custody")
	}
	if _, err = s.NamespaceFD(); err == nil {
		t.Fatal("closed namespace exported")
	}
}

func TestMeasurementCannotChangeRetainedBinding(t *testing.T) {
	a := lifecycle.Authorization{Binding: bindingFixture()}
	s := &Stage{measurement: Measurement{Binding: snapshot(a.Binding), Files: []FileMeasurement{{ReferenceID: "provider"}}}}
	read := s.Measurement()
	read.Binding.ArtifactDigests["credential.provider"] = "changed"
	read.Files[0].ReferenceID = "changed"
	if s.measurement.Binding.ArtifactDigests["credential.provider"] != a.Binding.ArtifactDigests["credential.provider"] || s.measurement.Files[0].ReferenceID != "provider" {
		t.Fatal("measurement caller changed custody")
	}
}

func TestPrivateMountReadbackRejectsMissingFlagsAndPropagation(t *testing.T) {
	valid := "71 1 0:2 / /owned/auth ro,nosuid,nodev,noexec - tmpfs memfd rw\n"
	if verifyPrivateMount([]byte(valid), 71) != nil {
		t.Fatal("valid private mount readback rejected")
	}
	for _, raw := range []string{strings.Replace(valid, " ro,", " rw,", 1), strings.Replace(valid, ",noexec", "", 1), strings.Replace(valid, " - ", " shared:9 - ", 1), strings.Replace(valid, " - ", " master:9 - ", 1), strings.Replace(valid, "71 ", "72 ", 1)} {
		if verifyPrivateMount([]byte(raw), 71) == nil {
			t.Fatal("unsafe mount readback accepted")
		}
	}
}

func TestTargetPinRejectsLinksWritableParentsAndNonemptyFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("protected target tests require root in a disposable build container")
	}
	scratch := os.Getenv("AGENTGATE_TEST_SCRATCH")
	if scratch == "" {
		t.Skip("set AGENTGATE_TEST_SCRATCH to an owned private directory")
	}
	root, err := os.MkdirTemp(scratch, "credential-target-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	for _, name := range []string{"linked-target", "writable-parent", "nonempty", "writable-target", "hardlink"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(root, name)
			if err := os.Mkdir(dir, 0755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "auth")
			if err := os.WriteFile(path, nil, 0400); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "linked-target":
				os.Symlink(path, path+".link")
				path += ".link"
			case "writable-parent":
				os.Chmod(dir, 0777)
			case "nonempty":
				os.Chmod(path, 0600)
				os.WriteFile(path, []byte("public-fixture"), 0400)
				os.Chmod(path, 0400)
			case "writable-target":
				os.Chmod(path, 0600)
			case "hardlink":
				os.Link(path, path+".link")
			}
			parent, target, _, err := pinTarget(path)
			if parent != nil {
				parent.Close()
			}
			if target != nil {
				target.Close()
			}
			if err == nil {
				t.Fatal("unsafe target accepted")
			}
		})
	}
}
