// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package childwire

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/runtimeguard"
	"bytes"
	"encoding/binary"
	"golang.org/x/sys/unix"
	"os"
	"strings"
	"testing"
)

func manifest() lifecycle.Manifest {
	return lifecycle.Manifest{Protocol: "agentgate.job.manifest.v1", AgentKind: "codex", RuntimeVersion: "fixture-encoder-v1", Executable: "/owned/agent", ExecutableDigest: strings.Repeat("a", 64), ImageDigest: "sha256:" + strings.Repeat("b", 64), Arguments: []string{"", "one argument"}, Workspace: "/owned/workspace", Environment: map[string]string{"Z_LAST": "z", "A_FIRST": "a"}, InputDigest: strings.Repeat("c", 64)}
}

func TestNamespaceFrameBindsTheReservedDescriptorAndIdentity(t *testing.T) {
	paths := IOPaths{"/owned/input", "/owned/output", "/owned/error"}
	identity := NamespaceIdentity{Device: 4, Inode: 998877}
	raw, err := EncodeNamespace(manifest(), paths, identity)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw[:8]) != "AGJOB002" || binary.LittleEndian.Uint32(raw[8:]) != 2 || binary.LittleEndian.Uint32(raw[20:]) != NamespaceFD || binary.LittleEndian.Uint64(raw[24:]) != identity.Device || binary.LittleEndian.Uint64(raw[32:]) != identity.Inode {
		t.Fatal("the namespace frame loses its exact identity")
	}
	for _, invalid := range []NamespaceIdentity{{}, {Device: 1}, {Inode: 1}} {
		if _, err = EncodeNamespace(manifest(), paths, invalid); err == nil {
			t.Fatal("an incomplete identity was encoded")
		}
	}
}

func TestNamespaceTransportVerifiesTypeIdentityAndDuplicateCustody(t *testing.T) {
	p, err := runtimeguard.Compile(policy.Runtime{Profile: "managed-unprivileged.v1", UID: 65534, GID: 65534, SupplementaryGroups: []int{}, Capabilities: []string{}, NoNewPrivileges: true, Seccomp: policy.Seccomp{Profile: "explicit-allowlist-notify.v2", Architecture: "x86_64", Default: "deny", AllowSyscalls: []string{"getpid"}}})
	if err != nil {
		t.Fatal(err)
	}
	paths := IOPaths{"/owned/input", "/owned/output", "/owned/error"}
	ns, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	var st unix.Stat_t
	if err = unix.Fstat(int(ns.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	identity := NamespaceIdentity{uint64(st.Dev), st.Ino}
	transport, err := NewNamespace(manifest(), paths, p, ns, identity)
	if err != nil {
		t.Fatal(err)
	}
	if len(transport.ExtraFiles()) != 4 || transport.Namespace.Fd() == ns.Fd() || transport.NamespaceIdentity != identity {
		t.Fatal("the reserved namespace descriptor custody differs")
	}
	transport.Close()
	if err = unix.Fstat(int(ns.Fd()), &st); err != nil {
		t.Fatal("transport closed the caller descriptor", err)
	}
	identity.Inode++
	if _, err = NewNamespace(manifest(), paths, p, ns, identity); err == nil {
		t.Fatal("a substituted namespace identity was accepted")
	}
	file, err := os.CreateTemp(t.TempDir(), "ordinary-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err = unix.Fstat(int(file.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	if _, err = NewNamespace(manifest(), paths, p, file, NamespaceIdentity{uint64(st.Dev), st.Ino}); err == nil {
		t.Fatal("an ordinary file became a mount namespace")
	}
}
func TestBoundedManifestAndSealedCustody(t *testing.T) {
	m := manifest()
	paths := IOPaths{"/owned/input", "/owned/output", "/owned/error"}
	a, e := Encode(m, paths)
	if e != nil {
		t.Fatal(e)
	}
	m.Environment = map[string]string{"A_FIRST": "a", "Z_LAST": "z"}
	b, e := Encode(m, paths)
	if e != nil || !bytes.Equal(a, b) {
		t.Fatal("manifest order is unstable")
	}
	if !bytes.HasPrefix(a, []byte("AGJOB001")) {
		t.Fatal("child protocol differs")
	}
	f, e := Seal("owned-test", a)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = f.Write([]byte("x")); e == nil {
		t.Fatal("sealed child declaration changed")
	}
	if _, e = Encode(m, IOPaths{"/tmp/input", "/owned/output", "/owned/error"}); e == nil {
		t.Fatal("unsafe stream path accepted")
	}
	m.Arguments = []string{strings.Repeat("x", 65537)}
	if _, e = Encode(m, paths); e == nil {
		t.Fatal("oversize declaration accepted")
	}
}
