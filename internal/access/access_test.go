// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package access

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/pocpolicy"
)

func full(t *testing.T) pocpolicy.Document {
	t.Helper()
	d, err := FullExample()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func v1(t *testing.T) pocpolicy.Document {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(pocDir, "policy.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := pocpolicy.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func code(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}

func TestWritableNeverExecutable(t *testing.T) {
	d := full(t)
	for _, p := range []string{"/var/lib/agentgate/workspace", "/var/lib/agentgate/workspace/bin", "/tmp", "/var/lib/agentgate"} {
		if _, err := Apply(d, Edit{Action: ActionExec, Values: []string{p}}); code(err) != CodeConflict {
			t.Fatalf("exec %s: %v", p, err)
		}
	}
	for _, p := range []string{"/usr/local", "/opt"} {
		r, err := Apply(d, Edit{Action: ActionExec, Values: []string{"/opt/tools"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = Apply(r.Document, Edit{Action: ActionWrite, Values: []string{p}}); code(err) != CodeConflict {
			t.Fatalf("write %s over an executable tree: %v", p, err)
		}
	}
	r, err := Apply(d, Edit{Action: ActionMount, Values: []string{"repo"}, Mode: "read-write"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Apply(r.Document, Edit{Action: ActionExec, Values: []string{MountRoot + "/repo/bin"}}); code(err) != CodeConflict {
		t.Fatal("a read-write mount became executable")
	}
}

func TestProtectedTreesAndDenyOverride(t *testing.T) {
	d := full(t)
	for _, p := range []string{"/etc/app", "/proc/x", "/run/agentgate/bridge", "/usr/lib/x", "/dev/shm"} {
		if _, err := Apply(d, Edit{Action: ActionWrite, Values: []string{p}}); err == nil {
			t.Fatalf("protected tree %s became writable", p)
		}
	}
	if _, err := Apply(d, Edit{Action: ActionRead, Values: []string{"/etc/shadow"}}); code(err) != CodeConflict {
		t.Fatal("a denied path was granted without revoking the deny")
	}
}

func TestEditsAreIdempotentAndDoNotChangeInput(t *testing.T) {
	d := full(t)
	before, _ := json.Marshal(d)
	r, err := Apply(d, Edit{Action: ActionRead, Values: []string{"/srv/data"}})
	if err != nil || !r.Changed {
		t.Fatal(err)
	}
	after, _ := json.Marshal(d)
	if string(before) != string(after) {
		t.Fatal("Apply changed its input document")
	}
	again, err := Apply(r.Document, Edit{Action: ActionRead, Values: []string{"/srv/data"}})
	if err != nil || again.Changed || !reflect.DeepEqual(again.Document, r.Document) {
		t.Fatal("a repeated grant changed the document")
	}
	if again.Document.Digest() != r.Document.Digest() {
		t.Fatal("an idempotent grant changed the digest")
	}
	revoked, err := Apply(r.Document, Edit{Action: ActionRevoke, Kind: "read", Values: []string{"/srv/data"}})
	if err != nil || revoked.Document.Digest() != d.Digest() {
		t.Fatal("revoke did not restore the original document")
	}
}

func TestVersionOneUpgradeOnlyWhenExplicit(t *testing.T) {
	d := v1(t)
	if _, err := Apply(d, Edit{Action: ActionRead, Values: []string{"/srv"}}); code(err) != CodeUpgrade {
		t.Fatalf("v1 path edit without upgrade: %v", err)
	}
	r, err := Apply(d, Edit{Action: ActionDenyWeb, Values: []string{"quic"}})
	if err != nil || r.Document.Version != pocpolicy.VersionV1 {
		t.Fatal("a network edit upgraded the document")
	}
	r, err = Apply(d, Edit{Action: ActionRead, Values: []string{"/srv"}, UpgradeToV2: true})
	if err != nil || r.Document.Version != pocpolicy.VersionV2 || len(r.Notices) != 1 {
		t.Fatal("explicit upgrade failed", err)
	}
	if !reflect.DeepEqual(r.Document.DNS, d.DNS) || !reflect.DeepEqual(r.Document.Web, d.Web) || r.Document.Taskboard != d.Taskboard {
		t.Fatal("the upgrade changed the network section")
	}
}

func TestEditInputBounds(t *testing.T) {
	d := full(t)
	bad := []Edit{
		{Action: "chmod", Values: []string{"/x"}},
		{Action: ActionRead, Values: []string{"/" + strings.Repeat("a", 200)}},
		{Action: ActionRead, Values: []string{"/a", "/b"}},
		{Action: ActionRead, Values: []string{"/a\n/b"}},
		{Action: ActionRead, Kind: "read", Values: []string{"/a"}},
		{Action: ActionSignal, Values: make([]string, MaxValues+1)},
		{Action: ActionRevoke, Kind: "everything", Values: []string{"/a"}},
		{Action: ActionDNS, Values: []string{"10.0.0.1"}},
		{Action: ActionDNS},
		{Action: ActionPreset, Values: []string{"nope"}},
		{Action: ActionMount, Values: []string{"repo"}, Mode: "read-execute"},
	}
	for _, e := range bad {
		if _, err := Apply(d, e); err == nil {
			t.Fatalf("accepted %+v", e)
		}
	}
	broken := full(t)
	broken.Filesystem.Execute = append(broken.Filesystem.Execute, "/tmp")
	if _, err := Apply(broken, Edit{Action: ActionDenyWeb}); code(err) != CodeRejected {
		t.Fatal("an invalid input document was edited")
	}
}

func TestPresetsBuildValidDocuments(t *testing.T) {
	for _, name := range PresetNames() {
		d, err := NewFromPreset(name)
		if err != nil {
			t.Fatal(name, err)
		}
		if d.Validate() != nil || d.Version != pocpolicy.VersionV2 {
			t.Fatal(name, "invalid preset document")
		}
	}
	if len(PresetNames()) != 4 {
		t.Fatal("unexpected preset count")
	}
}

func TestDeviceGrantsAllowOnlyTheSixDevices(t *testing.T) {
	doc, err := FullExample()
	if err != nil {
		t.Fatal(err)
	}
	r, err := Apply(doc, Edit{Action: ActionDevice, Values: []string{"/dev/tty"}})
	if err != nil || !r.Changed || r.Document.Filesystem.Devices[len(r.Document.Filesystem.Devices)-1] != "/dev/tty" || r.Message != "device: added /dev/tty" {
		t.Fatalf("%+v %v", r, err)
	}
	if again, err := Apply(r.Document, Edit{Action: ActionDevice, Values: []string{"/dev/tty"}}); err != nil || again.Changed {
		t.Fatal("a repeated device grant changed the policy")
	}
	for _, bad := range []string{"/dev/sda", "/dev/mem", "/dev/../dev/null", "/dev/null/", "tty", ""} {
		if _, err := Apply(doc, Edit{Action: ActionDevice, Values: []string{bad}}); !IsCode(err, CodeUsage) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	gone, err := Apply(r.Document, Edit{Action: ActionRevoke, Kind: "device", Values: []string{"/dev/tty"}})
	if err != nil || !gone.Changed || contains(gone.Document.Filesystem.Devices, "/dev/tty") {
		t.Fatalf("revoke device: %+v %v", gone, err)
	}
	if len(Devices) != 6 {
		t.Fatal("the device allowlist changed")
	}
}
