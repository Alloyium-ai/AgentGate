// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package pocpolicy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/fsrules"
	"github.com/cilium/ebpf"
)

func fullExample(t *testing.T) Document {
	t.Helper()
	raw, err := os.ReadFile("../../poc/ssh-diagnostic/policy.full.example.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// network is evidence that the six cgroup network hooks are attached to domain.
func network(t *testing.T, domain uint64) fsrules.CgroupNetworkGuard {
	t.Helper()
	attached := []fsrules.CgroupProgram{}
	for i, hook := range fsrules.CgroupNetworkHooks() {
		attached = append(attached, fsrules.CgroupProgram{Attach: hook.Attach, ID: ebpf.ProgramID(i + 1), Name: hook.Program, Type: hook.Type})
	}
	guard, err := fsrules.NewCgroupNetworkGuard(domain, attached)
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func TestVersionOneNeverCarriesHostControls(t *testing.T) {
	d := fullExample(t)
	d.Version = VersionV1
	if d.Validate() == nil {
		t.Fatal("a version one document accepted filesystem and process sections")
	}
	d = fullExample(t)
	d.Filesystem = nil
	if d.Validate() == nil {
		t.Fatal("a version two document omitted its filesystem section")
	}
	d = fullExample(t)
	d.Process = nil
	if d.Validate() == nil {
		t.Fatal("a version two document omitted its process section")
	}
}

func TestFilesystemPlanDeniesByDefaultAndSeparatesOperations(t *testing.T) {
	d := fullExample(t)
	plan, err := d.FilesystemPlan(42, 1, 1_000_000, network(t, 42))
	if err != nil {
		t.Fatal(err)
	}
	ws := "/var/lib/agentgate/workspace"
	cases := []struct {
		path, operation, want string
	}{
		{ws + "/a.py", "read", "allow"}, {ws + "/a.py", "write", "allow"}, {ws + "/d/a.py", "create", "allow"},
		{ws + "/d", "mkdir", "allow"}, {ws + "/a.py", "delete", "allow"}, {ws + "/b", "rename", "allow"},
		{ws + "/l", "symlink", "allow"}, {ws + "/a.py", "metadata", "allow"},
		// A writable tree is never executable, even by mapping.
		{ws + "/tool", "execute", "deny"}, {ws + "/lib.so", "map_execute", "deny"},
		{ws + "/a.py", "hardlink", "deny"}, {ws + "/a.py", "descriptor_receive", "deny"},
		{"/tmp/x", "write", "allow"}, {"/tmp/x", "execute", "deny"},
		// System trees can be read and run but never changed.
		{"/usr/bin/python3", "execute", "allow"}, {"/usr/bin/python3", "read", "allow"},
		{"/usr/lib/x86_64-linux-gnu/libc.so.6", "map_execute", "allow"},
		{"/usr/lib/x86_64-linux-gnu/libc.so.6", "mprotect", "allow"},
		{"/usr/bin/python3", "write", "deny"}, {"/usr/bin/evil", "create", "deny"},
		{"/usr/bin/python3", "delete", "deny"}, {"/usr/bin/python3", "rename", "deny"},
		{"/usr/bin/python3", "metadata", "deny"},
		{"/etc/hosts", "read", "allow"}, {"/etc/hosts", "write", "deny"}, {"/etc/hosts", "execute", "deny"},
		{"/etc/shadow", "read", "deny"}, {"/etc/shadow", "mmap", "deny"},
		{"/proc/self/status", "read", "allow"}, {"/proc/sys/kernel/hostname", "read", "deny"}, {"/proc/kcore", "read", "deny"},
		{"/run/agentgate/taskboard/task.json", "read", "allow"}, {"/run/agentgate/taskboard/task.json", "write", "deny"},
		{"/dev/null", "write", "allow"}, {"/dev/zero", "read", "allow"}, {"/dev/sda", "read", "deny"}, {"/dev/null", "execute", "deny"},
		{"/root/.ssh/id_ed25519", "read", "deny"}, {"/var/lib/other", "read", "deny"}, {"/home/user/x", "write", "deny"},
		// Traversal reads exist for the ancestors only, not their children.
		{"/", "read", "allow"}, {"/var", "read", "allow"}, {"/var/lib", "read", "allow"}, {"/var/lib", "write", "deny"},
		{"/var/log/syslog", "read", "deny"}, {"/run", "read", "allow"}, {"/run/secrets/token", "read", "deny"},
	}
	for _, c := range cases {
		if got := plan.Effect(c.path, c.operation); got != c.want {
			t.Errorf("%s %s: got %s want %s", c.operation, c.path, got, c.want)
		}
	}
	// No socket LSM guard exists in the POC; the plan must say so.
	if plan.State().SocketGeneration != plan.State().Generation || plan.SocketMode() != fsrules.SocketsCgroupNetworkOnly || plan.SocketLSMGuard() {
		t.Fatalf("socket mode differs: %s lsm=%v", plan.SocketMode(), plan.SocketLSMGuard())
	}
	if plan.State().Pipes != 1|2|4|fsrules.InheritedStdio {
		t.Fatalf("pipe rights differ: %b", plan.State().Pipes)
	}
	if err := plan.CheckAccess(42, 500); err != nil {
		t.Fatalf("the compiled plan cannot install: %v", err)
	}
}

func TestFilesystemPlanRequiresLiveNetworkEvidenceForItsDomain(t *testing.T) {
	d := fullExample(t)
	if _, err := d.FilesystemPlan(42, 1, 1_000_000, fsrules.CgroupNetworkGuard{}); err == nil {
		t.Fatal("a plan let socket I/O through without network guard evidence")
	}
	if _, err := d.FilesystemPlan(42, 1, 1_000_000, network(t, 43)); err == nil {
		t.Fatal("a plan accepted network guard evidence for another domain")
	}
	plan, err := d.FilesystemPlan(42, 1, 1_000_000, network(t, 42))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Domain() != 42 || plan.CheckAccess(42, 500) != nil {
		t.Fatal("the evidenced plan does not install on its own domain")
	}
}

func TestMemoryExecuteRequiresExplicitOptIn(t *testing.T) {
	d := fullExample(t)
	plan, err := d.FilesystemPlan(42, 1, 1_000_000, network(t, 42))
	if err != nil {
		t.Fatal(err)
	}
	if plan.State().Memory&4 != 0 || plan.State().Memory&(1|2|8|16) != 1|2|8|16 {
		t.Fatalf("default anonymous memory rights differ: %b", plan.State().Memory)
	}
	d.Filesystem.Memory.AnonymousExecute = true
	plan, err = d.FilesystemPlan(42, 1, 1_000_000, network(t, 42))
	if err != nil {
		t.Fatal(err)
	}
	if plan.State().Memory&4 == 0 {
		t.Fatal("explicit executable anonymous memory was not granted")
	}
}

func TestFilesystemValidationRefusesDangerousShapes(t *testing.T) {
	mutate := map[string]func(*Document){
		"relative workspace":        func(d *Document) { d.Filesystem.Workspace = "work" },
		"root workspace":            func(d *Document) { d.Filesystem.Workspace = "/" },
		"unclean path":              func(d *Document) { d.Filesystem.Scratch = []string{"/tmp/../etc"} },
		"writable proc":             func(d *Document) { d.Filesystem.Scratch = []string{"/proc/self"} },
		"writable usr":              func(d *Document) { d.Filesystem.Scratch = []string{"/usr/local"} },
		"writable parent of dev":    func(d *Document) { d.Filesystem.Scratch = []string{"/"} },
		"writable bridge":           func(d *Document) { d.Filesystem.Scratch = []string{"/run/agentgate/taskboard"} },
		"executable workspace":      func(d *Document) { d.Filesystem.Execute = []string{"/var/lib/agentgate/workspace/bin"} },
		"executable parent of work": func(d *Document) { d.Filesystem.Execute = []string{"/var/lib"} },
		"unknown device":            func(d *Document) { d.Filesystem.Devices = []string{"/dev/sda"} },
		"duplicate device":          func(d *Document) { d.Filesystem.Devices = []string{"/dev/null", "/dev/null"} },
		"missing array":             func(d *Document) { d.Filesystem.Deny = nil },
		"too many paths":            func(d *Document) { d.Filesystem.ReadOnly = make([]string, 17) },
		"unknown signal":            func(d *Document) { d.Process.Signals = []string{"SIGSEGV"} },
		"duplicate signal":          func(d *Document) { d.Process.Signals = []string{"SIGTERM", "SIGTERM"} },
		"missing signals":           func(d *Document) { d.Process.Signals = nil },
	}
	for name, change := range mutate {
		d := fullExample(t)
		change(&d)
		if d.Validate() == nil {
			t.Errorf("%s: validation passed", name)
		}
	}
}

func TestDenyEntriesAreAbsolute(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(*Filesystem)
		error string // empty means the document must validate
	}{
		{"deny below an allowance", func(f *Filesystem) { f.Deny = []string{"/etc/shadow"} }, ""},
		{"read below a deny", func(f *Filesystem) {
			f.Deny = []string{"/etc/secret"}
			f.ReadOnly = append(f.ReadOnly, "/etc/secret/readable")
		},
			"filesystem.read_only entry /etc/secret/readable is below filesystem.deny entry /etc/secret"},
		{"execute below a deny", func(f *Filesystem) { f.Deny = []string{"/opt"}; f.Execute = append(f.Execute, "/opt/tool") },
			"filesystem.execute entry /opt/tool is below filesystem.deny entry /opt"},
		{"execute equal to a deny", func(f *Filesystem) { f.Deny = []string{"/usr"} },
			"filesystem.execute entry /usr is equal to filesystem.deny entry /usr"},
		{"read equal to a deny", func(f *Filesystem) { f.Deny = []string{"/etc"} },
			"filesystem.read_only entry /etc is equal to filesystem.deny entry /etc"},
		{"workspace below a deny", func(f *Filesystem) { f.Deny = []string{"/var/lib"} },
			"filesystem.workspace entry /var/lib/agentgate/workspace is below filesystem.deny entry /var/lib"},
		{"scratch equal to a deny", func(f *Filesystem) { f.Deny = []string{"/tmp"} },
			"filesystem.scratch entry /tmp is equal to filesystem.deny entry /tmp"},
		{"scratch below a deny", func(f *Filesystem) { f.Scratch = []string{"/srv/data/out"}; f.Deny = []string{"/srv/data"} },
			"filesystem.scratch entry /srv/data/out is below filesystem.deny entry /srv/data"},
		{"device below a deny", func(f *Filesystem) { f.Deny = []string{"/dev"} },
			"filesystem.devices entry /dev/null is below filesystem.deny entry /dev"},
		{"device equal to a deny", func(f *Filesystem) { f.Deny = []string{"/dev/urandom"} },
			"filesystem.devices entry /dev/urandom is equal to filesystem.deny entry /dev/urandom"},
		// Component boundaries: a shared string prefix is not a parent.
		{"sibling with a shared prefix", func(f *Filesystem) { f.Deny = []string{"/et"}; f.ReadOnly = append(f.ReadOnly, "/etcetera") }, ""},
		{"deny with a longer sibling name", func(f *Filesystem) { f.Deny = []string{"/etcetera"} }, ""},
		{"deny of a sibling tree", func(f *Filesystem) {
			f.Deny = []string{"/usr2", "/proc/sys"}
			f.ReadOnly = append(f.ReadOnly, "/usr2x")
		}, ""},
		{"deny of an ancestor's other child", func(f *Filesystem) { f.Deny = []string{"/var/log"} }, ""},
	}
	for _, c := range cases {
		d := fullExample(t)
		c.edit(d.Filesystem)
		err := d.Validate()
		switch {
		case c.error == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.error != "" && err == nil:
			t.Errorf("%s: validated, but the deny would not be absolute", c.name)
		case c.error != "" && !strings.Contains(err.Error(), c.error):
			t.Errorf("%s: error %q does not name %q", c.name, err, c.error)
		}
	}
}

// TestShippedDocumentsValidate runs every shipped preset and example through
// the same validator, including the copies the access engine embeds.
func TestShippedDocumentsValidate(t *testing.T) {
	for _, dir := range []string{"../../poc/ssh-diagnostic", "../access"} {
		raw, err := os.ReadFile(filepath.Join(dir, "policy.full.example.json"))
		if err != nil {
			t.Fatal(err)
		}
		example, err := Parse(raw)
		if err != nil {
			t.Fatalf("%s example: %v", dir, err)
		}
		raw, err = os.ReadFile(filepath.Join(dir, "presets.json"))
		if err != nil {
			t.Fatal(err)
		}
		var presets struct {
			Presets map[string]struct {
				Filesystem  json.RawMessage `json:"filesystem"`
				Process     json.RawMessage `json:"process"`
				FromExample string          `json:"from_example"`
			} `json:"presets"`
		}
		if err = json.Unmarshal(raw, &presets); err != nil || len(presets.Presets) == 0 {
			t.Fatalf("%s presets: %v", dir, err)
		}
		for name, preset := range presets.Presets {
			if preset.FromExample != "" {
				continue // the example itself validated above
			}
			d := example
			d.Filesystem, d.Process = &Filesystem{}, &Process{}
			for _, part := range []struct {
				raw  json.RawMessage
				into any
			}{{preset.Filesystem, d.Filesystem}, {preset.Process, d.Process}} {
				decoder := json.NewDecoder(bytes.NewReader(part.raw))
				decoder.DisallowUnknownFields()
				if err = decoder.Decode(part.into); err != nil {
					t.Fatalf("%s preset %s: %v", dir, name, err)
				}
			}
			if err = d.Validate(); err != nil {
				t.Errorf("%s preset %s: %v", dir, name, err)
			}
		}
	}
}

func TestParseRejectsUnknownHostControlFields(t *testing.T) {
	raw, err := os.ReadFile("../../poc/ssh-diagnostic/policy.full.example.json")
	if err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(string(raw), `"anonymous_execute": false`, `"anonymous_execute": false, "jit": true`, 1)
	if _, err = Parse([]byte(bad)); err == nil {
		t.Fatal("an unknown filesystem field was accepted")
	}
	bad = strings.Replace(string(raw), `"read_only": [`, `"read_only": [ "/etc", `, 1)
	if _, err = Parse([]byte(bad)); err == nil {
		t.Fatal("a repeated read-only path was accepted")
	}
}

func TestProcessPlanBindsSignalsAndDomain(t *testing.T) {
	d := fullExample(t)
	plan, err := d.ProcessPlan(42, 1, 1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	want := uint64(1)<<0 | 1<<1 | 1<<8 | 1<<9 | 1<<11 | 1<<14 | 1<<17 | 1<<18
	if plan.State().Signals != want || plan.Domain() != 42 || plan.State().Generation != 1 {
		t.Fatalf("process plan differs: %+v", plan.State())
	}
	if plan.State().Signals&(1<<(11-1)) != 0 {
		t.Fatal("SIGSEGV entered the allowlist")
	}
}
