// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package pocpolicy

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"alloyium.local/kernel-poc/internal/fsrules"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/processrules"
)

// VersionV1 is the network-only document. VersionV2 adds explicit filesystem
// and process sections that the host kernel components enforce.
const (
	VersionV1 = "agentgate.network-poc.v1"
	VersionV2 = "agentgate.poc.v2"
)

// Filesystem lists every path a command may touch. Everything else is denied.
// A path in more than one list receives the union of those rights, except that
// a deny entry always overrides an allowance that is less specific.
type Filesystem struct {
	// Workspace and Scratch are writable trees. They never grant execution.
	Workspace string   `json:"workspace"`
	Scratch   []string `json:"scratch"`
	// ReadOnly trees can be read and mapped, but not changed or executed.
	ReadOnly []string `json:"read_only"`
	// Execute trees can be read, mapped executable and run as programs.
	Execute []string `json:"execute"`
	// Devices is a subset of the character devices a shell needs.
	Devices []string `json:"devices"`
	// Deny trees refuse every operation, even below an allowed tree.
	Deny   []string `json:"deny"`
	Memory Memory   `json:"memory"`
}

// Memory controls anonymous mappings. Executable anonymous memory is what a
// JIT or libffi closure needs, and it weakens write-xor-execute separation.
type Memory struct {
	AnonymousExecute bool `json:"anonymous_execute"`
}

// Process limits signals to the command's own tree. Tracing is always denied.
type Process struct {
	Signals []string `json:"signals"`
}

var signalNumbers = map[string]int{
	"SIGHUP": 1, "SIGINT": 2, "SIGQUIT": 3, "SIGKILL": 9, "SIGUSR1": 10, "SIGUSR2": 12,
	"SIGPIPE": 13, "SIGALRM": 14, "SIGTERM": 15, "SIGCHLD": 17, "SIGCONT": 18,
	"SIGSTOP": 19, "SIGWINCH": 28,
}

var allowedDevices = map[string]bool{
	"/dev/null": true, "/dev/zero": true, "/dev/full": true,
	"/dev/random": true, "/dev/urandom": true, "/dev/tty": true,
}

// Tree prefixes that can never be made writable, because they expose kernel
// state or the trusted bridge. Read-only access to /proc and /sys is allowed.
var protectedWrite = []string{"/proc", "/sys", "/dev", "/run/agentgate", "/sbin", "/bin", "/usr", "/lib", "/lib64", "/etc"}

const maxListEntries = 16

func cleanTree(label, value string) error {
	if value == "" || value[0] != '/' || path.Clean(value) != value || strings.ContainsRune(value, 0) || len(value) > 160 {
		return fmt.Errorf("%s requires a canonical absolute path of at most 160 bytes", label)
	}
	if value == "/" {
		return fmt.Errorf("%s may not be the filesystem root", label)
	}
	return nil
}

func within(parent, child string) bool {
	return child == parent || strings.HasPrefix(child, parent+"/")
}

func (f Filesystem) validate() error {
	if err := cleanTree("filesystem.workspace", f.Workspace); err != nil {
		return err
	}
	lists := []struct {
		name   string
		values []string
	}{{"scratch", f.Scratch}, {"read_only", f.ReadOnly}, {"execute", f.Execute}, {"deny", f.Deny}}
	for _, list := range lists {
		if list.values == nil || len(list.values) > maxListEntries {
			return fmt.Errorf("filesystem.%s requires an explicit array of at most %d paths", list.name, maxListEntries)
		}
		seen := map[string]bool{}
		for _, value := range list.values {
			if err := cleanTree("filesystem."+list.name, value); err != nil {
				return err
			}
			if seen[value] {
				return fmt.Errorf("filesystem.%s repeats %s", list.name, value)
			}
			seen[value] = true
		}
	}
	if f.Devices == nil || len(f.Devices) > len(allowedDevices) {
		return errors.New("filesystem.devices requires an explicit array")
	}
	seen := map[string]bool{}
	for _, device := range f.Devices {
		if !allowedDevices[device] || seen[device] {
			return fmt.Errorf("filesystem.devices supports only unique %s", "/dev/{null,zero,full,random,urandom,tty}")
		}
		seen[device] = true
	}
	for _, writable := range append([]string{f.Workspace}, f.Scratch...) {
		for _, protected := range protectedWrite {
			if within(protected, writable) || within(writable, protected) {
				return fmt.Errorf("%s may not be writable: it overlaps protected tree %s", writable, protected)
			}
		}
	}
	for _, run := range f.Execute {
		for _, writable := range append([]string{f.Workspace}, f.Scratch...) {
			if within(writable, run) || within(run, writable) {
				return fmt.Errorf("%s is both writable and executable; writable trees never run code", run)
			}
		}
	}
	return nil
}

func (p Process) validate() error {
	if p.Signals == nil || len(p.Signals) > len(signalNumbers) {
		return errors.New("process.signals requires an explicit array")
	}
	seen := map[string]bool{}
	for _, name := range p.Signals {
		if _, ok := signalNumbers[name]; !ok || seen[name] {
			return fmt.Errorf("process.signals supports only unique names from %s", signalList())
		}
		seen[name] = true
	}
	return nil
}

func signalList() string {
	names := make([]string, 0, len(signalNumbers))
	for name := range signalNumbers {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// HasHostControls reports whether the document asks for kernel filesystem and
// process enforcement. A version one document never does.
func (d Document) HasHostControls() bool { return d.Filesystem != nil || d.Process != nil }

func (d Document) validateHostControls() error {
	switch d.Version {
	case VersionV1:
		if d.HasHostControls() {
			return errors.New("filesystem and process sections require version " + VersionV2)
		}
		return nil
	case VersionV2:
		if d.Filesystem == nil || d.Process == nil {
			return errors.New("version " + VersionV2 + " requires explicit filesystem and process sections")
		}
		if err := d.Filesystem.validate(); err != nil {
			return err
		}
		return d.Process.validate()
	}
	return errors.New("network policy requires version " + VersionV1 + " or " + VersionV2)
}

// ancestors returns every proper ancestor directory of the trees. Tools stat
// each component, and the file hook treats a stat like a read of that path.
func ancestors(trees []string) []string {
	set := map[string]bool{}
	for _, tree := range trees {
		for dir := path.Dir(tree); dir != "/" && dir != "."; dir = path.Dir(dir) {
			set[dir] = true
		}
	}
	out := make([]string, 0, len(set))
	for dir := range set {
		out = append(out, dir)
	}
	sort.Strings(out)
	return out
}

var writableOperations = []string{"read", "write", "create", "mkdir", "delete", "rename", "symlink", "metadata", "mmap", "mprotect"}
var readableOperations = []string{"read", "mmap", "mprotect"}
var executableOperations = []string{"read", "mmap", "map_execute", "mprotect"}
var denyOperations = []string{"read", "write", "create", "mkdir", "delete", "rename", "symlink", "metadata", "mmap", "map_execute", "mprotect", "descriptor_receive"}

// Rules builds the file and program rules that realize the document.
func (f Filesystem) Rules() (policy.Files, policy.Programs, error) {
	if err := f.validate(); err != nil {
		return policy.Files{}, policy.Programs{}, err
	}
	files := policy.Files{Defaults: policy.FileDefaults{Read: "deny", Write: "deny"}, ResourceUse: "recheck-and-terminate", Rules: []policy.FileRule{}}
	programs := policy.Programs{Default: "deny", Rules: []policy.ProgramRule{}}
	count := 0
	add := func(prefix, kind, target string, operations []string, effect string) {
		count++
		files.Rules = append(files.Rules, policy.FileRule{ID: fmt.Sprintf("%s-%d", prefix, count),
			Selector: policy.Selector{Kind: kind, Path: target}, Operations: operations, Effect: effect})
	}
	trees := append([]string{f.Workspace}, f.Scratch...)
	trees = append(trees, f.ReadOnly...)
	trees = append(trees, f.Execute...)
	devices := append([]string{}, f.Devices...)
	sort.Strings(devices)
	trees = append(trees, devices...)
	add("root", "exact", "/", []string{"read"}, "allow")
	for _, dir := range ancestors(trees) {
		add("parent", "exact", dir, []string{"read"}, "allow")
	}
	for _, tree := range f.ReadOnly {
		add("readonly", "subtree", tree, readableOperations, "allow")
	}
	for _, tree := range f.Execute {
		add("execute", "subtree", tree, executableOperations, "allow")
		programs.Rules = append(programs.Rules, policy.ProgramRule{ID: fmt.Sprintf("program-%d", len(programs.Rules)+1),
			Selector: policy.Selector{Kind: "subtree", Path: tree}, Effect: "allow"})
	}
	add("workspace", "subtree", f.Workspace, writableOperations, "allow")
	for _, tree := range f.Scratch {
		add("scratch", "subtree", tree, writableOperations, "allow")
	}
	for _, device := range devices {
		add("device", "exact", device, []string{"read", "write"}, "allow")
	}
	for _, tree := range f.Deny {
		add("deny", "subtree", tree, denyOperations, "deny")
		programs.Rules = append(programs.Rules, policy.ProgramRule{ID: fmt.Sprintf("program-%d", len(programs.Rules)+1),
			Selector: policy.Selector{Kind: "subtree", Path: tree}, Effect: "deny"})
	}
	return files, programs, nil
}

// RuntimeSection carries the explicit pipe and anonymous memory rights. The
// seccomp section is only schema padding: this POC filters no syscalls.
func (f Filesystem) RuntimeSection(signals *Process) policy.Runtime {
	memory := []string{"map", "protect", "read", "write"}
	if f.Memory.AnonymousExecute {
		memory = append(memory, "execute")
	}
	runtime := policy.Runtime{
		Profile: "managed-unprivileged.v1", UID: 65534, GID: 65534, SupplementaryGroups: []int{},
		Capabilities: []string{}, NoNewPrivileges: true,
		Seccomp: policy.Seccomp{Profile: "explicit-allowlist-notify.v2", Architecture: "x86_64", Default: "deny", AllowSyscalls: []string{}},
		IPC:     &policy.IPCPolicy{Default: "deny", Pipes: []string{"create", "read", "write"}},
		Memory:  &policy.MemoryPolicy{Default: "deny", Anonymous: memory, Heap: "deny"},
	}
	if signals != nil {
		numbers := []int{}
		for _, name := range signals.Signals {
			numbers = append(numbers, signalNumbers[name])
		}
		sort.Ints(numbers)
		runtime.Signals = &numbers
	}
	return runtime
}

// FilesystemPlan compiles the filesystem section for one prepared domain.
//
// The POC attaches no socket LSM guard. The plan therefore uses
// fsrules.SocketsCgroupNetworkOnly: VFS reads and writes on socket descriptors
// pass this component, and the only kernel control over sockets is the six
// cgroup network hooks, which bound IP traffic by address. network must be live evidence of those hooks on
// this domain (fsrules.ObserveCgroupNetworkGuard); without it the plan fails.
func (d Document) FilesystemPlan(domain, generation, deadline uint64, network fsrules.CgroupNetworkGuard) (fsrules.Plan, error) {
	if err := d.Validate(); err != nil {
		return fsrules.Plan{}, err
	}
	if d.Filesystem == nil || d.Process == nil {
		return fsrules.Plan{}, errors.New("the document has no filesystem section")
	}
	files, programs, err := d.Filesystem.Rules()
	if err != nil {
		return fsrules.Plan{}, err
	}
	plan, err := fsrules.CompileWithRuntime(files, programs, d.Filesystem.RuntimeSection(d.Process), domain, generation, deadline)
	if err != nil {
		return fsrules.Plan{}, err
	}
	// The gateway hands the command its stdio as pipes it created outside the domain.
	return plan.WithMutationEnforcement().WithInheritedStdio().WithCgroupNetworkGuardOnly(network)
}

// ProcessPlan compiles the signal and tracing restrictions for one domain.
func (d Document) ProcessPlan(domain, generation, deadline uint64) (processrules.Plan, error) {
	if err := d.Validate(); err != nil {
		return processrules.Plan{}, err
	}
	if d.Filesystem == nil || d.Process == nil {
		return processrules.Plan{}, errors.New("the document has no process section")
	}
	return processrules.Compile(d.Filesystem.RuntimeSection(d.Process), domain, generation, deadline)
}
