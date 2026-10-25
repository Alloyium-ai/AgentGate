// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Package access applies typed grant and revoke edits to a POC policy
// document. Each edit returns a new validated document and never changes its
// input. The rules mirror poc/ssh-diagnostic/grants.py: a writable tree never
// becomes executable, a denied tree must be revoked before it is granted,
// protected trees stay read-only, a repeated grant is a no-op, and a version
// one document becomes version two only when the caller asks for it.
//
// This package is the source of truth for the control plane API. The Python
// grant command keeps the same semantics for the standalone SSH POC, and a
// parity test runs both on the same inputs.
package access

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"reflect"
	"sort"
	"strings"

	"alloyium.local/kernel-poc/internal/pocpolicy"
)

// Error codes. They match the grant command's exit categories.
const (
	CodeUsage    = "usage"            // an invalid action, value or path
	CodeConflict = "conflict"         // the edit contradicts another entry
	CodeUpgrade  = "upgrade_required" // the edit needs version two; set UpgradeToV2
	CodeRejected = "rejected"         // the resulting document fails validation
)

// Error is a typed edit failure.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

func usage(format string, args ...any) error {
	return &Error{CodeUsage, fmt.Sprintf(format, args...)}
}
func conflict(format string, args ...any) error {
	return &Error{CodeConflict, fmt.Sprintf(format, args...)}
}

// Actions.
const (
	ActionRead     = "read"
	ActionWrite    = "write"
	ActionExec     = "exec"
	ActionDeny     = "deny"
	ActionAllowWeb = "allow-web"
	ActionDenyWeb  = "deny-web"
	ActionDNS      = "dns"
	ActionSignal   = "signal"
	ActionAnonExec = "anon-exec"
	ActionMount    = "mount"
	ActionUnmount  = "unmount"
	ActionDevice   = "device"
	ActionPreset   = "preset"
	ActionRevoke   = "revoke"
)

// Actions lists every action, and RevokeKinds every kind revoke accepts.
var (
	Actions     = []string{ActionRead, ActionWrite, ActionExec, ActionDeny, ActionAllowWeb, ActionDenyWeb, ActionDNS, ActionSignal, ActionAnonExec, ActionMount, ActionUnmount, ActionDevice, ActionPreset, ActionRevoke}
	RevokeKinds = []string{"web", "dns", "read", "write", "exec", "deny", "signal", "anon-exec", "mount", "device"}
	// Devices are the only character devices a policy may allow.
	Devices = []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty"}
)

// Edit is one typed change.
//
//	read|write|exec|deny   Values = [PATH]
//	allow-web|deny-web     Values = protocols (http, https, quic, all); empty means all
//	dns                    Values = 1..3 public IPv4 resolvers, replacing the list
//	signal                 Values = signal names (TERM or SIGTERM)
//	anon-exec              no values
//	mount                  Values = [NAME or /var/lib/agentgate/mounts/NAME], Mode read-only|read-write
//	unmount                Values = [NAME]
//	device                 Values = [one of Devices]
//	preset                 Values = [PRESET]
//	revoke                 Kind = one of RevokeKinds, Values as for the grant
type Edit struct {
	Action      string   `json:"action"`
	Kind        string   `json:"kind,omitempty"`
	Values      []string `json:"values,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	UpgradeToV2 bool     `json:"upgrade_to_v2,omitempty"`
}

// Result is the outcome of one edit.
type Result struct {
	Document pocpolicy.Document `json:"document"`
	Changed  bool               `json:"changed"`
	Message  string             `json:"message"`
	Notices  []string           `json:"notices"`
}

// Bounds on edit input.
const (
	MaxValues     = 16
	MaxValueBytes = 160
)

// WritableMount is the agent workspace that is always a writable mount.
const WritableMount = "/var/lib/agentgate/workspace"

// MountRoot is where host folders appear inside the agent.
const MountRoot = "/var/lib/agentgate/mounts"

type webRule struct {
	protocol string
	port     int
}

var web = map[string]webRule{"http": {"tcp", 80}, "https": {"tcp", 443}, "quic": {"udp", 443}}
var webOrder = []string{"http", "https", "quic"}

func clone(d pocpolicy.Document) pocpolicy.Document {
	raw, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}
	var out pocpolicy.Document
	if err := json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return out
}

func within(parent, child string) bool {
	parent = strings.TrimRight(parent, "/")
	return child == parent || strings.HasPrefix(child, parent+"/")
}

func covering(entries []string, p string) string {
	for _, e := range entries {
		if within(e, p) {
			return e
		}
	}
	return ""
}

// ContainerPath validates a canonical absolute path inside the agent.
func ContainerPath(value string) (string, error) {
	if !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\x00\n") {
		return "", usage("a path inside the agent must be absolute: %q", value)
	}
	stripped := strings.TrimRight(value, "/")
	if stripped == "" {
		stripped = "/"
	}
	bad := false
	for _, part := range strings.Split(stripped, "/")[1:] {
		if part == "" || part == "." || part == ".." {
			bad = true
		}
	}
	if stripped == "/" || bad || path.Clean(stripped) != stripped {
		return "", usage("use a canonical absolute path other than / (no ., .., or //): %q", value)
	}
	if len(stripped) > MaxValueBytes {
		return "", usage("a policy path is limited to 160 bytes: %q", value)
	}
	return stripped, nil
}

func webProtocols(names []string) (map[string]bool, error) {
	chosen := map[string]bool{}
	if len(names) == 0 {
		names = []string{"all"}
	}
	for _, name := range names {
		switch {
		case name == "all":
			for k := range web {
				chosen[k] = true
			}
		case web[name] != webRule{}:
			chosen[name] = true
		default:
			return nil, usage("web protocol must be http, https, quic, or all: %q", name)
		}
	}
	return chosen, nil
}

// CurrentWeb names the web protocols a document allows.
func CurrentWeb(d pocpolicy.Document) map[string]bool {
	names := map[string]bool{}
	for _, r := range d.Web.Rules {
		for name, w := range web {
			if r.Protocol == w.protocol && r.Port == w.port {
				names[name] = true
			}
		}
	}
	return names
}

func setWeb(d *pocpolicy.Document, names map[string]bool) {
	if d.Web.Destination == "" {
		d.Web.Destination = "public-ipv4"
	}
	d.Web.Rules = []pocpolicy.WebRule{}
	for _, name := range webOrder {
		if names[name] {
			d.Web.Rules = append(d.Web.Rules, pocpolicy.WebRule{Protocol: web[name].protocol, Port: web[name].port})
		}
	}
}

func signalName(value string) string {
	name := strings.ToUpper(value)
	if strings.HasPrefix(name, "SIG") {
		return name
	}
	return "SIG" + name
}

// MountName accepts NAME or /var/lib/agentgate/mounts/NAME and returns NAME.
func MountName(value string) (string, error) {
	value = strings.TrimPrefix(value, MountRoot+"/")
	if len(value) < 1 || len(value) > 32 || !(value[0] >= 'a' && value[0] <= 'z' || value[0] >= '0' && value[0] <= '9') {
		return "", usage("a mount name needs 1..32 of a-z 0-9 _ - and must start with a letter or digit: %q", value)
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return "", usage("a mount name needs 1..32 of a-z 0-9 _ - and must start with a letter or digit: %q", value)
		}
	}
	return value, nil
}

// Upgrade returns the version two form of a version one document: every
// network field is kept and the full example's host controls are added.
func Upgrade(d pocpolicy.Document) (pocpolicy.Document, error) {
	example, err := FullExample()
	if err != nil {
		return d, err
	}
	out := clone(d)
	out.Version = pocpolicy.VersionV2
	if out.Filesystem == nil {
		fs := *clone(example).Filesystem
		out.Filesystem = &fs
	}
	if out.Process == nil {
		p := *clone(example).Process
		out.Process = &p
	}
	return out, nil
}

type editor struct {
	edit    Edit
	notices []string
}

func (e *editor) needsV2(d pocpolicy.Document, action string) (pocpolicy.Document, error) {
	switch d.Version {
	case pocpolicy.VersionV2:
		return d, nil
	case pocpolicy.VersionV1:
	default:
		return d, &Error{CodeRejected, fmt.Sprintf("unknown policy version %q", d.Version)}
	}
	if e.edit.UpgradeToV2 {
		e.notices = append(e.notices, "upgraded the policy to version two; the network section is unchanged")
		return Upgrade(d)
	}
	return d, &Error{CodeUpgrade, fmt.Sprintf("%q needs a version two policy (filesystem and process controls). Upgrading keeps every network field and adds the conservative host controls of policy.full.example.json. The BPF LSM filesystem and process components have not been exercised on a BPF LSM kernel; the first command may fail closed. Set upgrade_to_v2.", action)}
}

func onePath(values []string) (string, error) {
	if len(values) != 1 {
		return "", usage("this edit takes exactly one path")
	}
	return ContainerPath(values[0])
}

func (e *editor) path(d pocpolicy.Document, kind string) (pocpolicy.Document, string, error) {
	p, err := onePath(e.edit.Values)
	if err != nil {
		return d, "", err
	}
	d, err = e.needsV2(clone(d), kind)
	if err != nil {
		return d, "", err
	}
	fs := d.Filesystem
	writable := append([]string{fs.Workspace}, fs.Scratch...)
	if denied := covering(fs.Deny, p); kind != ActionDeny && denied != "" {
		return d, "", conflict("%s is denied by the deny entry %s; revoke deny %s first", p, denied, denied)
	}
	switch kind {
	case ActionRead:
		all := append(append(append([]string{}, fs.ReadOnly...), fs.Execute...), writable...)
		if holder := covering(all, p); holder != "" {
			return d, fmt.Sprintf("%s is already readable through %s", p, holder), nil
		}
		fs.ReadOnly = append(fs.ReadOnly, p)
		return d, "read-only: added " + p, nil
	case ActionWrite:
		if holder := covering(writable, p); holder != "" {
			return d, fmt.Sprintf("%s is already writable through %s", p, holder), nil
		}
		for _, tree := range fs.Execute {
			if within(tree, p) || within(p, tree) {
				return d, "", conflict("%s overlaps the executable tree %s; writable trees never run code", p, tree)
			}
		}
		fs.Scratch = append(fs.Scratch, p)
		mounted := []string{WritableMount, "/tmp"}
		for _, s := range fs.Scratch {
			if within(MountRoot, s) {
				mounted = append(mounted, s)
			}
		}
		if covering(mounted, p) == "" {
			e.notices = append(e.notices, fmt.Sprintf("the container root is read-only: %s is writable only below a writable mount (the workspace, /tmp, or a read-write host folder)", p))
		}
		return d, "writable (never executable): added " + p, nil
	case ActionExec:
		for _, tree := range writable {
			if within(tree, p) || within(p, tree) {
				return d, "", conflict("%s overlaps the writable tree %s; writable trees never run code", p, tree)
			}
		}
		if holder := covering(fs.Execute, p); holder != "" {
			return d, fmt.Sprintf("%s is already executable through %s", p, holder), nil
		}
		fs.Execute = append(fs.Execute, p)
		return d, "executable: added " + p, nil
	case ActionDeny:
		if holder := covering(fs.Deny, p); holder != "" {
			return d, fmt.Sprintf("%s is already denied through %s", p, holder), nil
		}
		fs.Deny = append(fs.Deny, p)
		return d, "denied: added " + p, nil
	}
	return d, "", usage("unknown path edit %q", kind)
}

func (e *editor) signal(d pocpolicy.Document) (pocpolicy.Document, string, error) {
	if len(e.edit.Values) < 1 {
		return d, "", usage("signal needs at least one name")
	}
	d, err := e.needsV2(clone(d), ActionSignal)
	if err != nil {
		return d, "", err
	}
	added := []string{}
	for _, v := range e.edit.Values {
		name := signalName(v)
		present := false
		for _, s := range d.Process.Signals {
			present = present || s == name
		}
		if !present {
			d.Process.Signals = append(d.Process.Signals, name)
			added = append(added, name)
		}
	}
	if len(added) == 0 {
		return d, "signals: already allowed", nil
	}
	return d, "signals: added " + strings.Join(added, ", "), nil
}

func (e *editor) anonExec(d pocpolicy.Document, enable bool) (pocpolicy.Document, string, error) {
	if len(e.edit.Values) != 0 {
		return d, "", usage("anon-exec takes no values")
	}
	if !enable && d.Version != pocpolicy.VersionV2 {
		return clone(d), "anonymous execute: not granted", nil
	}
	d, err := e.needsV2(clone(d), ActionAnonExec)
	if err != nil {
		return d, "", err
	}
	d.Filesystem.Memory.AnonymousExecute = enable
	if enable {
		return d, "executable anonymous memory: on (weakens W^X)", nil
	}
	return d, "executable anonymous memory: off", nil
}

func (e *editor) web(d pocpolicy.Document, allow bool) (pocpolicy.Document, string, error) {
	names, err := webProtocols(e.edit.Values)
	if err != nil {
		return d, "", err
	}
	d = clone(d)
	present := CurrentWeb(d)
	for name := range names {
		if allow {
			present[name] = true
		} else {
			delete(present, name)
		}
	}
	setWeb(&d, present)
	labels := []string{}
	for _, n := range webOrder {
		if names[n] {
			labels = append(labels, n)
		}
	}
	verb := "allowed"
	if !allow {
		verb = "denied"
	}
	return d, fmt.Sprintf("public web: %s %s", verb, strings.Join(labels, ", ")), nil
}

func (e *editor) dns(d pocpolicy.Document) (pocpolicy.Document, string, error) {
	if len(e.edit.Values) < 1 {
		return d, "", usage("dns needs at least one resolver")
	}
	d = clone(d)
	resolvers := []string{}
	for _, v := range e.edit.Values {
		if !contains(resolvers, v) {
			resolvers = append(resolvers, v)
		}
	}
	d.DNS.Resolvers = resolvers
	return d, "dns resolvers: " + strings.Join(resolvers, ", "), nil
}

func (e *editor) mount(d pocpolicy.Document) (pocpolicy.Document, string, error) {
	if len(e.edit.Values) != 1 {
		return d, "", usage("mount takes exactly one NAME")
	}
	name, err := MountName(e.edit.Values[0])
	if err != nil {
		return d, "", err
	}
	readOnly := e.edit.Mode == "" || e.edit.Mode == "read-only"
	if !readOnly && e.edit.Mode != "read-write" {
		return d, "", usage("mount mode must be read-only or read-write")
	}
	p := MountRoot + "/" + name
	d, err = e.needsV2(clone(d), ActionMount)
	if err != nil {
		return d, "", err
	}
	fs := d.Filesystem
	if !readOnly {
		for _, tree := range fs.Execute {
			if within(tree, p) || within(p, tree) {
				return d, "", conflict("a writable mount at %s overlaps the executable tree %s", p, tree)
			}
		}
	}
	if readOnly {
		fs.Scratch = remove(fs.Scratch, p)
		if !contains(fs.ReadOnly, p) {
			fs.ReadOnly = append(fs.ReadOnly, p)
		}
		return d, fmt.Sprintf("host folder: %s (read-only)", p), nil
	}
	fs.ReadOnly = remove(fs.ReadOnly, p)
	if !contains(fs.Scratch, p) {
		fs.Scratch = append(fs.Scratch, p)
	}
	return d, fmt.Sprintf("host folder: %s (read-write, never executable)", p), nil
}

func (e *editor) unmount(d pocpolicy.Document) (pocpolicy.Document, string, error) {
	if len(e.edit.Values) != 1 {
		return d, "", usage("unmount takes exactly one NAME")
	}
	name, err := MountName(e.edit.Values[0])
	if err != nil {
		return d, "", err
	}
	p := MountRoot + "/" + name
	d = clone(d)
	if d.Version == pocpolicy.VersionV2 {
		d.Filesystem.ReadOnly = remove(d.Filesystem.ReadOnly, p)
		d.Filesystem.Scratch = remove(d.Filesystem.Scratch, p)
		d.Filesystem.Execute = remove(d.Filesystem.Execute, p)
	}
	return d, "host folder " + p + " removed", nil
}

// devicePath accepts exactly one of the six allowed device paths.
func devicePath(values []string) (string, error) {
	if len(values) != 1 {
		return "", usage("device takes exactly one of %s", strings.Join(Devices, ", "))
	}
	if !contains(Devices, values[0]) {
		return "", usage("a device is one of %s: %q", strings.Join(Devices, ", "), values[0])
	}
	return values[0], nil
}

func (e *editor) device(d pocpolicy.Document) (pocpolicy.Document, string, error) {
	p, err := devicePath(e.edit.Values)
	if err != nil {
		return d, "", err
	}
	d, err = e.needsV2(clone(d), ActionDevice)
	if err != nil {
		return d, "", err
	}
	fs := d.Filesystem
	if denied := covering(fs.Deny, p); denied != "" {
		return d, "", conflict("%s is denied by the deny entry %s; revoke deny %s first", p, denied, denied)
	}
	if contains(fs.Devices, p) {
		return d, "device " + p + " is already allowed", nil
	}
	fs.Devices = append(fs.Devices, p)
	return d, "device: added " + p, nil
}

func (e *editor) preset(d pocpolicy.Document) (pocpolicy.Document, string, error) {
	if len(e.edit.Values) != 1 {
		return d, "", usage("preset takes exactly one NAME")
	}
	presets, err := Presets()
	if err != nil {
		return d, "", err
	}
	p, ok := presets[e.edit.Values[0]]
	if !ok {
		names := make([]string, 0, len(presets))
		for n := range presets {
			names = append(names, n)
		}
		sort.Strings(names)
		return d, "", usage("unknown preset %q; choose one of: %s", e.edit.Values[0], strings.Join(names, ", "))
	}
	d, err = e.needsV2(clone(d), ActionPreset)
	if err != nil {
		return d, "", err
	}
	fs, proc := p.Filesystem, p.Process
	d.Filesystem, d.Process = &fs, &proc
	d = clone(d)
	chosen := map[string]bool{}
	for _, w := range p.Web {
		chosen[w] = true
	}
	setWeb(&d, chosen)
	return d, "preset: " + e.edit.Values[0], nil
}

func (e *editor) revoke(d pocpolicy.Document) (pocpolicy.Document, string, error) {
	kind, values := e.edit.Kind, e.edit.Values
	switch kind {
	case "web":
		return e.web(d, false)
	case "anon-exec":
		return e.anonExec(d, false)
	case "mount":
		return e.unmount(d)
	case "device":
		p, err := devicePath(values)
		if err != nil {
			return d, "", err
		}
		d = clone(d)
		if d.Version != pocpolicy.VersionV2 {
			return d, "device: not granted (version one policy)", nil
		}
		if !contains(d.Filesystem.Devices, p) {
			return d, "device: " + p + " was not granted", nil
		}
		d.Filesystem.Devices = remove(d.Filesystem.Devices, p)
		return d, "device: removed " + p, nil
	}
	if !contains(RevokeKinds, kind) {
		return d, "", usage("revoke kind must be one of %s", strings.Join(RevokeKinds, ", "))
	}
	if len(values) == 0 {
		return d, "", usage("revoke %s needs a value", kind)
	}
	d = clone(d)
	switch kind {
	case "dns":
		kept := []string{}
		for _, ip := range d.DNS.Resolvers {
			if !contains(values, ip) {
				kept = append(kept, ip)
			}
		}
		d.DNS.Resolvers = kept
		return d, "dns resolvers: " + strings.Join(kept, ", "), nil
	case "signal":
		if d.Version != pocpolicy.VersionV2 {
			return d, "signals: not granted", nil
		}
		names := []string{}
		for _, v := range values {
			names = append(names, signalName(v))
		}
		kept := []string{}
		for _, s := range d.Process.Signals {
			if !contains(names, s) {
				kept = append(kept, s)
			}
		}
		d.Process.Signals = kept
		return d, "signals: removed " + strings.Join(names, ", "), nil
	}
	if len(values) != 1 {
		return d, "", usage("revoke %s takes exactly one path", kind)
	}
	p, err := ContainerPath(values[0])
	if err != nil {
		return d, "", err
	}
	if d.Version != pocpolicy.VersionV2 {
		return d, fmt.Sprintf("%s: not granted (version one policy)", kind), nil
	}
	fs := d.Filesystem
	if kind == "write" && p == fs.Workspace {
		return d, "", conflict("the workspace is required; use deny PATH to hide a subtree of it")
	}
	lists := map[string]*[]string{"read": &fs.ReadOnly, "write": &fs.Scratch, "exec": &fs.Execute, "deny": &fs.Deny}
	if list := lists[kind]; contains(*list, p) {
		*list = remove(*list, p)
		return d, fmt.Sprintf("%s: removed %s", kind, p), nil
	}
	if kind != "deny" {
		holders := map[string][]string{
			"read":  append(append(append(append([]string{}, fs.ReadOnly...), fs.Execute...), fs.Workspace), fs.Scratch...),
			"write": append([]string{fs.Workspace}, fs.Scratch...),
			"exec":  fs.Execute,
		}[kind]
		if holder := covering(holders, p); holder != "" {
			state := map[string]string{"read": "readable", "write": "writable", "exec": "executable"}[kind]
			return d, "", conflict("%s is not a separate entry; it stays %s through %s. Revoke %s, or add deny %s", p, state, holder, holder, p)
		}
	}
	return d, fmt.Sprintf("%s: %s was not granted", kind, p), nil
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func remove(list []string, v string) []string {
	out := []string{}
	for _, item := range list {
		if item != v {
			out = append(out, item)
		}
	}
	return out
}

func checkEdit(e Edit) error {
	if !contains(Actions, e.Action) {
		return usage("unknown action %q", e.Action)
	}
	if e.Kind != "" && e.Action != ActionRevoke {
		return usage("only revoke takes a kind")
	}
	if e.Mode != "" && e.Action != ActionMount {
		return usage("only mount takes a mode")
	}
	if len(e.Values) > MaxValues {
		return usage("an edit takes at most %d values", MaxValues)
	}
	for _, v := range e.Values {
		if len(v) > MaxValueBytes || strings.ContainsAny(v, "\x00\n\r") {
			return usage("an edit value is limited to %d bytes on one line", MaxValueBytes)
		}
	}
	return nil
}

// Apply performs one edit on a copy of d and validates the result with
// pocpolicy. The input document must itself be valid.
func Apply(d pocpolicy.Document, e Edit) (Result, error) {
	if err := checkEdit(e); err != nil {
		return Result{}, err
	}
	if err := d.Validate(); err != nil {
		return Result{}, &Error{CodeRejected, "the current policy is invalid: " + err.Error()}
	}
	ed := &editor{edit: e}
	var out pocpolicy.Document
	var message string
	var err error
	switch e.Action {
	case ActionRead, ActionWrite, ActionExec, ActionDeny:
		out, message, err = ed.path(d, e.Action)
	case ActionAllowWeb:
		out, message, err = ed.web(d, true)
	case ActionDenyWeb:
		out, message, err = ed.web(d, false)
	case ActionDNS:
		out, message, err = ed.dns(d)
	case ActionSignal:
		out, message, err = ed.signal(d)
	case ActionAnonExec:
		out, message, err = ed.anonExec(d, true)
	case ActionMount:
		out, message, err = ed.mount(d)
	case ActionUnmount:
		out, message, err = ed.unmount(d)
	case ActionDevice:
		out, message, err = ed.device(d)
	case ActionPreset:
		out, message, err = ed.preset(d)
	case ActionRevoke:
		out, message, err = ed.revoke(d)
	}
	if err != nil {
		return Result{}, err
	}
	if verr := out.Validate(); verr != nil {
		return Result{}, &Error{CodeRejected, verr.Error()}
	}
	notices := ed.notices
	if notices == nil {
		notices = []string{}
	}
	return Result{Document: out, Changed: !reflect.DeepEqual(clone(d), out), Message: message, Notices: notices}, nil
}

// IsCode reports whether err is an access Error with code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}
