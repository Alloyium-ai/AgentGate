// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package access

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"alloyium.local/kernel-poc/internal/pocpolicy"
)

const pocDir = "../../poc/ssh-diagnostic"

func TestEmbeddedPresetDataMatchesThePOC(t *testing.T) {
	for name, embedded := range map[string][]byte{"presets.json": presetsJSON, "policy.full.example.json": fullExampleJSON} {
		poc, err := os.ReadFile(filepath.Join(pocDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(poc, embedded) {
			t.Fatalf("internal/access/%s drifted from poc/ssh-diagnostic/%s; copy it again", name, name)
		}
	}
}

// The driver runs the grant command's own edit functions without touching a
// policy file, a lock or the native validator. The Go test validates the
// Python output with pocpolicy, which is what the native validator runs.
const pythonDriver = `
import argparse, json, sys
sys.path.insert(0, sys.argv[1])
import grants
cases = json.loads(sys.stdin.read())
class Ctx:
    def __init__(self):
        self.notices = []
    def mount_entries(self):
        return []
def run(document, edit):
    ctx = Ctx()
    args = argparse.Namespace(command=edit['action'], upgrade_to_v2=edit.get('upgrade_to_v2', False), interactive=False, dry_run=False)
    action, values = edit['action'], edit.get('values', [])
    if action in ('allow-web', 'deny-web'):
        args.protocols = values
        return grants.op_web(ctx, document, args, allow=action == 'allow-web').document
    if action == 'dns':
        args.resolvers = values
        return grants.op_dns(ctx, document, args).document
    if action in ('read', 'write', 'exec', 'deny'):
        if len(values) != 1:
            raise grants.GrantError(grants.USAGE, 'one path')
        args.path = values[0]
        return grants.op_path(ctx, document, args, action).document
    if action == 'signal':
        args.signals = values
        return grants.op_signal(ctx, document, args).document
    if action == 'anon-exec':
        return grants.op_anon_exec(ctx, document, args).document
    if action == 'preset':
        args.name = values[0]
        return grants.op_preset(ctx, document, args).document
    if action == 'device':
        if len(values) != 1:
            raise grants.GrantError(grants.USAGE, 'one device')
        args.path = values[0]
        return grants.op_device(ctx, document, args).document
    if action == 'mount':
        name = grants.mountlib.name_from_path(values[0])
        return grants.mount_policy(ctx, document, args, grants.mountlib.mount_path(name), edit.get('mode', 'read-only') == 'read-only')
    if action == 'unmount' or (action == 'revoke' and edit.get('kind') == 'mount'):
        name = grants.mountlib.name_from_path(values[0])
        return grants.unmount_policy(document, grants.mountlib.mount_path(name))
    if action == 'revoke':
        args.kind, args.values = edit['kind'], list(values)
        return grants.op_revoke(ctx, document, args).document
    raise grants.GrantError(grants.USAGE, 'unknown action')
out = []
for step in cases:
    document = grants.parse_policy(step['document'].encode())
    try:
        out.append({'document': run(document, step['edit'])})
    except grants.GrantError as error:
        out.append({'error': error.code})
    except grants.mountlib.MountError:
        out.append({'error': grants.USAGE})
presets = grants.load_presets()
print(json.dumps({'steps': out, 'presets': presets}))
`

var pythonCodes = map[int]string{2: CodeUsage, 4: CodeRejected, 6: CodeUpgrade, 12: CodeConflict}

type parityCase struct {
	Start string `json:"start"`
	Edits []Edit `json:"edits"`
}

func parityCases(t *testing.T) []parityCase {
	full, _ := filepath.Abs(filepath.Join(pocDir, "policy.full.example.json"))
	v1, _ := filepath.Abs(filepath.Join(pocDir, "policy.example.json"))
	return []parityCase{
		{full, []Edit{
			{Action: "read", Values: []string{"/srv/data"}},
			{Action: "read", Values: []string{"/srv/data/sub"}},
			{Action: "write", Values: []string{"/var/lib/agentgate/workspace/out"}},
			{Action: "write", Values: []string{"/srv/scratch"}},
			{Action: "exec", Values: []string{"/opt/tools"}},
			{Action: "exec", Values: []string{"/srv/scratch/bin"}},
			{Action: "write", Values: []string{"/usr/local"}},
			{Action: "write", Values: []string{"/etc/app"}},
			{Action: "deny", Values: []string{"/srv/data/private"}},
			{Action: "read", Values: []string{"/srv/data/private/x"}},
			{Action: "deny", Values: []string{"/srv/data/private"}},
			{Action: "revoke", Kind: "deny", Values: []string{"/srv/data/private"}},
			{Action: "revoke", Kind: "read", Values: []string{"/srv/data/sub"}},
			{Action: "revoke", Kind: "read", Values: []string{"/srv/data"}},
			{Action: "revoke", Kind: "write", Values: []string{"/var/lib/agentgate/workspace"}},
			{Action: "revoke", Kind: "exec", Values: []string{"/usr/bin"}},
			{Action: "read", Values: []string{"relative/path"}},
			{Action: "read", Values: []string{"/a/../b"}},
			{Action: "read", Values: []string{"/"}},
		}},
		{full, []Edit{
			{Action: "deny-web", Values: []string{"quic"}},
			{Action: "deny-web"},
			{Action: "allow-web", Values: []string{"https"}},
			{Action: "allow-web", Values: []string{"gopher"}},
			{Action: "revoke", Kind: "web", Values: []string{"https"}},
			{Action: "allow-web", Values: []string{"all"}},
			{Action: "dns", Values: []string{"9.9.9.9", "1.1.1.1", "9.9.9.9"}},
			{Action: "dns", Values: []string{"10.0.0.1"}},
			{Action: "revoke", Kind: "dns", Values: []string{"9.9.9.9"}},
			{Action: "revoke", Kind: "dns", Values: []string{"1.1.1.1"}},
			{Action: "signal", Values: []string{"term", "SIGWINCH", "usr1"}},
			{Action: "signal", Values: []string{"SIGBOGUS"}},
			{Action: "revoke", Kind: "signal", Values: []string{"WINCH"}},
			{Action: "anon-exec"},
			{Action: "revoke", Kind: "anon-exec"},
			{Action: "mount", Values: []string{"repo"}},
			{Action: "mount", Values: []string{"/var/lib/agentgate/mounts/repo"}, Mode: "read-write"},
			{Action: "mount", Values: []string{"Bad Name"}},
			{Action: "unmount", Values: []string{"repo"}},
			{Action: "revoke", Kind: "mount", Values: []string{"repo"}},
		}},
		{full, []Edit{
			{Action: "preset", Values: []string{"locked-down"}},
			{Action: "preset", Values: []string{"python-dev"}},
			{Action: "preset", Values: []string{"web-readonly"}},
			{Action: "preset", Values: []string{"full-example"}},
			{Action: "preset", Values: []string{"missing"}},
		}},
		{v1, []Edit{
			{Action: "read", Values: []string{"/srv/data"}},
			{Action: "signal", Values: []string{"TERM"}},
			{Action: "revoke", Kind: "read", Values: []string{"/srv/data"}},
			{Action: "revoke", Kind: "signal", Values: []string{"TERM"}},
			{Action: "revoke", Kind: "anon-exec"},
			{Action: "deny-web", Values: []string{"http"}},
			{Action: "read", Values: []string{"/srv/data"}, UpgradeToV2: true},
			{Action: "exec", Values: []string{"/opt/tools"}},
		}},
		{v1, []Edit{
			{Action: "preset", Values: []string{"python-dev"}, UpgradeToV2: true},
			{Action: "write", Values: []string{"/tmp/cache"}},
		}},
		{full, []Edit{
			{Action: "device", Values: []string{"/dev/tty"}},
			{Action: "device", Values: []string{"/dev/tty"}},
			{Action: "device", Values: []string{"/dev/sda"}},
			{Action: "device", Values: []string{"null"}},
			{Action: "device", Values: []string{"/dev/full", "/dev/tty"}},
			{Action: "device"},
			{Action: "revoke", Kind: "device", Values: []string{"/dev/zero"}},
			{Action: "revoke", Kind: "device", Values: []string{"/dev/zero"}},
			{Action: "revoke", Kind: "device", Values: []string{"/dev/sda"}},
			{Action: "deny", Values: []string{"/dev"}},
			{Action: "revoke", Kind: "device", Values: []string{"/dev/null"}},
			{Action: "revoke", Kind: "device", Values: []string{"/dev/random"}},
			{Action: "revoke", Kind: "device", Values: []string{"/dev/urandom"}},
			{Action: "revoke", Kind: "device", Values: []string{"/dev/tty"}},
			{Action: "deny", Values: []string{"/dev"}},
			{Action: "device", Values: []string{"/dev/null"}},
			{Action: "revoke", Kind: "deny", Values: []string{"/dev"}},
			{Action: "device", Values: []string{"/dev/full"}},
		}},
		{v1, []Edit{
			{Action: "device", Values: []string{"/dev/null"}},
			{Action: "revoke", Kind: "device", Values: []string{"/dev/null"}},
			{Action: "device", Values: []string{"/dev/full"}, UpgradeToV2: true},
		}},
	}
}

type parityStep struct {
	Document string `json:"document"`
	Edit     Edit   `json:"edit"`
}

func TestGoAndPythonGrantEnginesAgree(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	// Go runs each chain; every step's input document goes to Python too, so
	// the engines are compared on identical inputs at every step.
	steps := []parityStep{}
	results := []Result{}
	codes := []string{}
	for _, c := range parityCases(t) {
		raw, err := os.ReadFile(c.Start)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := pocpolicy.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, edit := range c.Edits {
			input, _ := json.Marshal(doc)
			steps = append(steps, parityStep{string(input), edit})
			got, err := Apply(doc, edit)
			code := ""
			if err != nil {
				e, ok := err.(*Error)
				if !ok {
					t.Fatalf("%+v: untyped error %v", edit, err)
				}
				code = e.Code
			} else {
				doc = got.Document
			}
			results = append(results, got)
			codes = append(codes, code)
		}
	}
	input, _ := json.Marshal(steps)
	abs, _ := filepath.Abs(pocDir)
	cmd := exec.Command(python, "-I", "-B", "-c", pythonDriver, abs)
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("python driver: %v", err)
	}
	var result struct {
		Steps []struct {
			Document json.RawMessage `json:"document"`
			Error    int             `json:"error"`
		} `json:"steps"`
		Presets map[string]struct {
			Description string               `json:"description"`
			Web         []string             `json:"web"`
			Filesystem  pocpolicy.Filesystem `json:"filesystem"`
			Process     pocpolicy.Process    `json:"process"`
		} `json:"presets"`
	}
	if err = json.Unmarshal(output, &result); err != nil || len(result.Steps) != len(steps) {
		t.Fatal("python driver output", err)
	}
	for i, step := range result.Steps {
		want := ""
		var pyDoc pocpolicy.Document
		if step.Error != 0 {
			want = pythonCodes[step.Error]
		} else {
			dec := json.NewDecoder(bytes.NewReader(step.Document))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&pyDoc); err != nil {
				t.Fatal(err)
			}
			if pyDoc.Validate() != nil {
				want = CodeRejected
			}
		}
		if codes[i] != want {
			t.Fatalf("step %d %+v: Go result %q, Python result %q", i, steps[i].Edit, codes[i], want)
		}
		if want == "" && !reflect.DeepEqual(results[i].Document, pyDoc) {
			g, _ := json.Marshal(results[i].Document)
			p, _ := json.Marshal(pyDoc)
			t.Fatalf("step %d %+v: documents differ\nGo:     %s\nPython: %s", i, steps[i].Edit, g, p)
		}
	}
	presets, err := Presets()
	if err != nil {
		t.Fatal(err)
	}
	if len(presets) != len(result.Presets) {
		t.Fatal("preset sets differ")
	}
	for name, py := range result.Presets {
		g := presets[name]
		if g.Description != py.Description || !reflect.DeepEqual(g.Web, append([]string{}, py.Web...)) || !reflect.DeepEqual(g.Filesystem, py.Filesystem) || !reflect.DeepEqual(g.Process, py.Process) {
			t.Fatalf("preset %s differs between Go and Python", name)
		}
	}
	if len(steps) < 50 {
		t.Fatal("the parity corpus shrank")
	}
}
