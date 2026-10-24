// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The web UI's tests use answers of the real service, not hand-written
// ones. This test drives the real service over HTTP and records its answers
// in web/qa/fixtures/api. With AGENTGATE_WRITE_WEB_FIXTURES=1 it rewrites
// them; otherwise it fails when a committed fixture's shape (its keys and
// value types, recursively) differs from what the service answers now.
const webFixtureDir = "../../web/qa/fixtures/api"

type webFixtures struct {
	t     *testing.T
	f     *provFixture
	files map[string]any
}

func (w *webFixtures) call(method, path, token string, body any, status int) map[string]any {
	w.t.Helper()
	var raw []byte
	if body != nil {
		switch b := body.(type) {
		case []byte:
			raw = b
		default:
			raw, _ = json.Marshal(b)
		}
	}
	resp, out := w.f.apiRequest(method, path, token, raw)
	if resp.StatusCode != status {
		w.t.Fatalf("%s %s: %d %v", method, path, resp.StatusCode, out)
	}
	return out
}

func (w *webFixtures) record(name string, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		w.t.Fatal(err)
	}
	var decoded any
	json.Unmarshal(raw, &decoded)
	w.files[name] = decoded
}

// shape reduces a JSON value to its keys and types. A list has the shape of
// its first element.
func shape(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, x := range t {
			out[k] = shape(x)
		}
		return out
	case []any:
		if len(t) == 0 {
			return []any{}
		}
		return []any{shape(t[0])}
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	case nil:
		return "null"
	}
	return fmt.Sprintf("%T", v)
}

func shapeDiff(prefix string, a, b any, out *[]string) {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		keys := map[string]bool{}
		for k := range am {
			keys[k] = true
		}
		for k := range bm {
			keys[k] = true
		}
		names := []string{}
		for k := range keys {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			shapeDiff(prefix+"."+k, am[k], bm[k], out)
		}
		return
	}
	al, alok := a.([]any)
	bl, blok := b.([]any)
	if alok && blok && len(al) == 1 && len(bl) == 1 {
		shapeDiff(prefix+"[]", al[0], bl[0], out)
		return
	}
	if !reflect.DeepEqual(a, b) {
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		*out = append(*out, fmt.Sprintf("%s: committed %s, service %s", prefix, ja, jb))
	}
}

func (w *webFixtures) finish() {
	w.t.Helper()
	if os.Getenv("AGENTGATE_WRITE_WEB_FIXTURES") == "1" {
		if err := os.MkdirAll(webFixtureDir, 0o755); err != nil {
			w.t.Fatal(err)
		}
		for name, v := range w.files {
			raw, _ := json.MarshalIndent(v, "", "  ")
			if err := os.WriteFile(filepath.Join(webFixtureDir, name), append(raw, '\n'), 0o644); err != nil {
				w.t.Fatal(err)
			}
		}
		return
	}
	names := []string{}
	for name := range w.files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(webFixtureDir, name))
		if err != nil {
			w.t.Fatalf("%s is missing; run AGENTGATE_WRITE_WEB_FIXTURES=1 go test ./internal/control -run TestWebFixtures", name)
		}
		var committed any
		if err = json.Unmarshal(raw, &committed); err != nil {
			w.t.Fatalf("%s: %v", name, err)
		}
		diffs := []string{}
		shapeDiff(strings.TrimSuffix(name, ".json"), shape(committed), shape(w.files[name]), &diffs)
		if len(diffs) > 0 {
			w.t.Fatalf("%s no longer matches the service's answer (regenerate with AGENTGATE_WRITE_WEB_FIXTURES=1):\n%s", name, strings.Join(diffs, "\n"))
		}
		if bytes.Contains(raw, []byte("synthetic-credential")) {
			w.t.Fatalf("%s holds a secret value", name)
		}
	}
}

func TestWebFixturesAreRealServiceAnswers(t *testing.T) {
	f := newProv(t)
	w := &webFixtures{t: t, f: f, files: map[string]any{}}
	editor := f.token(f.editor(), "editor")
	p := f.profileFrom("python-dev", "python-dev", true)
	parent := w.call("GET", "/api/v1/profiles/"+p.ID+"/versions/1", editor, nil, 200)
	request := map[string]any{"edits": []any{
		map[string]any{"action": "read", "values": []string{"/srv/data"}},
		map[string]any{"action": "deny-web", "values": []string{"http"}},
		map[string]any{"action": "mount", "values": []string{"repo"}, "mode": "read-only"},
		map[string]any{"action": "signal", "values": []string{"WINCH"}},
	}, "reason": "Read the data set", "dry_run": true}
	dry := w.call("POST", "/api/v1/profiles/"+p.ID+"/versions/1/grants", editor, request, 200)
	w.record("grant-dry-run.json", map[string]any{"parent": parent, "request": request, "response": dry})
	delete(request, "dry_run")
	applied := w.call("POST", "/api/v1/profiles/"+p.ID+"/versions/1/grants", editor, request, 200)
	w.record("grant-applied.json", map[string]any{"parent": parent, "request": request, "response": applied})
	w.finish()
}
