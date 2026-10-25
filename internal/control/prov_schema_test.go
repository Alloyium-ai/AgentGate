// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/access"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// TestLaunchSpecSchemaAgreesWithTheValidator checks the published JSON Schema
// with a real draft 2020-12 validator: every spec the service accepts passes
// the schema, and every structural rejection is also a schema rejection.
// Rules listed under x-service-rules are only checked by the service.
func TestLaunchSpecSchemaAgreesWithTheValidator(t *testing.T) {
	raw, _ := json.Marshal(LaunchSpecSchema())
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err = c.AddResource("urn:agentgate:launch:v1", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile("urn:agentgate:launch:v1")
	if err != nil {
		t.Fatal(err)
	}
	check := func(m map[string]any) (bool, bool) {
		b := specBytes(t, m)
		v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, verr := ValidateLaunchSpec(b)
		return verr == nil, schema.Validate(v) == nil
	}
	full, _ := access.FullExample()
	valid := []func(m map[string]any){
		func(m map[string]any) {},
		func(m map[string]any) { m["mode"] = "oneshot"; m["lifetime_seconds"] = 1 },
		func(m map[string]any) { m["lifetime_seconds"] = 86400 },
		func(m map[string]any) { m["access"] = map[string]any{"inline": full} },
		func(m map[string]any) {
			m["mounts"] = []any{map[string]any{"name": "repo", "source": "/srv/repos/app", "mode": "snapshot"}}
			m["agent"].(map[string]any)["workdir"] = "/var/lib/agentgate/mounts/repo/src"
		},
		func(m map[string]any) {
			m["secrets"] = []any{map[string]any{"ref": "model-api", "expose": map[string]any{"env": "MODEL_API_BASE_URL"}}}
		},
		func(m map[string]any) {
			delete(m["agent"].(map[string]any), "env")
			delete(m, "mounts")
			delete(m, "secrets")
		},
	}
	structural := []func(m map[string]any){
		func(m map[string]any) { m["name"] = "Bad" },
		func(m map[string]any) { m["mode"] = "daemon" },
		func(m map[string]any) { m["lifetime_seconds"] = 59 },
		func(m map[string]any) { m["mode"] = "oneshot"; m["lifetime_seconds"] = 3601 },
		func(m map[string]any) { m["mode"] = "oneshot"; m["agent"].(map[string]any)["command"] = []string{} },
		func(m map[string]any) { m["agent"].(map[string]any)["image"] = "agentgate-coding:latest" },
		func(m map[string]any) {
			m["agent"].(map[string]any)["env"] = map[string]string{"AWS_SECRET_ACCESS_KEY": "x"}
		},
		func(m map[string]any) { m["agent"].(map[string]any)["env"] = map[string]string{"LD_PRELOAD": "x"} },
		func(m map[string]any) { m["privileged"] = true },
		func(m map[string]any) { m["approval"] = "skip" },
		func(m map[string]any) { m["version"] = "agentgate.launch.v2" },
		func(m map[string]any) { m["access"].(map[string]any)["inline"] = full },
		func(m map[string]any) { delete(m["access"].(map[string]any), "version") },
		func(m map[string]any) { delete(m, "target") },
		func(m map[string]any) {
			m["mounts"] = []any{map[string]any{"name": "r", "source": "/srv/r", "mode": "exec"}}
		},
		func(m map[string]any) {
			m["secrets"] = []any{map[string]any{"ref": "k", "value": "v", "expose": map[string]any{"env": "K"}}}
		},
	}
	for i, fn := range valid {
		m := specMap("dev")
		fn(m)
		if ok, schemaOK := check(m); !ok || !schemaOK {
			t.Fatalf("valid case %d: validator %v schema %v", i, ok, schemaOK)
		}
	}
	for i, fn := range structural {
		m := specMap("dev")
		fn(m)
		if ok, schemaOK := check(m); ok || schemaOK {
			t.Fatalf("structural case %d: validator %v schema %v", i, ok, schemaOK)
		}
	}
	if !strings.Contains(string(raw), "x-service-rules") {
		t.Fatal("the schema does not list service-only rules")
	}
}
