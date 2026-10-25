// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// agentgate identity against the real control service in process.
func TestIdentityCommandsAgainstTheRealService(t *testing.T) {
	svc := startRealService(t)
	dir := filepath.Join(t.TempDir(), "agentgate")
	run := func(args ...string) result {
		t.Helper()
		var out, errOut bytes.Buffer
		a := &App{Stdin: strings.NewReader(adaPassword + "\n"), Stdout: &out, Stderr: &errOut, Getenv: func(k string) string {
			return map[string]string{"AGENTGATE_CONFIG_DIR": dir, "HOME": dir}[k]
		}, Term: &fakeTerm{}, Hostname: func() (string, error) { return "identity", nil }, Version: "test", Now: time.Now}
		code := a.Main(context.Background(), args)
		return result{out.String(), errOut.String(), code}
	}
	if r := run("login", svc.srv.URL, "--ca-file", svc.ca, "--username", "ada", "--password-stdin"); r.code != 0 {
		t.Fatalf("%v", r)
	}
	if r := run("identity", "ls"); r.code != 0 || !strings.Contains(r.stderr, "No subjects are linked") {
		t.Fatalf("%v", r)
	}
	if r := run("identity", "link", "local:lin", "oidc:lin-sso", "--reason", "Lin signs in two ways"); r.code != 0 || !strings.Contains(r.stdout, "Linked as one person: local:lin, oidc:lin-sso") {
		t.Fatalf("%v", r)
	}
	r := run("identity", "ls", "--json")
	var list struct {
		Items []IdentityLink `json:"items"`
	}
	if r.code != 0 || json.Unmarshal([]byte(r.stdout), &list) != nil || len(list.Items) != 1 || strings.Join(list.Items[0].Subjects, ",") != "local:lin,oidc:lin-sso" || list.Items[0].LinkedBy != "local:ada" {
		t.Fatalf("%v", r)
	}
	if r = run("identity", "ls"); r.code != 0 || !strings.Contains(r.stdout, "local:lin, oidc:lin-sso") {
		t.Fatalf("%v", r)
	}
	// Refusals: usage, invalid subjects (the service's message), and an administrator's own group.
	if r = run("identity", "link", "local:lin"); r.code != ExitUsage {
		t.Fatalf("one subject: %v", r)
	}
	if r = run("identity", "link", "lin", "oidc:x", "--reason", "Bad subject"); r.code != ExitRejected || !strings.Contains(r.stderr, "HTTP 422") {
		t.Fatalf("bad subject: %v", r)
	}
	if r = run("identity", "link", "local:ada", "oidc:ada-sso", "--reason", "Ada's accounts"); r.code != 0 {
		t.Fatalf("%v", r)
	}
	if r = run("identity", "unlink", "oidc:ada-sso", "--reason", "Unlink my own"); r.code != ExitForbidden || !strings.Contains(r.stderr, "self_unlink") {
		t.Fatalf("an administrator unlinked their own group: %v", r)
	}
	if r = run("identity", "unlink", "oidc:lin-sso", "--reason", "Lin closed the SSO account"); r.code != 0 || !strings.Contains(r.stdout, "had no other linked subject left") {
		t.Fatalf("%v", r)
	}
	if r = run("identity", "unlink", "oidc:lin-sso"); r.code != ExitNotFound {
		t.Fatalf("unlink twice: %v", r)
	}
}
