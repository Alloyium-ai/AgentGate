// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"bufio"
	"flag"
	"io"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestSplitCommandAndInterspersedFlags(t *testing.T) {
	path, rest := splitCommand([]string{"--context", "lab", "--json", "target", "approve-key", "local", "--host-key-id", "x"})
	if !reflect.DeepEqual(path, []string{"target", "approve-key"}) || !reflect.DeepEqual(rest, []string{"--context", "lab", "--json", "local", "--host-key-id", "x"}) {
		t.Fatalf("path %v rest %v", path, rest)
	}
	path, rest = splitCommand([]string{"launch", "--profile", "dev", "--", "echo", "--json"})
	if !reflect.DeepEqual(path, []string{"launch"}) || !reflect.DeepEqual(rest, []string{"--profile", "dev", "--", "echo", "--json"}) {
		t.Fatalf("path %v rest %v", path, rest)
	}
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	reason := fs.String("reason", "", "")
	json := fs.Bool("json", false, "")
	pos, tail, err := parseArgs(fs, []string{"dev", "read", "--reason", "data set", "/srv/data", "--json", "--", "-x", "--reason"})
	if err != nil || !reflect.DeepEqual(pos, []string{"dev", "read", "/srv/data"}) || !reflect.DeepEqual(tail, []string{"-x", "--reason"}) || *reason != "data set" || !*json {
		t.Fatalf("pos %v tail %v reason %q json %v err %v", pos, tail, *reason, *json, err)
	}
}

func TestUsageErrorsAndHelp(t *testing.T) {
	h := newHarness(t)
	if r := h.run(""); r.code != ExitUsage || !strings.Contains(r.stdout, "Commands:") {
		t.Fatalf("no command: %v", r)
	}
	if r := h.run("", "--help"); r.code != ExitOK {
		t.Fatalf("--help: %v", r)
	}
	if r := h.run("", "frobnicate"); r.code != ExitUsage || !strings.Contains(r.stderr, "unknown command") || !strings.Contains(r.stderr, "next:") {
		t.Fatalf("unknown command: %v", r)
	}
	if r := h.run("", "target"); r.code != ExitUsage || !strings.Contains(r.stdout, "approve-key") {
		t.Fatalf("group without subcommand: %v", r)
	}
	if r := h.run("", "target", "frob"); r.code != ExitUsage {
		t.Fatalf("unknown subcommand: %v", r)
	}
	if r := h.run("", "ps", "--bogus"); r.code != ExitUsage || !strings.Contains(r.stderr, "bogus") {
		t.Fatalf("unknown flag: %v", r)
	}
	if r := h.run("", "help", "launch"); r.code != ExitOK || !strings.Contains(r.stdout, "--dry-run") {
		t.Fatalf("help launch: %v", r)
	}
	if r := h.run("", "secret", "set", "--help"); r.code != ExitOK || !strings.Contains(r.stdout, "never read from arguments") {
		t.Fatalf("secret set --help: %v", r)
	}
	if r := h.run("", "version", "--json"); r.code != ExitOK || !strings.Contains(r.stdout, `"version": "test"`) {
		t.Fatalf("version: %v", r)
	}
}

func TestNotConfiguredIsAnAuthError(t *testing.T) {
	h := newHarness(t)
	r := h.run("", "ps")
	if r.code != ExitAuth || !strings.Contains(r.stderr, "agentgate login") {
		t.Fatalf("%v", r)
	}
	r = h.run("", "ps", "--json")
	if r.code != ExitAuth || !strings.Contains(r.stdout, `"exit_code": 3`) {
		t.Fatalf("json error: %v", r)
	}
}

// TestExitCodeTableIsComplete keeps docs/CLI.md and ExitCodes identical.
func TestExitCodeTableIsComplete(t *testing.T) {
	f, err := os.Open("../../docs/CLI.md")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	row := regexp.MustCompile("^\\| (\\d+) \\| `([a-z_]+)` \\| (.+) \\|$")
	documented := map[int]string{}
	meanings := map[int]string{}
	sc := bufio.NewScanner(f)
	inTable := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "## Exit codes") {
			inTable = true
			continue
		}
		if inTable && strings.HasPrefix(line, "## ") {
			break
		}
		if m := row.FindStringSubmatch(line); inTable && m != nil {
			code, _ := strconv.Atoi(m[1])
			if _, dup := documented[code]; dup {
				t.Errorf("exit code %d documented twice", code)
			}
			documented[code] = m[2]
			meanings[code] = m[3]
		}
	}
	for _, c := range ExitCodes {
		if documented[c.Code] != c.Name {
			t.Errorf("docs/CLI.md does not document exit code %d as %s (has %q)", c.Code, c.Name, documented[c.Code])
		}
		if meanings[c.Code] != c.Meaning {
			t.Errorf("exit code %d: docs/CLI.md says %q, the CLI says %q", c.Code, meanings[c.Code], c.Meaning)
		}
		delete(documented, c.Code)
	}
	for code, name := range documented {
		t.Errorf("docs/CLI.md documents exit code %d (%s) that the CLI does not use", code, name)
	}
	seen := map[int]bool{}
	for _, c := range ExitCodes {
		if seen[c.Code] {
			t.Errorf("exit code %d is listed twice", c.Code)
		}
		seen[c.Code] = true
	}
}

func TestStatusMapping(t *testing.T) {
	for status, want := range map[int]int{400: ExitRejected, 401: ExitAuth, 403: ExitForbidden, 404: ExitNotFound, 409: ExitConflict, 412: ExitConflict, 413: ExitRejected, 415: ExitRejected, 422: ExitRejected, 428: ExitRejected, 429: ExitServer, 500: ExitServer, 503: ExitServer} {
		if got := exitForStatus(status); got != want {
			t.Errorf("HTTP %d -> %d, want %d", status, got, want)
		}
	}
}

func TestCompletionScripts(t *testing.T) {
	h := newHarness(t)
	for _, shell := range []string{"bash", "zsh", "fish"} {
		r := h.run("", "completion", shell)
		if r.code != ExitOK || !strings.Contains(r.stdout, "approve-key") || !strings.Contains(r.stdout, "launch") {
			t.Errorf("%s: %v", shell, r)
		}
	}
	if r := h.run("", "completion", "tcsh"); r.code != ExitUsage {
		t.Errorf("tcsh: %v", r)
	}
}

func TestRedaction(t *testing.T) {
	in := "Authorization: Bearer " + testToken + " token agtenr_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG cookie __Host-enforcer-session=abc123"
	out := redactText(in)
	for _, secret := range []string{testToken, "agtenr_abcdefghijklmnop", "abc123"} {
		if strings.Contains(out, secret) {
			t.Errorf("redactText kept %q: %s", secret, out)
		}
	}
	if redactHeader("Authorization", "Bearer "+testToken) != "Bearer [redacted]" || redactHeader("Cookie", "x=y") != "[redacted]" {
		t.Error("redactHeader")
	}
}
