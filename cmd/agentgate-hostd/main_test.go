// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandLine(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"unit"}, &out, &errOut); err != nil || !strings.Contains(out.String(), "ExecStart=/usr/local/sbin/agentgate-hostd run") {
		t.Fatalf("unit: %v %s", err, out.String())
	}
	for _, args := range [][]string{{}, {"bogus"}, {"provision"}, {"install", "--token", "a", "--token-file", "b", "--service-url", "https://x"},
		{"install", "--service-url", "http://example.org", "--token", "x"}} {
		err := run(args, &out, &errOut)
		var code *exitCode
		if !errors.As(err, &code) || code.code != 2 {
			t.Errorf("%v: %v", args, err)
		}
	}
}

func TestMountRootsCommand(t *testing.T) {
	file := filepath.Join(t.TempDir(), "etc", "mount-roots.json")
	state := filepath.Join(t.TempDir(), "state")
	root := func() int { return 0 }
	show := func(args ...string) (map[string]any, error) {
		var out bytes.Buffer
		err := mountRoots(append([]string{"--state-dir", state}, args...), &out, file, root)
		var v map[string]any
		if err == nil {
			if jerr := json.Unmarshal(out.Bytes(), &v); jerr != nil {
				t.Fatalf("output %s", out.String())
			}
		}
		return v, err
	}
	if v, err := show(); err != nil || fmt.Sprint(v["mount_roots"]) != "[]" {
		t.Fatalf("default %v %v", v, err)
	}
	if v, err := show("--root", "/srv/data", "--root", "/opt/projects"); err != nil || fmt.Sprint(v["mount_roots"]) != "[/srv/data /opt/projects]" {
		t.Fatalf("set %v %v", v, err)
	}
	for _, args := range [][]string{{"--root", "/etc"}, {"--root", "/srv/data/../../etc"}, {"--root", "/home/alice"}, {"--root", state + "/brokers"},
		{"--root", "/var/lib/agentgate/secrets"}, {"--root", "/srv", "--clear"}, {"extra"}} {
		var code *exitCode
		if _, err := show(args...); !errors.As(err, &code) || code.code != 2 {
			t.Errorf("%v: %v", args, err)
		}
	}
	if v, _ := show(); fmt.Sprint(v["mount_roots"]) != "[/srv/data /opt/projects]" {
		t.Fatalf("a refused change altered the list: %v", v)
	}
	if err := mountRoots([]string{"--state-dir", state, "--clear"}, &bytes.Buffer{}, file, func() int { return 1000 }); err == nil {
		t.Fatal("a non-root user changed the mount roots")
	}
	if v, err := show("--clear"); err != nil || fmt.Sprint(v["mount_roots"]) != "[]" {
		t.Fatalf("clear %v %v", v, err)
	}
	var code *exitCode
	if err := run([]string{"install", "--service-url", "https://x.example", "--token", "t", "--mount-root", "/srv", "--no-mount-roots"}, &bytes.Buffer{}, &bytes.Buffer{}); !errors.As(err, &code) || code.code != 2 {
		t.Fatalf("--mount-root with --no-mount-roots: %v", err)
	}
}
