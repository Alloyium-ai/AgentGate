// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"bytes"
	"errors"
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
