// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobartifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestRunningExecutableUsesTheKernelReference(t *testing.T) {
	raw, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	if err = VerifyRunningExecutable(hex.EncodeToString(hash[:])); err != nil {
		t.Fatal(err)
	}
	if VerifyRunningExecutable(strings.Repeat("0", 64)) == nil {
		t.Fatal("an unrelated running artifact digest was accepted")
	}
}
