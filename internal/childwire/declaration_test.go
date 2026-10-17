// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package childwire

import (
	"bytes"
	"os"
	"testing"
)

func TestDeclarationReadsImmutableActualFrameBytes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root frame custody required")
	}
	raw := []byte("actual supplied frame")
	f, err := Seal("supplied", raw)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, seals, err := sealedFrame(f)
	if err != nil || !bytes.Equal(got, raw) || seals == 0 {
		t.Fatal("actual frame differs", err)
	}
	if _, err = f.WriteAt([]byte("X"), 0); err == nil {
		t.Fatal("sealed input changed")
	}
	plain, err := os.CreateTemp(t.TempDir(), "unsealed")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	_, _ = plain.Write(raw)
	if _, _, err = sealedFrame(plain); err == nil {
		t.Fatal("unsealed frame supplied custody")
	}
}
