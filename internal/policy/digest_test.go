// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package policy

import (
	"encoding/json"
	"testing"
)

func TestDocumentDigestBindsValidatedCanonicalContent(t *testing.T) {
	d := NewSelected(Selected{WorkspaceWrite: true, TCPAddress: "127.0.0.1", TCPPort: 1234})
	first, err := d.Digest()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Parse(raw, "json")
	if err != nil {
		t.Fatal(err)
	}
	second, err := decoded.Digest()
	if err != nil || first != second {
		t.Fatal("canonical whitespace changed the binding")
	}
	decoded.Selected.TCPPort++
	changed, err := decoded.Digest()
	if err != nil || changed == first {
		t.Fatal("different rights kept the document binding")
	}
	d.RequiredCapabilities = []string{}
	if _, err = d.Digest(); err == nil {
		t.Fatal("an incomplete capability declaration received a document digest")
	}
}
