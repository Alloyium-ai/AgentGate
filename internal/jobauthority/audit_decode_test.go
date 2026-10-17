// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/jobaudit"
	"strings"
	"testing"
)

func TestAuditDecoderRejectsAmbiguityAndStructuralExcess(t *testing.T) {
	for name, raw := range map[string]string{"duplicate": `{"events":[],"events":[]}`, "case-alias": `{"Events":[]}`, "unknown": `{"extra":1}`, "trailing": `{} {}`, "wrong-shape": `{"events":{}}`, "record-bound": `{"events":[` + strings.Repeat(`null,`, MaxAuditRecords) + `null]}`} {
		t.Run(name, func(t *testing.T) {
			var bundle jobaudit.Bundle
			if decodeAudit([]byte(raw), &bundle) == nil {
				t.Fatal("ambiguous or excessive audit accepted")
			}
		})
	}
}
