// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestNodeProofNonceSurvivesRestartAndRejectsStaleTime(t *testing.T) {
	journal := journalFixture(t)
	ctx := context.Background()
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		t.Fatal(err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	issued := time.Now().Unix()
	if err := journal.ConsumeProof(ctx, "agent-one", nonce, issued); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(journal.path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err = reopened.ConsumeProof(ctx, "agent-one", nonce, issued); !errors.Is(err, ErrReplay) {
		t.Fatal("node proof replay accepted", err)
	}
	if err = reopened.ConsumeProof(ctx, "agent-one", nonce, issued-120); err == nil {
		t.Fatal("stale proof accepted")
	}
	if err = reopened.ConsumeProof(ctx, "agent-one", nonce, issued+120); err == nil {
		t.Fatal("future proof accepted")
	}
	if NodeAudience("node-one") != "agentgate-node.v1:node-one" {
		t.Fatal("node audience differs")
	}
}
