// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

package control

import (
	"bytes"
	"context"
	"net/http"
	"testing"
)

func TestProofAudienceAndRestartEpoch(t *testing.T) {
	f := authTestFixture(t)
	actor, key := enroll(t, f.Store, "synthetic-epoch-agent", "agent", []string{"request:create", "policy:read"})
	body := []byte(`{"version_id":"unknown","reason":"Check the recipient binding"}`)
	path := "/api/v1/requests"
	proof := SignProof(actor.Subject, "POST", path, body, key, "https://other.invalid", f.Auth.Epoch)
	r, _ := http.NewRequest("POST", f.App.URL+path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Alloyium-Proof "+proof)
	res, err := f.Client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("cross-recipient proof accepted")
	}
	proof = SignProof(actor.Subject, "POST", path, body, key, f.App.URL, f.Auth.Epoch)
	next, err := NewAuth(context.Background(), f.Store, f.Auth.Config)
	if err != nil {
		t.Fatal(err)
	}
	if next.Epoch == f.Auth.Epoch {
		t.Fatal("restart reused its proof epoch")
	}
	r, _ = http.NewRequest("POST", f.App.URL+path, bytes.NewReader(body))
	r.Header.Set("Authorization", "Alloyium-Proof "+proof)
	if _, _, err = next.Machine(r, body); err == nil {
		t.Fatal("proof survived a receiver restart")
	}
}
