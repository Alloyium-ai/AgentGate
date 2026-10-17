// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

package control

import (
	"alloyium.local/kernel-poc/internal/control/oidctest"
	"bytes"
	"context"
	"github.com/coreos/go-oidc/v3/oidc"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestIndependentRestartRequiresFreshIssuerSession(t *testing.T) {
	f := authTestFixture(t)
	response, _ := loginFlow(t, f, "admin")
	response.Body.Close()
	oldSession := readSession(t, f)
	originalURL := f.App.URL
	originalAddress := f.App.Listener.Addr().String()
	f.App.Close()
	issuer := oidctest.NewTLS()
	defer issuer.Close()
	issuer.ClientID = "independent-replacement-client"
	issuer.Secret = "synthetic-replacement-secret"
	restarted := httptest.NewUnstartedServer(http.NotFoundHandler())
	restarted.Listener.Close()
	listener, err := net.Listen("tcp", originalAddress)
	if err != nil {
		t.Fatal(err)
	}
	restarted.Listener = listener
	restarted.StartTLS()
	defer restarted.Close()
	if restarted.URL != originalURL {
		t.Fatal("the public origin changed in the test")
	}
	cfg := AuthConfig{Issuer: issuer.URL(), ClientID: issuer.ClientID, ClientSecret: issuer.Secret, PublicURL: restarted.URL, GroupRoles: map[string][]string{"admins": {"admin"}}, SessionLifetime: time.Minute}
	auth, err := NewAuth(oidc.ClientContext(context.Background(), issuer.Server.Client()), f.Store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Epoch == f.Auth.Epoch {
		t.Fatal("the restart did not replace the machine epoch")
	}
	current := VerifiedSettings{Schema: "agentgate.verified-settings.v1", Subject: "agentgate-control", Deployment: "dev", Target: "service:agentgate", Key: "agentgate.control.settings", Revision: 2, Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Deadline: time.Now().Add(time.Minute).UnixMilli(), Settings: DeploymentSettings{Schema: "agentgate.control.settings.v1", PublicURL: cfg.PublicURL, Issuer: cfg.Issuer, ClientID: cfg.ClientID, GroupRoles: cfg.GroupRoles, Listen: "0.0.0.0:8930", SessionSeconds: 60}}
	auth.BindLiveConfig(func() (VerifiedSettings, error) { return current, nil }, current.Settings)
	app := NewServer(f.Store, auth, filepath.Join(t.TempDir(), "spool"), t.TempDir())
	restarted.Config.Handler = app.Handler()
	sessionResponse, err := f.Client.Get(restarted.URL + "/api/v1/session")
	if err != nil {
		t.Fatal(err)
	}
	sessionResponse.Body.Close()
	body := []byte(`{"name":"Old issuer session","description":"","rights":{"workspace_write":false,"tcp_address":"127.0.0.1","tcp_port":18081},"reason":"Require a fresh login after an identity change"}`)
	request, _ := http.NewRequest("POST", restarted.URL+"/api/v1/policies", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", restarted.URL)
	request.Header.Set("X-CSRF-Token", oldSession.CSRF)
	mutated, err := f.Client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	mutated.Body.Close()
	if sessionResponse.StatusCode == 200 || mutated.StatusCode == 200 {
		t.Fatalf("OLD_ISSUER_SESSION_AUTHORIZES_AFTER_RESTART session_status=%d mutation_status=%d", sessionResponse.StatusCode, mutated.StatusCode)
	}
	issuer.Redirect = restarted.URL + "/auth/callback"
	f.App = restarted
	f.Auth = auth
	f.Issuer = issuer
	response, _ = loginFlow(t, f, "admin")
	response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatal("fresh login failed after the identity change", response.StatusCode)
	}
	fresh := readSession(t, f)
	if fresh.Actor.Subject == "" || !fresh.Actor.Can("policy:write") {
		t.Fatal("fresh session lost approved rights")
	}

}
