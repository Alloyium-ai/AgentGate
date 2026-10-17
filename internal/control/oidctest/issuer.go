// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// This fake issuer is used only by tests and the separate acceptance fixture binary.
package oidctest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"
)

var enc = base64.RawURLEncoding

type code struct {
	Nonce, Challenge, Redirect, User string
	Expiry                           int64
}
type Issuer struct {
	Server                     *httptest.Server
	ClientID, Secret, Redirect string
	key                        ed25519.PrivateKey
	pub                        ed25519.PublicKey
	mu                         sync.Mutex
	codes                      map[string]code
	mode                       string
}

func New() *Issuer    { return newIssuer(false) }
func NewTLS() *Issuer { return newIssuer(true) }
func newIssuer(secure bool) *Issuer {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	f := &Issuer{ClientID: "synthetic-client", Secret: "synthetic-test-only-secret", key: key, pub: pub, codes: map[string]code{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/jwks", f.jwks)
	mux.HandleFunc("/authorize", f.authorize)
	mux.HandleFunc("/complete", f.complete)
	mux.HandleFunc("/token", f.token)
	if secure {
		f.Server = httptest.NewTLSServer(mux)
	} else {
		f.Server = httptest.NewServer(mux)
	}
	return f
}
func (f *Issuer) URL() string       { return f.Server.URL }
func (f *Issuer) Close()            { f.Server.Close() }
func (f *Issuer) Mode(value string) { f.mu.Lock(); defer f.mu.Unlock(); f.mode = value }
func send(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(value)
}
func (f *Issuer) discovery(w http.ResponseWriter, r *http.Request) {
	send(w, map[string]any{"issuer": f.URL(), "authorization_endpoint": f.URL() + "/authorize", "token_endpoint": f.URL() + "/token", "jwks_uri": f.URL() + "/jwks", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"EdDSA"}, "code_challenge_methods_supported": []string{"S256"}})
}
func (f *Issuer) jwks(w http.ResponseWriter, r *http.Request) {
	send(w, map[string]any{"keys": []any{map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": "synthetic-key", "alg": "EdDSA", "use": "sig", "x": enc.EncodeToString(f.pub)}}})
}

var login = template.Must(template.New("login").Parse(`<!doctype html><html><head><title>Synthetic identity provider</title></head><body><h1>Synthetic developer acceptance</h1><p>This local issuer is not a production identity provider.</p><form action="/complete" method="get">{{range $key,$value:=.}}<input type="hidden" name="{{$key}}" value="{{$value}}">{{end}}<button name="user" value="admin">Sign in as Synthetic Admin</button><button name="user" value="editor">Sign in as Synthetic Editor</button><button name="user" value="approver">Sign in as Synthetic Approver</button><button name="user" value="auditor">Sign in as Synthetic Auditor</button><button name="user" value="viewer">Sign in as Synthetic Viewer</button><button name="user" value="untrusted">Sign in with an unknown group</button></form></body></html>`))

func (f *Issuer) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != f.ClientID || q.Get("redirect_uri") != f.Redirect || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "invalid synthetic authorization", 400)
		return
	}
	values := map[string]string{}
	for _, key := range []string{"state", "nonce", "code_challenge", "redirect_uri", "client_id"} {
		values[key] = q.Get(key)
	}
	login.Execute(w, values)
}
func (f *Issuer) complete(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != f.ClientID || q.Get("redirect_uri") != f.Redirect {
		http.Error(w, "invalid redirect", 400)
		return
	}
	b := make([]byte, 16)
	rand.Read(b)
	id := enc.EncodeToString(b)
	f.mu.Lock()
	f.codes[id] = code{q.Get("nonce"), q.Get("code_challenge"), f.Redirect, q.Get("user"), time.Now().Unix() + 60}
	f.mu.Unlock()
	u, _ := url.Parse(f.Redirect)
	p := u.Query()
	p.Set("code", id)
	p.Set("state", q.Get("state"))
	u.RawQuery = p.Encode()
	http.Redirect(w, r, u.String(), 302)
}
func (f *Issuer) token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	client, secret, ok := r.BasicAuth()
	if !ok {
		client, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
	}
	if client != f.ClientID || secret != f.Secret {
		http.Error(w, "invalid client", 401)
		return
	}
	f.mu.Lock()
	c, ok := f.codes[r.Form.Get("code")]
	delete(f.codes, r.Form.Get("code"))
	mode := f.mode
	f.mu.Unlock()
	sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if !ok || c.Expiry < time.Now().Unix() || c.Challenge != enc.EncodeToString(sum[:]) || r.Form.Get("redirect_uri") != c.Redirect {
		http.Error(w, "invalid code or PKCE", 401)
		return
	}
	group := map[string]string{"admin": "admins", "editor": "editors", "viewer": "viewers", "approver": "approvers", "auditor": "auditors", "untrusted": "unknown"}[c.User]
	if group == "" {
		group = "unknown"
	}
	claims := map[string]any{"iss": f.URL(), "sub": "synthetic-" + c.User, "aud": f.ClientID, "iat": time.Now().Unix(), "exp": time.Now().Unix() + 600, "nonce": c.Nonce, "groups": []string{group}, "name": "Synthetic " + c.User, "actor_kind": "human"}
	switch mode {
	case "wrong-issuer":
		claims["iss"] = "https://untrusted.invalid"
	case "wrong-audience":
		claims["aud"] = "other-client"
	case "expired":
		claims["exp"] = time.Now().Unix() - 10
	case "wrong-nonce":
		claims["nonce"] = "untrusted"
	case "machine-account":
		claims["actor_kind"] = "service"
	case "invalid-claims":
		claims["actor_kind"] = false
	}
	header := map[string]string{"alg": "EdDSA", "kid": "synthetic-key"}
	h, _ := json.Marshal(header)
	body, _ := json.Marshal(claims)
	unsigned := enc.EncodeToString(h) + "." + enc.EncodeToString(body)
	signature := ed25519.Sign(f.key, []byte(unsigned))
	if mode == "invalid-signature" {
		signature[0] ^= 1
	}
	jwt := unsigned + "." + enc.EncodeToString(signature)
	send(w, map[string]any{"access_token": "synthetic-test-only", "token_type": "Bearer", "expires_in": 600, "id_token": jwt})
}
func (f *Issuer) CompleteURL(authorization, user string) string {
	u, _ := url.Parse(authorization)
	q := u.Query()
	q.Set("user", user)
	return fmt.Sprintf("%s/complete?%s", f.URL(), q.Encode())
}
