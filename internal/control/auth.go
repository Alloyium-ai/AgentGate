// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/requestproof"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var b64 = base64.RawURLEncoding

type AuthConfig struct {
	Issuer, ClientID, ClientSecret, PublicURL string
	AuthMode, Instance                        string
	GroupRoles                                map[string][]string
	SessionLifetime                           time.Duration
}
type Auth struct {
	Store          *Store
	Config         AuthConfig
	OAuth          oauth2.Config
	Verifier       *oidc.IDTokenVerifier
	Epoch          string
	HTTPClient     *http.Client
	CurrentConfig  func() (AuthConfig, error)
	LoginAuthority string
}
type Session struct {
	Binding string `json:"-"`
	Actor   Actor  `json:"actor"`
	CSRF    string `json:"csrf_token"`
	Expires int64  `json:"expires"`
}

func randomToken() string {
	v := make([]byte, 32)
	if _, err := rand.Read(v); err != nil {
		panic(err)
	}
	return b64.EncodeToString(v)
}
func NewAuth(ctx context.Context, s *Store, c AuthConfig) (*Auth, error) {
	s.LocalIdentity = c.Instance != ""
	if c.SessionLifetime <= 0 || c.SessionLifetime > time.Hour {
		c.SessionLifetime = 30 * time.Minute
	}
	if c.AuthMode == "local" {
		auth := &Auth{Store: s, Config: c, Epoch: randomToken()}
		auth.LoginAuthority = loginAuthority(c)
		if err := s.bindLoginAuthority(auth.LoginAuthority, auth.roles); err != nil {
			return nil, err
		}
		return auth, nil
	}
	p, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(c.Issuer, "https://") {
		var metadata struct {
			Authorization string `json:"authorization_endpoint"`
			Token         string `json:"token_endpoint"`
			Keys          string `json:"jwks_uri"`
		}
		if err = p.Claims(&metadata); err != nil {
			return nil, err
		}
		for _, endpoint := range []string{metadata.Authorization, metadata.Token, metadata.Keys} {
			u, e := url.Parse(endpoint)
			if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
				return nil, errors.New("OIDC discovery endpoints must use HTTPS")
			}
		}
	}
	client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	auth := &Auth{Store: s, Config: c, Epoch: randomToken(), HTTPClient: client, Verifier: p.Verifier(&oidc.Config{ClientID: c.ClientID}), OAuth: oauth2.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, RedirectURL: strings.TrimRight(c.PublicURL, "/") + "/auth/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups"}, Endpoint: p.Endpoint()}}
	auth.LoginAuthority = loginAuthority(c)
	if err = s.bindLoginAuthority(auth.LoginAuthority, auth.roles); err != nil {
		return nil, err
	}
	return auth, nil
}
func secureCookie(w http.ResponseWriter, name, value string, max int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: max})
}
func authOperation(r *http.Request, action string, a Actor) Operation {
	return Operation{Actor: a, Action: action, Resource: "session", RequestID: r.Header.Get("X-Request-ID"), CorrelationID: r.Header.Get("X-Correlation-ID"), Reason: "OIDC session lifecycle"}
}
func (a *Auth) Login(w http.ResponseWriter, r *http.Request) error {
	if a.Verifier == nil {
		return fail(404, "oidc_disabled", "OIDC sign-in is disabled.")
	}
	state, nonce, verifier, binding := randomToken(), randomToken(), oauth2.GenerateVerifier(), randomToken()
	op := a.operation(r, "auth.login.started", Actor{Subject: "anonymous", Kind: "unknown", Scopes: []string{"auth:write"}})
	_, err := a.Store.Mutation(op, "auth:write", false, func(tx *sql.Tx, _ *Operation) (any, error) {
		_, err := tx.Exec("INSERT INTO login_states VALUES(?,?,?,?,?)", digest([]byte(state)), nonce, verifier, a.stateBinding(binding), time.Now().Add(5*time.Minute).Unix())
		return map[string]string{"result": "redirected"}, err
	})
	if err != nil {
		return err
	}
	secureCookie(w, "__Host-enforcer-login", binding, 300)
	u := a.OAuth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, u, http.StatusFound)
	return nil
}
func (a *Auth) consumeState(r *http.Request) (string, string, error) {
	var nonce, verifier string
	cookie, err := r.Cookie("__Host-enforcer-login")
	if err != nil {
		return "", "", fail(401, "invalid_state", "The login session expired. Start sign-in again.")
	}
	state := r.URL.Query().Get("state")
	if len(state) > 100 || len(state) < 20 {
		return "", "", fail(401, "invalid_state", "The login state is invalid.")
	}
	op := a.operation(r, "auth.callback.received", Actor{Subject: "anonymous", Kind: "unknown", Scopes: []string{"auth:write"}})
	_, err = a.Store.Mutation(op, "auth:write", false, func(tx *sql.Tx, _ *Operation) (any, error) {
		var binding string
		var expires int64
		e := tx.QueryRow("SELECT nonce,verifier,binding_hash,expires FROM login_states WHERE state_hash=?", digest([]byte(state))).Scan(&nonce, &verifier, &binding, &expires)
		if e != nil || expires <= time.Now().Unix() || subtle.ConstantTimeCompare([]byte(binding), []byte(a.stateBinding(cookie.Value))) != 1 {
			return nil, fail(401, "invalid_state", "The login state expired or already exists in a completed login.")
		}
		_, e = tx.Exec("DELETE FROM login_states WHERE state_hash=?", digest([]byte(state)))
		return map[string]string{"result": "consumed"}, e
	})
	return nonce, verifier, err
}
func (a *Auth) Callback(w http.ResponseWriter, r *http.Request) error {
	if a.Verifier == nil {
		return fail(404, "oidc_disabled", "OIDC sign-in is disabled.")
	}
	nonce, verifier, err := a.consumeState(r)
	if err != nil {
		return err
	}
	secureCookie(w, "__Host-enforcer-login", "", -1)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if a.HTTPClient != nil {
		ctx = oidc.ClientContext(ctx, a.HTTPClient)
	}
	token, err := a.OAuth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		return fail(401, "oidc_exchange_failed", "The identity provider rejected this login.")
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return fail(401, "invalid_token", "The identity provider omitted its ID token.")
	}
	id, err := a.Verifier.Verify(ctx, raw)
	if err != nil {
		return fail(401, "invalid_token", "The identity token signature, issuer, audience or expiry is invalid.")
	}
	if subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(nonce)) != 1 {
		return fail(401, "invalid_nonce", "The identity token does not belong to this login.")
	}
	var claims struct {
		Groups    []string `json:"groups"`
		Name      string   `json:"name"`
		Preferred string   `json:"preferred_username"`
		ActorKind string   `json:"actor_kind"`
	}
	if err = id.Claims(&claims); err != nil {
		return fail(401, "invalid_claims", "The identity claims are invalid.")
	}
	actor := Actor{Subject: id.Subject, Kind: claims.ActorKind, Name: claims.Name, Groups: claims.Groups}
	if a.Config.Instance != "" {
		actor.Subject = "oidc:" + id.Subject
		// Standard OIDC human logins do not require a private fleet claim.
		if actor.Kind == "" {
			actor.Kind = "human"
		}
	}
	if actor.Kind != "human" {
		if actor.Kind != "service" && actor.Kind != "agent" {
			actor.Kind = "unknown"
		}
		return deniedCallback(actor, fail(403, "machine_session_forbidden", "Machine identities use the separate signed service API."))
	}
	actor.Roles = a.roles(claims.Groups)
	if actor.Name == "" {
		actor.Name = claims.Preferred
	}
	if len(actor.Name) > 128 {
		actor.Name = id.Subject
	}
	if len(actor.Roles) == 0 {
		return deniedCallback(actor, fail(403, "untrusted_groups", "Your Authentik groups do not grant access to this application."))
	}
	sid, csrf := randomToken(), randomToken()
	expires := time.Now().Add(a.Config.SessionLifetime).Unix()
	if id.Expiry.Unix() < expires {
		expires = id.Expiry.Unix()
	}
	op := a.operation(r, "auth.login.completed", actor)
	actor.Scopes = []string{"auth:write"}
	op.Actor = Actor{Subject: actor.Subject, Kind: "system", Scopes: []string{"auth:write"}}
	op.SessionHash = digest([]byte(sid))
	_, err = a.Store.Mutation(op, "auth:write", false, func(tx *sql.Tx, operation *Operation) (any, error) {
		operation.Actor = actor
		_, e := tx.Exec("INSERT INTO sessions VALUES(?,?,?,?)", digest([]byte(sid)), jsonText(sessionActor{actor, a.LoginAuthority}), csrf, expires)
		return map[string]any{"subject": actor.Subject, "expires": expires}, e
	})
	if err != nil {
		return deniedCallback(actor, err)
	}
	secureCookie(w, "__Host-enforcer-session", sid, int(expires-time.Now().Unix()))
	http.Redirect(w, r, "/", http.StatusFound)
	return nil
}
func (a *Auth) roles(groups []string) []string {
	out := []string{}
	seen := map[string]bool{}
	valid := map[string]bool{"viewer": true, "auditor": true, "editor": true, "approver": true, "admin": true}
	cfg := a.Config
	if a.CurrentConfig != nil {
		var err error
		cfg, err = a.CurrentConfig()
		if err != nil {
			return out
		}
	}
	for _, group := range groups {
		for _, role := range cfg.GroupRoles[group] {
			if valid[role] && !seen[role] {
				out = append(out, role)
				seen[role] = true
			}
		}
	}
	return out
}
func (a *Auth) Session(r *http.Request) (Session, error) {
	var session Session
	cookie, err := r.Cookie("__Host-enforcer-session")
	if err != nil {
		return session, fail(401, "authentication_required", "Sign in to continue.")
	}
	session.Binding = digest([]byte(cookie.Value))
	var actor string
	actor, session.CSRF, session.Expires, err = a.sessionRow(session.Binding)
	if err != nil {
		return session, err
	}
	var stored sessionActor
	err = json.Unmarshal([]byte(actor), &stored)
	if err != nil {
		return session, err
	}
	if stored.LoginAuthority != a.LoginAuthority {
		return session, fail(401, "login_authority_changed", "The login authority changed. Sign in again.")
	}
	session.Actor = stored.Actor
	if a.Config.Instance != "" && strings.HasPrefix(session.Actor.Subject, "local:") {
		a.Store.mu.Lock()
		session.Actor, err = localActor(a.Store.DB, session.Actor.Subject)
		a.Store.mu.Unlock()
		return session, err
	}
	if err == nil {
		session.Actor.Roles = a.roles(session.Actor.Groups)
		if len(session.Actor.Roles) == 0 {
			return session, fail(403, "untrusted_groups", "The current role mapping no longer grants access.")
		}
	}
	return session, err
}
func (a *Auth) CSRF(r *http.Request, session Session) error {
	if r.Header.Get("Origin") != strings.TrimRight(a.Config.PublicURL, "/") || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(session.CSRF)) != 1 {
		return fail(403, "csrf_failed", "The request does not belong to this browser session.")
	}
	return nil
}
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) error {
	session, err := a.Session(r)
	if err != nil {
		return err
	}
	if err = a.CSRF(r, session); err != nil {
		return err
	}
	cookie, _ := r.Cookie("__Host-enforcer-session")
	op := a.operation(r, "auth.logout", session.Actor)
	op.Actor.Scopes = []string{"auth:write"}
	op.SessionHash = session.Binding
	_, err = a.Store.Mutation(op, "auth:write", false, func(tx *sql.Tx, _ *Operation) (any, error) {
		_, e := tx.Exec("DELETE FROM sessions WHERE id_hash=?", digest([]byte(cookie.Value)))
		return map[string]string{"result": "session revoked"}, e
	})
	if err != nil {
		return err
	}
	secureCookie(w, "__Host-enforcer-session", "", -1)
	return nil
}
func validPublicKey(value string) error {
	key, err := b64.DecodeString(value)
	if err != nil || len(key) != ed25519.PublicKeySize || b64.EncodeToString(key) != value {
		return fail(422, "invalid_public_key", "Supply an Ed25519 public key.")
	}
	return nil
}
func EncodePublic(key ed25519.PublicKey) string { return b64.EncodeToString(key) }
func SignProof(subject, method, path string, body []byte, key ed25519.PrivateKey, audience, epoch string) string {
	return requestproof.Sign(subject, method, path, audience, epoch, body, key)
}
func (a *Auth) Machine(r *http.Request, body []byte) (Actor, string, error) {
	value := strings.TrimPrefix(r.Header.Get("Authorization"), "Alloyium-Proof ")
	p, err := requestproof.Parse(value)
	if err != nil {
		return Actor{}, "", fail(401, "invalid_proof", "Supply a valid scoped request proof.")
	}
	svc, err := serviceFrom(a.Store.DB, p.Subject)
	if err != nil {
		return Actor{}, "", fail(401, "unknown_service", "The service identity is not enrolled.")
	}
	key, err := b64.DecodeString(svc.PublicKey)
	if err != nil {
		return Actor{}, "", fail(401, "invalid_proof", "The enrolled public key is invalid.")
	}
	if _, err = requestproof.Verify(value, ed25519.PublicKey(key), strings.TrimRight(a.Config.PublicURL, "/"), a.Epoch, r.Method, r.URL.RequestURI(), body); err != nil {
		return Actor{}, "", fail(401, "invalid_proof", "The signed proof does not bind this recipient, epoch or request.")
	}
	actor := Actor{Subject: svc.Subject, Kind: svc.Kind, Scopes: svc.Scopes}
	if !svc.Enabled {
		return actor, p.Nonce, fail(401, "unknown_service", "The service identity is not active.")
	}
	return actor, p.Nonce, nil
}

func ValidateAuthConfig(c AuthConfig) error {
	for _, v := range []string{c.Issuer, c.PublicURL} {
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("OIDC issuer and public URL must use explicit HTTPS origins")
		}
	}
	u, _ := url.Parse(c.PublicURL)
	if u.Path != "" && u.Path != "/" {
		return errors.New("the public URL must be an HTTPS origin without a path")
	}
	if c.ClientID == "" {
		return errors.New("OIDC client ID required")
	}
	return nil
}
