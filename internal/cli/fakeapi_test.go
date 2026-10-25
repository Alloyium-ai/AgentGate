// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/control"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The fake service is built from the service's own OpenAPI document
// (control.OpenAPI): every /api/v1 request the CLI sends must name an
// operation the document publishes, and its body must validate against the
// operation's request schema. A test registers responses per operation.

const testToken = "agt_" + "TESTTOKENtesttokenTESTTOKENtesttokenTESTTOK"

type apiOp struct {
	method, template string
	re               *regexp.Regexp
	schema           *jsonschema.Schema
}

type recorded struct {
	Method, Path, Template string
	Query                  url.Values
	Header                 http.Header
	Body                   []byte
}

type handlerFunc func(w http.ResponseWriter, r *http.Request, body []byte, params []string)

type fakeAPI struct {
	t      *testing.T
	srv    *httptest.Server
	ops    []apiOp
	mu     sync.Mutex
	routes map[string]handlerFunc
	reqs   []recorded
	token  string
	health int
	// lenient accepts bodies that fail the request schema, for tests of
	// the service's own validation answer.
	lenient bool
}

var (
	openAPIOnce sync.Once
	openAPIOps  []apiOp
	openAPIErr  error
)

func loadOpenAPI() ([]apiOp, error) {
	openAPIOnce.Do(func() {
		doc := control.OpenAPI()
		raw, err := json.Marshal(doc)
		if err != nil {
			openAPIErr = err
			return
		}
		parsed, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			openAPIErr = err
			return
		}
		c := jsonschema.NewCompiler()
		const base = "https://agentgate.invalid/openapi.json"
		if err = c.AddResource(base, parsed); err != nil {
			openAPIErr = err
			return
		}
		paths := doc["paths"].(map[string]any)
		names := make([]string, 0, len(paths))
		for p := range paths {
			names = append(names, p)
		}
		sort.Strings(names)
		for _, p := range names {
			methods, _ := paths[p].(map[string]any)
			for method, v := range methods {
				segs := strings.Split(p, "/")
				for i, seg := range segs {
					if strings.HasPrefix(seg, "{") {
						segs[i] = `([^/]+)`
					} else {
						segs[i] = regexp.QuoteMeta(seg)
					}
				}
				op := apiOp{method: strings.ToUpper(method), template: p, re: regexp.MustCompile("^" + strings.Join(segs, "/") + "$")}
				if d, ok := v.(map[string]any); ok {
					if body, ok := d["requestBody"].(map[string]any); ok {
						ref := body["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]string)["$ref"]
						sch, err := c.Compile(base + ref)
						if err != nil {
							openAPIErr = fmt.Errorf("compile %s: %w", ref, err)
							return
						}
						op.schema = sch
					}
				}
				openAPIOps = append(openAPIOps, op)
			}
		}
	})
	return openAPIOps, openAPIErr
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	ops, err := loadOpenAPI()
	if err != nil {
		t.Fatalf("OpenAPI document: %v", err)
	}
	f := &fakeAPI{t: t, ops: ops, routes: map[string]handlerFunc{}, token: testToken, health: 200}
	// The fake serves the document it was built from, as the service does.
	f.reply("GET /api/v1/openapi.json", 200, control.OpenAPI())
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) URL() string { return f.srv.URL }

// handle registers a response for "METHOD /api/v1/template".
func (f *fakeAPI) handle(key string, h handlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[key] = h
}

// reply registers a fixed JSON answer.
func (f *fakeAPI) reply(key string, status int, v any) {
	f.handle(key, func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) { writeJSON(w, status, v) })
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-ID", "req-test")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}, "request_id": "req-test"})
}

func (f *fakeAPI) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded{}, f.reqs...)
}

// requestsTo returns the recorded requests for one operation key.
func (f *fakeAPI) requestsTo(key string) []recorded {
	out := []recorded{}
	for _, r := range f.requests() {
		if r.Method+" "+r.Template == key {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	rec := recorded{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Header: r.Header.Clone(), Body: body}
	var params []string
	switch {
	case r.URL.Path == "/healthz":
		rec.Template = "/healthz"
	case strings.HasPrefix(r.URL.Path, "/auth/"):
		rec.Template = r.URL.Path
	case r.URL.Path == "/api/v1/session":
		rec.Template = r.URL.Path
	default:
		var op *apiOp
		for i := range f.ops {
			if m := f.ops[i].re.FindStringSubmatch(r.URL.Path); m != nil && f.ops[i].method == r.Method {
				op, params = &f.ops[i], m[1:]
				break
			}
		}
		if op == nil {
			f.t.Errorf("the CLI called %s %s, which the OpenAPI document does not publish", r.Method, r.URL.Path)
			apiError(w, 404, "not_found", "unpublished operation")
			return
		}
		rec.Template = op.template
		if op.schema != nil {
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
			if err != nil {
				f.t.Errorf("%s %s: body is not JSON: %v", r.Method, r.URL.Path, err)
			} else if err = op.schema.Validate(inst); err != nil && !f.lenient {
				f.t.Errorf("%s %s: body does not match the OpenAPI request schema: %v\nbody: %s", r.Method, r.URL.Path, err, body)
			}
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				f.t.Errorf("%s %s: no JSON content type", r.Method, r.URL.Path)
			}
		} else if r.Method != "GET" && len(body) > 0 {
			f.t.Errorf("%s %s: body sent to an operation without a request body", r.Method, r.URL.Path)
		}
	}
	f.mu.Lock()
	f.reqs = append(f.reqs, rec)
	h := f.routes[r.Method+" "+rec.Template]
	health := f.health
	f.mu.Unlock()
	if rec.Template == "/healthz" && h == nil {
		writeJSON(w, health, map[string]string{"status": "ready"})
		return
	}
	if strings.HasPrefix(rec.Template, "/api/v1/") && !strings.HasPrefix(rec.Template, "/api/v1/hostd/") {
		auth := r.Header.Get("Authorization")
		cookie, _ := r.Cookie("__Host-enforcer-session")
		if auth != "Bearer "+f.token && (cookie == nil || cookie.Value != "fake-session") {
			apiError(w, 401, "authentication_required", "Sign in to continue.")
			return
		}
	}
	if h == nil {
		f.t.Errorf("no fake response for %s %s", r.Method, rec.Template)
		apiError(w, 501, "not_implemented", "no fake response")
		return
	}
	h(w, r, body, params)
}

// enableSessions serves the local sign-in flow for user/password.
func (f *fakeAPI) enableSessions(username, password string, roles []string) {
	f.reply("GET /auth/options", 200, map[string]bool{"local": true, "oidc": false})
	f.handle("GET /auth/local/challenge", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		http.SetCookie(w, &http.Cookie{Name: "__Host-enforcer-login", Value: "login-binding", Path: "/", Secure: true, HttpOnly: true})
		writeJSON(w, 200, map[string]string{"csrf_token": "challenge-state"})
	})
	f.handle("POST /auth/local/login", func(w http.ResponseWriter, r *http.Request, body []byte, _ []string) {
		c, _ := r.Cookie("__Host-enforcer-login")
		if c == nil || c.Value != "login-binding" || r.Header.Get("X-CSRF-Token") != "challenge-state" || r.Header.Get("Origin") != f.srv.URL {
			apiError(w, 403, "csrf_failed", "Start a local login from this application.")
			return
		}
		var in struct{ Username, Password string }
		json.Unmarshal(body, &in)
		if in.Username != username || in.Password != password {
			apiError(w, 401, "invalid_credentials", "The username or password is invalid.")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "__Host-enforcer-session", Value: "fake-session", Path: "/", Secure: true, HttpOnly: true})
		writeJSON(w, 200, map[string]string{"result": "signed in"})
	})
	f.handle("GET /api/v1/session", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		writeJSON(w, 200, map[string]any{"actor": map[string]any{"subject": "local:" + username, "kind": "human", "name": username, "roles": roles}, "csrf_token": "session-csrf", "expires": time.Now().Add(time.Hour).Unix()})
	})
	f.handle("POST /auth/logout", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		writeJSON(w, 200, map[string]string{"result": "signed out"})
	})
}

// fakeTerm is a scripted terminal.
type fakeTerm struct {
	mu      sync.Mutex
	tty     [3]bool
	secrets [][]byte
	prompts []string
}

func (f *fakeTerm) IsTerminal(stream int) bool { return f.tty[stream] }

func (f *fakeTerm) ReadSecret(ctx context.Context, prompt string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prompts = append(f.prompts, prompt)
	if len(f.secrets) == 0 {
		return nil, usageError("no scripted secret")
	}
	v := f.secrets[0]
	f.secrets = f.secrets[1:]
	return append([]byte{}, v...), nil
}

type harness struct {
	t      *testing.T
	api    *fakeAPI
	dir    string
	env    map[string]string
	term   *fakeTerm
	runner Runner
	euid   int
	now    time.Time
}

type result struct {
	stdout, stderr string
	code           int
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return &harness{t: t, api: newFakeAPI(t), dir: filepath.Join(t.TempDir(), "agentgate"), env: map[string]string{}, term: &fakeTerm{}, euid: os.Geteuid(), now: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
}

// login saves a context with the test token for the fake service.
func (h *harness) login(subject string, roles ...string) {
	h.t.Helper()
	st := store{dir: h.dir, euid: os.Geteuid()}
	err := st.update(func(cfg *Config) error {
		cfg.Contexts["default"] = &Context{Server: h.api.URL(), Token: testToken, TokenID: "tok1", TokenName: "test", Subject: subject, Roles: roles, ExpiresAt: "2026-11-23T12:00:00Z"}
		cfg.CurrentContext = "default"
		return nil
	})
	if err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) app(stdin string) (*App, *bytes.Buffer, *bytes.Buffer) {
	var out, errOut bytes.Buffer
	env := map[string]string{"AGENTGATE_CONFIG_DIR": h.dir, "HOME": h.t.TempDir()}
	for k, v := range h.env {
		env[k] = v
	}
	a := &App{
		Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errOut,
		Getenv:    func(k string) string { return env[k] },
		Term:      h.term,
		Runner:    h.runner,
		Transport: h.api.srv.Client().Transport,
		Now:       func() time.Time { return h.now },
		Euid:      func() int { return h.euid },
		Hostname:  func() (string, error) { return "testhost", nil },
		Sleep: func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Millisecond):
				return nil
			}
		},
		Version: "test",
	}
	return a, &out, &errOut
}

func (h *harness) run(stdin string, args ...string) result {
	h.t.Helper()
	return h.runCtx(context.Background(), stdin, args...)
}

func (h *harness) runCtx(ctx context.Context, stdin string, args ...string) result {
	h.t.Helper()
	a, out, errOut := h.app(stdin)
	code := a.Main(ctx, args)
	return result{out.String(), errOut.String(), code}
}

func (r result) String() string {
	return fmt.Sprintf("exit %d\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
}

func mustDecode(t *testing.T, raw []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
}

var t0ctx = context.Background()
