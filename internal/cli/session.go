// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"regexp"
	"strings"
	"syscall"
)

// A password sign-in is the only way to mint, list or revoke API tokens:
// the service refuses those to a token. The CLI signs in with the local
// login flow (challenge cookie, then credentials), uses the short browser
// session for the one operation, and signs out. The session cookie is never
// stored.

var usernamePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{2,63}$`)

type session struct {
	c      *Client
	cookie string
	csrf   string
	info   SessionInfo
}

func cookieFrom(h http.Header, name string) string {
	for _, c := range (&http.Response{Header: h}).Cookies() {
		if c.Name == name && c.Value != "" {
			return c.Name + "=" + c.Value
		}
	}
	return ""
}

// appendJSONString appends b as a JSON string without converting it to a Go
// string, so the caller can zero every copy of a password.
func appendJSONString(dst, b []byte) []byte {
	const hexDigits = "0123456789abcdef"
	dst = append(dst, '"')
	for _, c := range b {
		switch {
		case c == '"' || c == '\\':
			dst = append(dst, '\\', c)
		case c < 0x20:
			dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		default:
			dst = append(dst, c)
		}
	}
	return append(dst, '"')
}

// signIn performs the local password login and returns a session.
func signIn(ctx context.Context, c *Client, username string, password []byte) (*session, error) {
	var options struct {
		Local bool `json:"local"`
		OIDC  bool `json:"oidc"`
	}
	if _, err := c.call(ctx, request{method: "GET", path: "/auth/options", noAuth: true, retry: true}, &options); err != nil {
		return nil, err
	}
	if !options.Local {
		return nil, &Error{Exit: ExitAuth, Code: "local_login_disabled", Message: "This service has no password sign-in.", Hint: codeHints["local_login_disabled"]}
	}
	resp, err := c.do(ctx, request{method: "GET", path: "/auth/local/challenge", noAuth: true})
	if err != nil {
		return nil, err
	}
	var challenge struct {
		CSRF string `json:"csrf_token"`
	}
	json.Unmarshal(resp.body, &challenge)
	login := cookieFrom(resp.header, "__Host-enforcer-login")
	if login == "" || challenge.CSRF == "" {
		return nil, &Error{Exit: ExitServer, Code: "invalid_response", Message: "The service did not issue a sign-in challenge.", RequestID: resp.requestID}
	}
	body := []byte(`{"username":`)
	body = appendJSONString(body, []byte(username))
	body = append(body, `,"password":`...)
	body = appendJSONString(body, password)
	body = append(body, '}')
	defer zero(body)
	resp, err = c.do(ctx, request{method: "POST", path: "/auth/local/login", noAuth: true, cookie: login, csrf: challenge.CSRF, body: body})
	if err != nil {
		return nil, err
	}
	s := &session{c: c, cookie: cookieFrom(resp.header, "__Host-enforcer-session")}
	if s.cookie == "" {
		return nil, &Error{Exit: ExitServer, Code: "invalid_response", Message: "The service signed in without a session cookie.", RequestID: resp.requestID}
	}
	if _, err = c.call(ctx, request{method: "GET", path: apiPrefix + "/session", cookie: s.cookie, retry: true}, &s.info); err != nil {
		return nil, err
	}
	s.csrf = s.info.CSRF
	return s, nil
}

func (s *session) call(ctx context.Context, method, path string, body any, out any) ([]byte, error) {
	r := request{method: method, path: path, cookie: s.cookie}
	if method == "GET" {
		r.retry = true
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r.body, r.csrf = raw, s.csrf
	}
	return s.c.call(ctx, r, out)
}

// close signs out; the session would otherwise expire on its own.
func (s *session) close(ctx context.Context) {
	s.c.do(ctx, request{method: "POST", path: "/auth/logout", cookie: s.cookie, csrf: s.csrf, body: []byte("{}")})
}

// credentialFlags are the sign-in inputs shared by login, token and up.
type credentialFlags struct {
	username      string
	passwordStdin bool
	passwordFile  string
}

func (f *credentialFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.username, "username", "", "")
	fs.BoolVar(&f.passwordStdin, "password-stdin", false, "")
	fs.StringVar(&f.passwordFile, "password-file", "", "")
}

const credentialHelp = `  --username NAME      local account to sign in with (prompted on a terminal)
  --password-stdin     read the password from standard input instead of prompting
  --password-file F    read the password from a mode 0600 file you own
  The password is never accepted as an argument or an environment variable.`

// credentials obtains a username and password. The caller zeroes the password.
func (e *env) credentials(ctx context.Context, f credentialFlags, purpose string) (string, []byte, error) {
	username := strings.TrimSpace(f.username)
	if username == "" {
		if !e.app.Term.IsTerminal(0) || f.passwordStdin {
			return "", nil, usageError("%s needs --username in a script", purpose)
		}
		var err error
		if username, err = e.readLine(ctx, "Username: "); err != nil {
			return "", nil, err
		}
		username = strings.TrimSpace(username)
	}
	if !usernamePattern.MatchString(username) {
		return "", nil, usageError("a local username matches ^[a-z][a-z0-9_.-]{2,63}$")
	}
	password, err := e.readPassword(ctx, f, "Password for "+username, false)
	return username, password, err
}

func (e *env) readPassword(ctx context.Context, f credentialFlags, label string, confirmTwice bool) ([]byte, error) {
	switch {
	case f.passwordStdin && f.passwordFile != "":
		return nil, usageError("use --password-stdin or --password-file, not both")
	case f.passwordFile != "":
		return readSecretFile(f.passwordFile, os.Geteuid())
	case f.passwordStdin:
		return e.readStdinSecret()
	case e.app.Term.IsTerminal(0):
		return e.readNewSecret(ctx, label, confirmTwice)
	}
	return nil, usageError("no terminal to prompt for the password: use --password-stdin or --password-file")
}

// readSecretFile reads a private file holding one secret line.
func readSecretFile(path string, euid int) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, usageError("cannot open %s: %v", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, failure("cannot stat %s", path)
	}
	if err = checkOwned(path, info, euid, false); err != nil {
		return nil, err
	}
	buf := make([]byte, maxSecretInput+2)
	n := 0
	for n < len(buf) {
		m, err := f.Read(buf[n:])
		n += m
		if err != nil || m == 0 {
			break
		}
	}
	value := buf[:n]
	if n > maxSecretInput {
		zero(buf)
		return nil, usageError("%s holds more than %d bytes", path, maxSecretInput)
	}
	for len(value) > 0 && (value[len(value)-1] == '\n' || value[len(value)-1] == '\r') {
		value = value[:len(value)-1]
	}
	if len(value) == 0 {
		return nil, usageError("%s is empty", path)
	}
	return value, nil
}
