// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"regexp"
	"strings"
)

// Credentials that may appear in text the CLI did not write (a transport
// error, a server message). redactText replaces them before anything prints.
var (
	apiTokenText    = regexp.MustCompile(`agt_[A-Za-z0-9_-]{8,}`)
	enrollTokenText = regexp.MustCompile(`agtenr_[A-Za-z0-9_-]{8,}`)
	bearerText      = regexp.MustCompile(`(?i)(bearer\s+)[^\s"']+`)
	cookieText      = regexp.MustCompile(`(__Host-enforcer-(session|login)=)[^;\s"']+`)
)

// redactText removes tokens and session cookies from text.
func redactText(s string) string {
	s = enrollTokenText.ReplaceAllString(s, "agtenr_[redacted]")
	s = apiTokenText.ReplaceAllString(s, "agt_[redacted]")
	s = bearerText.ReplaceAllString(s, "${1}[redacted]")
	s = cookieText.ReplaceAllString(s, "${1}[redacted]")
	return s
}

// redactHeader shows a header value for --verbose without its secret part.
func redactHeader(name, value string) string {
	switch strings.ToLower(name) {
	case "authorization":
		if i := strings.IndexByte(value, ' '); i > 0 {
			return value[:i] + " [redacted]"
		}
		return "[redacted]"
	case "cookie", "set-cookie", "x-csrf-token":
		return "[redacted]"
	}
	return redactText(value)
}

// zero overwrites a buffer that held a secret.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
