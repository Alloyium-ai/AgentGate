// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"errors"
	"slices"
	"strings"
	"unicode/utf8"
)

const SSHCommandMaxBytes = 16 << 10
const SSHEmptyInputDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// The shell receives only these signed, fixed toolchain settings. SSH client
// environment variables never enter the manifest.
func SSHEnvironmentMatches(workspace string, environment map[string]string) bool {
	for key, value := range environment {
		switch key {
		case "PATH":
			if value != "/usr/bin:/bin" {
				return false
			}
		case "HOME":
			if value != workspace {
				return false
			}
		case "LANG":
			if value != "C.UTF-8" {
				return false
			}
		case "PYTHONDONTWRITEBYTECODE":
			if value != "1" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// ValidateSSHCommand binds the exact SSH command to a POSIX shell -c invocation.
// Transport input is always empty; the command and workspace are in the signed digest.
func (m Manifest) ValidateSSHCommand() error {
	if m.AgentKind != "ssh" || len(m.Arguments) != 2 || m.Arguments[0] != "-c" ||
		len(m.Arguments[1]) == 0 || len(m.Arguments[1]) > SSHCommandMaxBytes ||
		!utf8.ValidString(m.Arguments[1]) || strings.ContainsRune(m.Arguments[1], 0) || strings.ContainsRune(m.Arguments[1], utf8.RuneError) || !SSHEnvironmentMatches(m.Workspace, m.Environment) ||
		m.InputDigest != SSHEmptyInputDigest {
		return errors.New("the exact SSH shell command contract differs")
	}
	return nil
}

// SSHRuntimeMatches requires a separately enrolled shell with only the -c prefix.
func SSHRuntimeMatches(prefix []string, m Manifest) bool {
	return slices.Equal(prefix, []string{"-c"}) && m.ValidateSSHCommand() == nil
}
