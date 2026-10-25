// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// ConfigFormat identifies the CLI configuration file.
const ConfigFormat = "agentgate.cli.config.v1"

const (
	configFileName = "config.json"
	maxConfigBytes = 1 << 20
	defaultContext = "default"
)

var contextNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Config is ~/.config/agentgate/config.json. It holds API tokens, so it is
// mode 0600 in a mode 0700 directory owned by the user, and the CLI refuses
// to read or write it otherwise.
type Config struct {
	Format         string              `json:"format"`
	CurrentContext string              `json:"current_context"`
	Contexts       map[string]*Context `json:"contexts"`
}

// Context is one service and the credential the CLI uses for it.
type Context struct {
	Server            string   `json:"server"`
	Token             string   `json:"token,omitempty"`
	TokenID           string   `json:"token_id,omitempty"`
	TokenName         string   `json:"token_name,omitempty"`
	Subject           string   `json:"subject,omitempty"`
	Roles             []string `json:"roles,omitempty"`
	ExpiresAt         string   `json:"expires_at,omitempty"`
	CAFile            string   `json:"ca_file,omitempty"`
	CertSHA256        string   `json:"cert_sha256,omitempty"`
	AllowLoopbackHTTP bool     `json:"allow_loopback_http,omitempty"`
}

// HasRole reports whether the token recorded for the context carries role
// (admin implies every role).
func (c *Context) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role || r == "admin" {
			return true
		}
	}
	return false
}

// store locates the configuration directory and enforces its custody.
type store struct {
	dir  string
	euid int
}

// underSudo reports whether this root process was started by sudo for
// another account: the environment (HOME, XDG_CONFIG_HOME) then belongs to
// that user, who may point it anywhere.
func underSudo(getenv func(string) string, euid int) bool {
	if euid != 0 {
		return false
	}
	user, uid := getenv("SUDO_USER"), getenv("SUDO_UID")
	return (user != "" && user != "root") || (uid != "" && uid != "0")
}

// configDir is $AGENTGATE_CONFIG_DIR, else $XDG_CONFIG_HOME/agentgate, else
// $HOME/.config/agentgate. Under sudo it never trusts HOME or
// XDG_CONFIG_HOME: root would otherwise create and write token files in a
// tree the invoking user controls (a link there redirects root's writes).
// It then uses root's own home from the account database (homeOf), which
// root owns; AGENTGATE_CONFIG_DIR still wins, under the usual custody rules
// (a directory owned by root, mode 0700). Outside sudo, a HOME or
// XDG_CONFIG_HOME that exists but belongs to another user (su without a
// login shell, an inherited environment) is refused for the same reason
// (ownerOf reports a path's owner). It returns a note to show when it set
// HOME aside.
func configDir(getenv func(string) string, euid int, homeOf func(uid int) (string, error), ownerOf func(path string) (int, bool)) (string, string, error) {
	if dir := getenv("AGENTGATE_CONFIG_DIR"); dir != "" {
		if !filepath.IsAbs(dir) {
			return "", "", usageError("AGENTGATE_CONFIG_DIR must be an absolute path")
		}
		return filepath.Clean(dir), "", nil
	}
	if underSudo(getenv, euid) {
		home, err := homeOf(euid)
		if err != nil || home == "" || !filepath.IsAbs(home) || filepath.Clean(home) != home {
			return "", "", failure("running under sudo for %s, agentgate does not keep tokens where HOME points, and root's home cannot be found in the account database (%v); set AGENTGATE_CONFIG_DIR to a root-owned directory", getenv("SUDO_USER"), err)
		}
		dir := filepath.Join(home, ".config", "agentgate")
		note := ""
		if h := getenv("HOME"); h != home || getenv("XDG_CONFIG_HOME") != "" {
			note = "running under sudo for " + firstNonEmpty(getenv("SUDO_USER"), "uid "+getenv("SUDO_UID")) + ": the configuration is root's own " + dir +
				", not the directory HOME or XDG_CONFIG_HOME names; as that user, run agentgate login to keep a context of your own"
		}
		return dir, note, nil
	}
	base, name, dir := "", "", ""
	if xdg := getenv("XDG_CONFIG_HOME"); xdg != "" && filepath.IsAbs(xdg) {
		base, name, dir = filepath.Clean(xdg), "XDG_CONFIG_HOME", filepath.Join(xdg, "agentgate")
	} else {
		home := getenv("HOME")
		if home == "" || !filepath.IsAbs(home) {
			return "", "", failure("HOME is not set; set AGENTGATE_CONFIG_DIR to an absolute directory")
		}
		base, name, dir = filepath.Clean(home), "HOME", filepath.Join(home, ".config", "agentgate")
	}
	if owner, exists := ownerOf(base); exists && owner != euid {
		return "", "", trustError("config_custody", fmt.Sprintf("%s (%s) belongs to uid %d, not to you (uid %d): agentgate would create its token files in another user's tree, and refuses.", name, base, owner, euid),
			"Run agentgate as that user, or set AGENTGATE_CONFIG_DIR to a directory you own.")
	}
	return dir, "", nil
}

// pathOwner reports the owner of an existing path (following links).
func pathOwner(path string) (int, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// accountHome looks up a uid's home directory in the account database.
func accountHome(uid int) (string, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}

func custodyError(path, problem, fix string) *Error {
	return trustError("config_custody", path+" "+problem+"; the CLI keeps tokens there and refuses to use it.", fix)
}

func checkOwned(path string, info os.FileInfo, euid int, wantDir bool) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return custodyError(path, "is a symbolic link", "Replace the link with a real "+map[bool]string{true: "directory", false: "file"}[wantDir]+".")
	}
	if wantDir && !info.IsDir() {
		return custodyError(path, "is not a directory", "Move it away so the CLI can create the directory.")
	}
	if !wantDir && !info.Mode().IsRegular() {
		return custodyError(path, "is not a regular file", "Move it away.")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != euid {
		return custodyError(path, fmt.Sprintf("is owned by uid %d, not by you (uid %d)", st.Uid, euid), "Use a configuration directory you own (AGENTGATE_CONFIG_DIR).")
	}
	if info.Mode().Perm()&0o077 != 0 {
		mode := "600"
		if wantDir {
			mode = "700"
		}
		return custodyError(path, fmt.Sprintf("is accessible by group or others (mode %04o)", info.Mode().Perm()), "Run chmod "+mode+" "+path+".")
	}
	return nil
}

// checkDir verifies the directory; missing is reported as os.ErrNotExist.
func (s store) checkDir() error {
	info, err := os.Lstat(s.dir)
	if err != nil {
		return err
	}
	return checkOwned(s.dir, info, s.euid, true)
}

func (s store) ensureDir() error {
	err := s.checkDir()
	if errors.Is(err, os.ErrNotExist) {
		if err = os.MkdirAll(filepath.Dir(s.dir), 0o700); err != nil {
			return failure("cannot create %s: %v", filepath.Dir(s.dir), err)
		}
		if err = os.Mkdir(s.dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return failure("cannot create %s: %v", s.dir, err)
		}
		err = s.checkDir()
	}
	return err
}

// readPrivate reads a private file without following links. A missing file
// returns os.ErrNotExist.
func (s store) readPrivate(name string, max int64) ([]byte, error) {
	if err := s.checkDir(); err != nil {
		return nil, err
	}
	path := filepath.Join(s.dir, name)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, custodyError(path, "is a symbolic link", "Replace the link with a real file.")
		}
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err = checkOwned(path, info, s.euid, false); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, failure("%s exceeds %d bytes", path, max)
	}
	return raw, nil
}

// writePrivate replaces name atomically with a mode 0600 file.
func (s store) writePrivate(name string, data []byte) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	path := filepath.Join(s.dir, name)
	if info, err := os.Lstat(path); err == nil {
		if err = checkOwned(path, info, s.euid, false); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(s.dir, "."+name+".*")
	if err != nil {
		return failure("cannot write %s: %v", path, err)
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		return failure("cannot write %s: %v", path, err)
	}
	if d, derr := os.Open(s.dir); derr == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// lock serializes read-modify-write cycles of the configuration.
func (s store) lock() (func(), error) {
	if err := s.ensureDir(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.dir, ".lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, failure("cannot lock the configuration: %v", err)
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, failure("cannot lock the configuration: %v", err)
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

func (s store) load() (*Config, error) {
	cfg := &Config{Format: ConfigFormat, Contexts: map[string]*Context{}}
	raw, err := s.readPrivate(configFileName, maxConfigBytes)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(cfg); err != nil || cfg.Format != ConfigFormat {
		return nil, failure("%s is not an %s file; move it away to start over", filepath.Join(s.dir, configFileName), ConfigFormat)
	}
	if cfg.Contexts == nil {
		cfg.Contexts = map[string]*Context{}
	}
	for name, c := range cfg.Contexts {
		if !contextNamePattern.MatchString(name) || c == nil {
			return nil, failure("%s holds an invalid context %q", filepath.Join(s.dir, configFileName), name)
		}
	}
	return cfg, nil
}

func (s store) save(cfg *Config) error {
	cfg.Format = ConfigFormat
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return s.writePrivate(configFileName, append(raw, '\n'))
}

// update applies fn to the configuration under the lock and saves it.
func (s store) update(fn func(*Config) error) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	cfg, err := s.load()
	if err != nil {
		return err
	}
	if err = fn(cfg); err != nil {
		return err
	}
	return s.save(cfg)
}

func contextNames(cfg *Config) []string {
	names := make([]string, 0, len(cfg.Contexts))
	for name := range cfg.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func validContextName(name string) error {
	if !contextNamePattern.MatchString(name) {
		return usageError("a context name is 1 to 64 letters, digits, '.', '_' or '-' (got %q)", strings.TrimSpace(name))
	}
	return nil
}
