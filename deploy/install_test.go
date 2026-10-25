// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Package deploy holds the release install script; this test runs it.
package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The tests run install.sh with --root, so it writes only below a temporary
// directory and never creates users or calls systemctl. The release files
// are small stand-ins with real checksums.

var releaseFiles = []string{"agentgate", "agentgate-hostd", "agentgate-broker", "community", "agentgate-broker@.service"}

func release(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "release")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	sums := ""
	for _, name := range releaseFiles {
		body := "#!/bin/sh\nexit 0\n# " + name + "\n"
		if strings.HasSuffix(name, ".service") {
			body = "[Unit]\nDescription=test\n"
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(body))
		sums += hex.EncodeToString(sum[:]) + "  " + name + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func install(t *testing.T, args ...string) (string, int) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	cmd := exec.Command("bash", append([]string{"install.sh"}, args...)...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	out, err := cmd.CombinedOutput()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

func digest(t *testing.T, path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func TestInstallVerifiesInstallsAndIsIdempotent(t *testing.T) {
	from := release(t)
	root := filepath.Join(t.TempDir(), "root")
	pin := digest(t, filepath.Join(from, "SHA256SUMS"))
	out, code := install(t, "--from", from, "--root", root, "--sha256sums", pin)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	want := map[string]os.FileMode{
		"usr/local/bin/agentgate":                      0o755,
		"usr/local/sbin/agentgate-hostd":               0o755,
		"usr/local/libexec/agentgate/agentgate-broker": 0o755,
		"usr/local/libexec/agentgate/community":        0o755,
		"etc/systemd/system/agentgate-broker@.service": 0o644,
		"etc/agentgate":                                0o755 | os.ModeDir,
		"etc/agentgate/broker":                         0o700 | os.ModeDir,
		"var/lib/agentgate":                            0o755 | os.ModeDir,
		"var/lib/agentgate/secrets":                    0o700 | os.ModeDir,
		"var/lib/agentgate/broker":                     0o711 | os.ModeDir,
	}
	for path, mode := range want {
		info, err := os.Lstat(filepath.Join(root, path))
		if err != nil || info.Mode() != mode {
			t.Errorf("%s: %v %v, want %v", path, info.Mode(), err, mode)
		}
	}
	if digest(t, filepath.Join(root, "usr/local/sbin/agentgate-hostd")) != digest(t, filepath.Join(from, "agentgate-hostd")) {
		t.Fatal("the installed host agent differs from the release")
	}
	for _, line := range []string{"every file matches SHA256SUMS", "SHA256SUMS digest " + pin,
		"would run: useradd --system --uid 10002 --gid agentgate-broker", "would run: systemctl daemon-reload", "agentgate doctor --target NAME"} {
		if !strings.Contains(out, line) {
			t.Errorf("output lacks %q:\n%s", line, out)
		}
	}
	// A second run changes nothing.
	out, code = install(t, "--from", from, "--root", root)
	if code != 0 || strings.Contains(out, "installed /") || strings.Contains(out, "created ") || strings.Contains(out, "daemon-reload") ||
		strings.Count(out, "unchanged /") != len(releaseFiles) {
		t.Fatalf("the second run changed something (exit %d):\n%s", code, out)
	}
	// A changed mode is put back.
	os.Chmod(filepath.Join(root, "etc/agentgate/broker"), 0o755)
	out, code = install(t, "--from", from, "--root", root)
	if code != 0 || !strings.Contains(out, "set "+root+"/etc/agentgate/broker to 0700") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	// A new release replaces exactly the changed file.
	newer := release(t)
	os.WriteFile(filepath.Join(newer, "agentgate"), []byte("#!/bin/sh\nexit 0\n# newer\n"), 0o755)
	sum := sha256.Sum256([]byte("#!/bin/sh\nexit 0\n# newer\n"))
	sums, _ := os.ReadFile(filepath.Join(newer, "SHA256SUMS"))
	lines := strings.Split(string(sums), "\n")
	lines[0] = hex.EncodeToString(sum[:]) + "  agentgate"
	os.WriteFile(filepath.Join(newer, "SHA256SUMS"), []byte(strings.Join(lines, "\n")), 0o644)
	out, code = install(t, "--from", newer, "--root", root)
	if code != 0 || strings.Count(out, "installed /") != 1 || !strings.Contains(out, "installed /usr/local/bin/agentgate (0755)") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestInstallRefusesBeforeChangingAnything(t *testing.T) {
	cases := map[string]func(t *testing.T, from, root string) []string{
		"tampered binary": func(t *testing.T, from, root string) []string {
			os.WriteFile(filepath.Join(from, "agentgate-broker"), []byte("#!/bin/sh\nexit 0\n# swapped\n"), 0o755)
			return []string{"a file does not match SHA256SUMS"}
		},
		"pinned sums differ": func(t *testing.T, from, root string) []string {
			return []string{"--sha256sums", strings.Repeat("0", 64), "not the pinned"}
		},
		"unlisted file": func(t *testing.T, from, root string) []string {
			sums, _ := os.ReadFile(filepath.Join(from, "SHA256SUMS"))
			lines := strings.Split(strings.TrimSpace(string(sums)), "\n")
			os.WriteFile(filepath.Join(from, "SHA256SUMS"), []byte(strings.Join(lines[1:], "\n")+"\n"), 0o644)
			return []string{"does not list every file"}
		},
		"unexpected file": func(t *testing.T, from, root string) []string {
			f, _ := os.OpenFile(filepath.Join(from, "SHA256SUMS"), os.O_APPEND|os.O_WRONLY, 0)
			f.WriteString(strings.Repeat("a", 64) + "  evil\n")
			f.Close()
			return []string{"unexpected file: evil"}
		},
		"malformed sums": func(t *testing.T, from, root string) []string {
			f, _ := os.OpenFile(filepath.Join(from, "SHA256SUMS"), os.O_APPEND|os.O_WRONLY, 0)
			f.WriteString("not a checksum line\n")
			f.Close()
			return []string{"malformed line"}
		},
		"symlinked release file": func(t *testing.T, from, root string) []string {
			os.Rename(filepath.Join(from, "community"), filepath.Join(from, "community.real"))
			os.Symlink(filepath.Join(from, "community.real"), filepath.Join(from, "community"))
			return []string{"community is missing or not a regular file"}
		},
		"missing release file": func(t *testing.T, from, root string) []string {
			os.Remove(filepath.Join(from, "agentgate-hostd"))
			return []string{"agentgate-hostd is missing"}
		},
		"symlinked destination": func(t *testing.T, from, root string) []string {
			os.MkdirAll(filepath.Join(root, "usr/local/bin"), 0o755)
			os.Symlink("/bin/true", filepath.Join(root, "usr/local/bin/agentgate"))
			return []string{"usr/local/bin/agentgate is a symlink"}
		},
		"writable destination directory": func(t *testing.T, from, root string) []string {
			os.MkdirAll(filepath.Join(root, "usr/local/libexec"), 0o755)
			os.Chmod(filepath.Join(root, "usr/local/libexec"), 0o777)
			return []string{"usr/local/libexec is writable by group or others"}
		},
		"relative root": func(t *testing.T, from, root string) []string {
			return []string{"--root", "relative/dir", "--root must be an absolute path"}
		},
		"dot segment root": func(t *testing.T, from, root string) []string {
			return []string{"--root", root + "/../x", "must not contain . or .. segments"}
		},
		"privileged broker uid": func(t *testing.T, from, root string) []string {
			return []string{"--broker-uid", "0", "unprivileged id"}
		},
	}
	for name, prepare := range cases {
		t.Run(name, func(t *testing.T) {
			from := release(t)
			root := filepath.Join(t.TempDir(), "root")
			extra := prepare(t, from, root)
			message := extra[len(extra)-1]
			args := append([]string{"--from", from, "--root", root}, extra[:len(extra)-1]...)
			out, code := install(t, args...)
			if code == 0 || !strings.Contains(out, message) {
				t.Fatalf("exit %d, want a refusal with %q:\n%s", code, message, out)
			}
			if strings.Contains(out, "installed /") || strings.Contains(out, "created ") {
				t.Fatalf("it changed something before refusing:\n%s", out)
			}
			for _, path := range []string{"usr/local/sbin/agentgate-hostd", "etc/agentgate"} {
				if _, err := os.Stat(filepath.Join(root, path)); err == nil {
					t.Fatalf("%s exists after a refusal", path)
				}
			}
		})
	}
}
