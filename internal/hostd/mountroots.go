// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// DefaultMountRootsFile holds the host folders this host's operator allows
// launches to mount or snapshot. It belongs to the host, not to the service:
// only "agentgate-hostd install --mount-root" or "agentgate-hostd mount-roots"
// (or root editing it by hand) changes it, and nothing a job carries can. A
// missing file means no roots, so every host folder mount is refused.
const DefaultMountRootsFile = "/etc/agentgate/mount-roots.json"

// MountRootsVersion is the format of the mount roots file.
const MountRootsVersion = "agentgate.hostd-mount-roots.v1"

const maxMountRootsFileBytes = 128 << 10

type mountRootsDocument struct {
	Version string   `json:"version"`
	Roots   []string `json:"roots"`
}

// overlapsPath reports whether two canonical absolute paths are equal or one
// contains the other, component by component.
func overlapsPath(a, b string) bool {
	return a == b || a == "/" || b == "/" || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// underPath reports whether path is root or below it, component by component
// (so /srv/dataevil is not below /srv/data).
func underPath(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+"/")
}

// CheckLocalMountRoots validates an operator's roots: the protocol's rules
// (hostproto.CheckMountRoots: at most 16 unique canonical paths of safe
// characters, outside the protected system and runtime trees, credential
// stores and home directories) and no overlap with what this host agent keeps
// private (its state directory, which also holds the broker configurations,
// and the secret store).
func CheckLocalMountRoots(roots []string, private []string) error {
	if err := hostproto.CheckMountRoots(roots); err != nil {
		return fmt.Errorf("hostd: %s", strings.TrimPrefix(err.Error(), "hostproto: "))
	}
	for _, r := range roots {
		for _, p := range private {
			if p == "" {
				continue
			}
			if overlapsPath(r, filepath.Clean(p)) {
				return fmt.Errorf("hostd: mount root %s overlaps %s, which this host agent keeps private", r, filepath.Clean(p))
			}
		}
	}
	return nil
}

// checkOperatorDir requires a directory owned by this user (root), not
// writable by group or others, reached without a symbolic link.
func checkOperatorDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("hostd: %s must be a directory owned by uid %d that group and others cannot write", dir, os.Geteuid())
	}
	if resolved, err := filepath.EvalSymlinks(dir); err != nil || resolved != dir {
		return fmt.Errorf("hostd: %s must be reached without a symbolic link", dir)
	}
	return nil
}

// LoadMountRoots reads the operator's mount roots. A missing file is an empty
// list. The file must be a regular file owned by this user (root), not
// writable by group or others (0644 or 0600), in a directory with the same
// custody, with exactly {"version", "roots"}; anything else is an error, and
// every caller then refuses every host folder.
func LoadMountRoots(path string, private []string) ([]string, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("hostd: mount roots file %s: %w", path, err)
	}
	defer file.Close()
	if err = checkOperatorDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("hostd: %s must be a regular file owned by uid %d that group and others cannot write (mode 0644)", path, os.Geteuid())
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxMountRootsFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxMountRootsFileBytes {
		return nil, fmt.Errorf("hostd: %s exceeds %d bytes", path, maxMountRootsFileBytes)
	}
	var doc mountRootsDocument
	if err = hostproto.DecodeStrict(raw, &doc); err != nil {
		return nil, fmt.Errorf("hostd: %s: %s", path, strings.TrimPrefix(err.Error(), "hostproto: "))
	}
	if doc.Version != MountRootsVersion || doc.Roots == nil {
		return nil, fmt.Errorf(`hostd: %s must be {"version": %q, "roots": [...]}`, path, MountRootsVersion)
	}
	if err = CheckLocalMountRoots(doc.Roots, private); err != nil {
		return nil, fmt.Errorf("%w (in %s)", err, path)
	}
	return doc.Roots, nil
}

// WriteMountRoots validates roots and replaces the file atomically with mode
// 0644, creating its directory (mode 0755) when it is missing. An empty list
// refuses every host folder.
func WriteMountRoots(path string, roots []string, private []string) error {
	if roots == nil {
		roots = []string{}
	}
	if err := CheckLocalMountRoots(roots, private); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := checkOperatorDir(dir); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(mountRootsDocument{Version: MountRootsVersion, Roots: roots}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(raw, '\n'), 0o644)
}

// fileID is a directory's identity: two paths with the same identity are one
// directory, whichever bind mount or link reaches it.
type fileID struct{ dev, ino uint64 }

// mountFS is the filesystem view of the host folder checks; tests replace it.
type mountFS struct {
	// resolve returns the path with every symbolic link resolved.
	resolve func(string) (string, error)
	// mountPoints lists the mount points of this host's mount namespace.
	mountPoints func() ([]string, error)
	// identity reports a path's directory identity, and false when it is
	// absent or not a directory.
	identity func(string) (fileID, bool)
}

func systemMountFS() mountFS {
	return mountFS{resolve: filepath.EvalSymlinks, mountPoints: func() ([]string, error) {
		file, err := os.Open("/proc/self/mountinfo")
		if err != nil {
			return nil, err
		}
		defer file.Close()
		return parseMountPoints(file)
	}, identity: func(path string) (fileID, bool) {
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			return fileID{}, false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fileID{}, false
		}
		return fileID{dev: uint64(stat.Dev), ino: stat.Ino}, true
	}}
}

var mountinfoEscape = regexp.MustCompile(`\\([0-7]{3})`)

// parseMountPoints reads /proc/self/mountinfo: the fifth field of each line is
// a mount point, with space, tab, newline and backslash octal-escaped.
func parseMountPoints(r io.Reader) ([]string, error) {
	var out []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		point := mountinfoEscape.ReplaceAllStringFunc(fields[4], func(m string) string {
			v, _ := strconv.ParseUint(m[1:], 8, 8)
			return string(rune(v))
		})
		out = append(out, point)
	}
	return out, scanner.Err()
}

// checkHostFolder decides whether a launch or snapshot may use source on this
// host. It returns a reason code and the refusal. The source must be inside
// one of the operator's roots, component by component; the deepest such root
// and the source must resolve to themselves (no symbolic link anywhere on
// either path); no mount point may lie inside that root on the way to the
// source, at the source, or below it (a bind mount inside a root could bring
// any other tree in); and neither the source nor the root may be the same
// directory as a protected tree or a private path of this host agent.
func checkHostFolder(source string, roots, private []string, fsys mountFS, file string) (string, error) {
	if len(roots) == 0 {
		return "mount_root_not_allowed", fmt.Errorf("this host allows no host folder mounts: its operator lists no mount roots in %s (agentgate-hostd mount-roots --root PATH)", file)
	}
	if err := hostproto.CheckMountSource(source); err != nil {
		return "invalid_mount", errors.New(strings.TrimPrefix(err.Error(), "hostproto: "))
	}
	root := ""
	for _, r := range roots {
		if underPath(source, r) && len(r) > len(root) {
			root = r
		}
	}
	if root == "" {
		return "mount_root_not_allowed", fmt.Errorf("%s is not inside a host folder this host's operator allows (mount roots: %s)", source, strings.Join(roots, ", "))
	}
	if resolved, err := fsys.resolve(root); err != nil || resolved != root {
		return "invalid_mount", fmt.Errorf("mount root %s is missing or is reached through a symbolic link", root)
	}
	resolved, err := fsys.resolve(source)
	if err != nil {
		return "invalid_mount", fmt.Errorf("%s cannot be resolved: it must be an existing directory", source)
	}
	if resolved != source {
		return "invalid_mount", fmt.Errorf("%s leads through a symbolic link to %s; only a real path inside a mount root is mounted", source, resolved)
	}
	points, err := fsys.mountPoints()
	if err != nil {
		return "invalid_mount", fmt.Errorf("the mount table cannot be read, so %s is refused: %v", source, err)
	}
	for _, p := range points {
		if p != root && strings.HasPrefix(p, root+"/") && (underPath(source, p) || underPath(p, source)) {
			return "invalid_mount", fmt.Errorf("mount point %s lies inside mount root %s at, above or below %s; a mount inside a root is refused (list it as its own root)", p, root, source)
		}
	}
	id, ok := fsys.identity(source)
	if !ok {
		return "invalid_mount", fmt.Errorf("%s is not an existing directory", source)
	}
	rootID, _ := fsys.identity(root)
	for _, p := range append(append([]string{}, hostproto.ProtectedMountTrees...), private...) {
		if p == "" {
			continue
		}
		if pid, ok := fsys.identity(p); ok && (pid == id || pid == rootID) {
			return "invalid_mount", fmt.Errorf("%s or its mount root is the same directory as the protected %s", source, p)
		}
	}
	return "", nil
}

// privatePaths are what no mount root or host folder may overlap: the state
// directory (keys, outbox, ledger, broker configurations) and the secret store.
func (d *Daemon) privatePaths() []string {
	return []string{d.StateDir, d.Config.secretRoot()}
}

func (d *Daemon) mountRootsPath() string {
	if d.MountRootsFile == "" {
		return DefaultMountRootsFile
	}
	return d.MountRootsFile
}

// mountRoots loads the operator's roots; an unreadable or invalid file is
// logged once per distinct error and allows nothing.
func (d *Daemon) mountRoots() []string {
	roots, err := LoadMountRoots(d.mountRootsPath(), d.privatePaths())
	message := ""
	if err != nil {
		message = err.Error()
		roots = []string{}
	}
	d.mu.Lock()
	changed := message != d.rootsErr
	d.rootsErr = message
	d.mu.Unlock()
	if changed && message != "" {
		d.logf("mount roots refused, so every host folder mount is refused: %s", message)
	}
	return roots
}

// reportedMountRoots is the list the heartbeat carries: the roots this host
// enforces right now (empty when the file is missing or invalid).
func (d *Daemon) reportedMountRoots() []string {
	roots := d.mountRoots()
	if hostproto.CheckMountRoots(roots) != nil {
		return []string{}
	}
	return roots
}

// checkLaunchMounts applies the operator's roots to every host folder of a
// launch, or to a snapshot source. The service applies its own list too; this
// is the host's own decision, so a service that sends a folder outside the
// host's roots is refused whatever it signed.
func (d *Daemon) checkLaunchMounts(mounts []hostproto.LaunchMount) (string, error) {
	if len(mounts) == 0 {
		return "", nil
	}
	roots := d.mountRoots()
	for _, m := range mounts {
		if code, err := checkHostFolder(m.Source, roots, d.privatePaths(), d.mountFS, d.mountRootsPath()); err != nil {
			return code, fmt.Errorf("mount %s: %w", m.Name, err)
		}
	}
	return "", nil
}

// EnforceMountRoots stops every running launch that uses a host folder no
// longer inside the operator's roots (a root was removed, or the file became
// invalid). The kernel policy and the bind stay until the stop tears the
// launch down, which happens at the next poll after the edit.
func (d *Daemon) EnforceMountRoots(ctx context.Context) {
	d.mu.Lock()
	var candidates []*activeLaunch
	for _, launch := range d.active {
		if len(launch.mounts) > 0 && !launch.rootStopSent {
			candidates = append(candidates, launch)
		}
	}
	d.mu.Unlock()
	if len(candidates) == 0 {
		return
	}
	roots := d.mountRoots()
	for _, launch := range candidates {
		outside := ""
		for _, m := range launch.mounts {
			if !hostproto.MountUnderRoots(m.Source, roots) {
				outside = m.Source
				break
			}
		}
		if outside == "" {
			continue
		}
		d.mu.Lock()
		launch.rootStopSent = true
		d.mu.Unlock()
		d.logf("launch %s: %s is no longer inside a mount root; stopping it", launch.launchID, outside)
		d.progress(launch.jobID, "the host's operator removed the mount root of "+outside+"; the launch is stopped")
		if _, err := d.Runtime.Stop(ctx, launch.launchID, 0, "mount_root_removed"); err != nil {
			d.logf("launch %s: stop request failed, cancelling its runtime: %v", launch.launchID, err)
			launch.cancel()
		}
	}
}
