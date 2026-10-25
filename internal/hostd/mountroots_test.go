// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// realRoots builds a directory tree with a mount root, a sibling whose name
// extends the root's (prefix confusion) and an outside tree, and writes the
// operator's file listing only the root.
func realRoots(t *testing.T) (dir, root, file string) {
	t.Helper()
	dir = t.TempDir()
	root = filepath.Join(dir, "srv", "data")
	for _, p := range []string{filepath.Join(root, "repo", "sub"), filepath.Join(dir, "srv", "dataevil"), filepath.Join(dir, "outside")} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	file = filepath.Join(dir, "etc-agentgate", "mount-roots.json")
	if err := WriteMountRoots(file, []string{root}, nil); err != nil {
		t.Fatal(err)
	}
	return dir, root, file
}

func TestMountRootsFileCustodyAndShape(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "absent", "mount-roots.json")
	if roots, err := LoadMountRoots(missing, nil); err != nil || roots == nil || len(roots) != 0 {
		t.Fatalf("a missing file must be an empty list: %v %v", roots, err)
	}
	file := filepath.Join(dir, "etc", "mount-roots.json")
	if err := WriteMountRoots(file, []string{"/srv/data", "/opt/projects"}, nil); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(file); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v %v", info.Mode(), err)
	}
	if roots, err := LoadMountRoots(file, nil); err != nil || strings.Join(roots, ",") != "/srv/data,/opt/projects" {
		t.Fatalf("roots %v %v", roots, err)
	}
	write := func(body string, mode os.FileMode) string {
		path := filepath.Join(dir, "etc", "bad.json")
		_ = os.Remove(path)
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(path, mode)
		return path
	}
	good := `{"version":"agentgate.hostd-mount-roots.v1","roots":["/srv/data"]}`
	bad := map[string]string{
		"group writable":   write(good, 0o664),
		"world writable":   write(good, 0o646),
		"unknown field":    write(`{"version":"agentgate.hostd-mount-roots.v1","roots":[],"extra":1}`, 0o644),
		"duplicate key":    write(`{"version":"agentgate.hostd-mount-roots.v1","roots":[],"roots":["/srv/data"]}`, 0o644),
		"wrong version":    write(`{"version":"v0","roots":[]}`, 0o644),
		"null roots":       write(`{"version":"agentgate.hostd-mount-roots.v1","roots":null}`, 0o644),
		"trailing data":    write(good+`{}`, 0o644),
		"dot dot":          write(`{"version":"agentgate.hostd-mount-roots.v1","roots":["/srv/data/../../etc"]}`, 0o644),
		"relative":         write(`{"version":"agentgate.hostd-mount-roots.v1","roots":["srv/data"]}`, 0o644),
		"protected tree":   write(`{"version":"agentgate.hostd-mount-roots.v1","roots":["/var/lib/docker/volumes"]}`, 0o644),
		"contains /etc":    write(`{"version":"agentgate.hostd-mount-roots.v1","roots":["/"]}`, 0o644),
		"home directory":   write(`{"version":"agentgate.hostd-mount-roots.v1","roots":["/home/alice"]}`, 0o644),
		"credential store": write(`{"version":"agentgate.hostd-mount-roots.v1","roots":["/srv/x/.ssh"]}`, 0o644),
		"listed twice":     write(`{"version":"agentgate.hostd-mount-roots.v1","roots":["/srv/a","/srv/a"]}`, 0o644),
	}
	for name, path := range bad {
		if roots, err := LoadMountRoots(path, nil); err == nil {
			t.Errorf("%s accepted: %v", name, roots)
		}
	}
	// A symbolic link to a valid file is refused (O_NOFOLLOW).
	link := filepath.Join(dir, "etc", "link.json")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMountRoots(link, nil); err == nil {
		t.Fatal("a symlinked roots file was accepted")
	}
	// A directory others can write is refused, even with a good file in it.
	loose := filepath.Join(dir, "loose")
	_ = os.MkdirAll(loose, 0o755)
	_ = os.Chmod(loose, 0o777)
	if err := os.WriteFile(filepath.Join(loose, "mount-roots.json"), []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMountRoots(filepath.Join(loose, "mount-roots.json"), nil); err == nil {
		t.Fatal("a roots file in a world-writable directory was accepted")
	}
	// Roots may not overlap what the host agent keeps private.
	private := []string{"/srv/hostd-state", "/srv/secrets"}
	for _, root := range []string{"/srv", "/srv/hostd-state", "/srv/hostd-state/brokers", "/srv/secrets/local"} {
		if err := WriteMountRoots(file, []string{root}, private); err == nil {
			t.Errorf("root %s overlapping a private path was written", root)
		}
	}
	if roots, _ := LoadMountRoots(file, nil); strings.Join(roots, ",") != "/srv/data,/opt/projects" {
		t.Fatalf("a refused write changed the file: %v", roots)
	}
	if err := os.WriteFile(file, []byte(`{"version":"agentgate.hostd-mount-roots.v1","roots":["/srv/hostd-state"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMountRoots(file, private); err == nil {
		t.Fatal("a hand-edited root over the state directory was accepted")
	}
}

func TestHostFolderChecksOnARealTree(t *testing.T) {
	dir, root, file := realRoots(t)
	roots, err := LoadMountRoots(file, nil)
	if err != nil {
		t.Fatal(err)
	}
	fsys := systemMountFS()
	fsys.mountPoints = func() ([]string, error) { return []string{"/", "/proc", dir}, nil }
	check := func(source string) string {
		code, err := checkHostFolder(source, roots, nil, fsys, file)
		if err != nil {
			return code + ": " + err.Error()
		}
		return ""
	}
	for _, ok := range []string{root, filepath.Join(root, "repo"), filepath.Join(root, "repo", "sub")} {
		if got := check(ok); got != "" {
			t.Fatalf("%s refused: %s", ok, got)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "outside"), filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(root, "repo", "etc")); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct{ source, code string }{
		"prefix confusion":     {filepath.Join(dir, "srv", "dataevil"), "mount_root_not_allowed"},
		"outside":              {filepath.Join(dir, "outside"), "mount_root_not_allowed"},
		"parent of the root":   {filepath.Join(dir, "srv"), "mount_root_not_allowed"},
		"dot dot":              {root + "/../dataevil", "invalid_mount"},
		"dot dot inside":       {root + "/repo/../../dataevil", "invalid_mount"},
		"symlink escape":       {filepath.Join(root, "escape"), "invalid_mount"},
		"symlink below escape": {filepath.Join(root, "repo", "etc"), "invalid_mount"},
		"missing":              {filepath.Join(root, "absent"), "invalid_mount"},
		"trailing slash":       {root + "/repo/", "invalid_mount"},
	}
	for name, c := range cases {
		if got := check(c.source); !strings.HasPrefix(got, c.code+":") {
			t.Errorf("%s (%s): %q, want %s", name, c.source, got, c.code)
		}
	}
	// A root that is itself reached through a symbolic link is refused.
	linked := filepath.Join(dir, "linked-root")
	if err := os.Symlink(root, linked); err != nil {
		t.Fatal(err)
	}
	if code, err := checkHostFolder(filepath.Join(linked, "repo"), []string{linked}, nil, fsys, file); err == nil || code != "invalid_mount" {
		t.Fatalf("a symlinked root: %s %v", code, err)
	}
	// The empty default refuses everything, naming the file to edit.
	if code, err := checkHostFolder(filepath.Join(root, "repo"), []string{}, nil, fsys, file); err == nil || code != "mount_root_not_allowed" || !strings.Contains(err.Error(), file) {
		t.Fatalf("empty roots: %s %v", code, err)
	}
}

func TestBindMountsInsideARootAreRefused(t *testing.T) {
	dir, root, file := realRoots(t)
	source := filepath.Join(root, "repo")
	cases := map[string]struct {
		points []string
		ok     bool
	}{
		"root is its own mount":       {[]string{"/", root}, true},
		"mount above the root":        {[]string{"/", filepath.Dir(root)}, true},
		"sibling mount":               {[]string{"/", filepath.Join(root, "other")}, true},
		"source is a bind mount":      {[]string{"/", source}, false},
		"bind between root and src":   {[]string{"/", filepath.Join(root, "repo")}, false},
		"submount below the source":   {[]string{"/", filepath.Join(source, "sub")}, false},
		"deep bind above the source":  {[]string{filepath.Join(root, "repo")}, false},
		"mount at the prefix sibling": {[]string{filepath.Join(dir, "srv", "dataevil")}, true},
	}
	for name, c := range cases {
		fsys := systemMountFS()
		points := c.points
		fsys.mountPoints = func() ([]string, error) { return points, nil }
		code, err := checkHostFolder(filepath.Join(source, "sub"), []string{root}, nil, fsys, file)
		if c.ok && err != nil || !c.ok && (err == nil || code != "invalid_mount") {
			t.Errorf("%s: %s %v", name, code, err)
		}
	}
	// An unreadable mount table refuses (fail closed).
	fsys := systemMountFS()
	fsys.mountPoints = func() ([]string, error) { return nil, os.ErrPermission }
	if _, err := checkHostFolder(source, []string{root}, nil, fsys, file); err == nil {
		t.Fatal("an unreadable mount table allowed a mount")
	}
	// A root or source that is the same directory as a protected tree or a
	// private path (a bind of /etc, say) is refused by identity.
	for _, same := range []string{"/etc", "/var/lib/docker"} {
		fsys = systemMountFS()
		fsys.mountPoints = func() ([]string, error) { return nil, nil }
		real := fsys.identity
		target := same
		fsys.identity = func(p string) (fileID, bool) {
			if p == target {
				return real(root)
			}
			return real(p)
		}
		if code, err := checkHostFolder(source, []string{root}, nil, fsys, file); err == nil || code != "invalid_mount" {
			t.Errorf("root bound to %s: %s %v", same, code, err)
		}
	}
	fsys = systemMountFS()
	fsys.mountPoints = func() ([]string, error) { return nil, nil }
	private := filepath.Join(dir, "state")
	_ = os.MkdirAll(private, 0o700)
	real := fsys.identity
	fsys.identity = func(p string) (fileID, bool) {
		if p == private {
			return real(source)
		}
		return real(p)
	}
	if code, err := checkHostFolder(source, []string{root}, []string{private}, fsys, file); err == nil || code != "invalid_mount" {
		t.Fatalf("source bound to the state directory: %s %v", code, err)
	}
}

func TestParseMountPointsUnescapes(t *testing.T) {
	info := "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n" +
		"40 22 8:1 /srv/x /srv/my\\040data rw - ext4 /dev/sda1 rw\n" +
		"41 22 0:5 / /srv/tab\\011dir rw - tmpfs tmpfs rw\n" +
		"short line\n"
	points, err := parseMountPoints(strings.NewReader(info))
	if err != nil || strings.Join(points, "|") != "/|/srv/my data|/srv/tab\tdir" {
		t.Fatalf("points %q %v", points, err)
	}
}

func TestLaunchesAndSnapshotsOutsideTheHostRootsAreRefused(t *testing.T) {
	h := newHarness(t)
	if err := WriteMountRoots(h.daemon.MountRootsFile, []string{"/srv/data"}, h.daemon.privatePaths()); err != nil {
		t.Fatal(err)
	}
	mount := func(source, mode string) []hostproto.LaunchMount {
		return []hostproto.LaunchMount{{Name: "repo", Source: source, Mode: mode, Path: hostproto.MountRoot + "/repo"}}
	}
	sources := []string{"/srv/dataevil", "/srv/other/app", "/srv"}
	var jobs []hostproto.Job
	for i, source := range sources {
		job := h.launchJob(specBytes("oneshot", 30, "{}"), mount(source, "read-only"), nil)
		job.LaunchID = strings.Repeat(string("abc"[i]), 32)
		jobs = append(jobs, job)
		h.service.send(t, job)
	}
	snapshot := h.boundJob(hostproto.JobSnapshotMount, hostproto.SnapshotMountPayload{Name: "docs", Source: "/srv/dataevil/docs", MaxBytes: 1 << 20, MaxEntries: 100})
	snapshot.SpecDigest, snapshot.PolicyDigest = "", ""
	h.service.send(t, snapshot)
	h.cycle()
	if h.runtime.called("run") != 0 || h.runtime.called("snapshot") != 0 {
		t.Fatalf("a host folder outside the roots was used: %v", h.runtime.calls)
	}
	for i, job := range jobs {
		r := h.service.results(job.ID)
		if len(r) != 1 || r[0].Status != hostproto.ResultRejected || r[0].Reason != "mount_root_not_allowed" || r[0].EvidenceMissing != "not_started" {
			t.Errorf("%s: %+v", sources[i], r)
		}
	}
	if r := h.service.results(snapshot.ID); len(r) != 1 || r[0].Status != hostproto.ResultRejected || r[0].Reason != "mount_root_not_allowed" {
		t.Fatalf("snapshot %+v", r)
	}
	// Inside the root both run.
	h.scripted("stopped", "exited", true)
	inside := h.launchJob(specBytes("oneshot", 30, "{}"), mount("/srv/data/app", "read-only"), nil)
	inside.LaunchID = strings.Repeat("d", 32)
	h.service.send(t, inside)
	ok := h.boundJob(hostproto.JobSnapshotMount, hostproto.SnapshotMountPayload{Name: "docs", Source: "/srv/data/docs", MaxBytes: 1 << 20, MaxEntries: 100})
	ok.SpecDigest, ok.PolicyDigest = "", ""
	h.service.send(t, ok)
	h.cycle()
	if h.runtime.called("run") != 1 || h.runtime.called("snapshot docs /srv/data/docs") != 1 {
		t.Fatalf("a host folder inside the roots was refused: %v %+v", h.runtime.calls, h.service.results(inside.ID))
	}
	// The heartbeat reports exactly the roots the host enforces.
	poll := h.service.polls[len(h.service.polls)-1]
	if poll.Heartbeat.MountRoots == nil || strings.Join(*poll.Heartbeat.MountRoots, ",") != "/srv/data" {
		t.Fatalf("heartbeat mount roots %v", poll.Heartbeat.MountRoots)
	}
}

func TestNoRootsFileRefusesEveryHostFolder(t *testing.T) {
	h := newHarness(t)
	if err := os.Remove(h.daemon.MountRootsFile); err != nil {
		t.Fatal(err)
	}
	job := h.launchJob(specBytes("oneshot", 30, "{}"), []hostproto.LaunchMount{{Name: "repo", Source: "/srv/repos/app", Mode: "read-only", Path: hostproto.MountRoot + "/repo"}}, nil)
	h.service.send(t, job)
	h.cycle()
	if h.runtime.called("run") != 0 {
		t.Fatal("a launch with a host folder ran on a host without mount roots")
	}
	if r := h.service.results(job.ID); len(r) != 1 || r[0].Reason != "mount_root_not_allowed" {
		t.Fatalf("result %+v", r)
	}
	if roots := h.service.polls[len(h.service.polls)-1].Heartbeat.MountRoots; roots == nil || len(*roots) != 0 {
		t.Fatalf("heartbeat must report an explicit empty list: %v", roots)
	}
	// A launch without host folders still runs.
	h.scripted("stopped", "exited", true)
	plain := h.launchJob(specBytes("oneshot", 30, "{}"), nil, nil)
	plain.LaunchID = strings.Repeat("e", 32)
	h.service.send(t, plain)
	h.cycle()
	if h.runtime.called("run") != 1 {
		t.Fatal("a launch without host folders was refused")
	}
	// An invalid file is the same as none.
	if err := os.WriteFile(h.daemon.MountRootsFile, []byte(`{"version":"agentgate.hostd-mount-roots.v1","roots":["/etc"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	again := h.launchJob(specBytes("oneshot", 30, "{}"), []hostproto.LaunchMount{{Name: "repo", Source: "/srv/repos/app", Mode: "read-only", Path: hostproto.MountRoot + "/repo"}}, nil)
	again.LaunchID = strings.Repeat("f", 32)
	h.service.send(t, again)
	h.cycle()
	if r := h.service.results(again.ID); len(r) != 1 || r[0].Reason != "mount_root_not_allowed" {
		t.Fatalf("an invalid roots file allowed a mount: %+v", r)
	}
}

func TestRemovingARootStopsTheLaunchThatUsesIt(t *testing.T) {
	h := newHarness(t)
	release := make(chan struct{})
	h.runtime.lines = func(job launcherJob, emit func(LauncherEvent), _ context.Context) {
		emit(LauncherEvent{Event: "state", State: "running"})
		<-release
		zero := 0
		emit(LauncherEvent{Event: "receipt", Receipt: launcherReceiptFor(job, "failed", "mount_root_removed", true, &zero)})
	}
	job := h.launchJob(specBytes("session", 3600, "{}"), []hostproto.LaunchMount{{Name: "repo", Source: "/srv/repos/app", Mode: "read-only", Path: hostproto.MountRoot + "/repo"}}, nil)
	h.service.send(t, job)
	_ = h.daemon.PollOnce(context.Background())
	<-h.runtime.runStarted
	// Unchanged roots, or a root edit that still covers the folder: nothing stops.
	h.daemon.EnforceMountRoots(context.Background())
	if err := WriteMountRoots(h.daemon.MountRootsFile, []string{"/srv/repos", "/opt/data"}, h.daemon.privatePaths()); err != nil {
		t.Fatal(err)
	}
	h.daemon.EnforceMountRoots(context.Background())
	if h.runtime.called("stop") != 0 {
		t.Fatalf("a covered launch was stopped: %v", h.runtime.calls)
	}
	// The operator removes the root: the launch is stopped once.
	if err := WriteMountRoots(h.daemon.MountRootsFile, []string{"/opt/data"}, h.daemon.privatePaths()); err != nil {
		t.Fatal(err)
	}
	h.daemon.EnforceMountRoots(context.Background())
	h.daemon.EnforceMountRoots(context.Background())
	if h.runtime.called("stop "+testLaunch+" 0 mount_root_removed") != 1 {
		t.Fatalf("calls %v", h.runtime.calls)
	}
	close(release)
	h.daemon.Wait()
	_ = h.daemon.FlushOutbox(context.Background())
	if r := h.service.results(job.ID); len(r) != 1 || r[0].Status != hostproto.ResultFailed || r[0].Reason != "mount_root_removed" {
		t.Fatalf("result %+v", r)
	}
}

func TestLaunchesWithoutMountsIgnoreRootEdits(t *testing.T) {
	h := newHarness(t)
	release := make(chan struct{})
	h.runtime.lines = func(job launcherJob, emit func(LauncherEvent), _ context.Context) {
		<-release
		zero := 0
		emit(LauncherEvent{Event: "receipt", Receipt: launcherReceiptFor(job, "stopped", "exited", true, &zero)})
	}
	job := h.launchJob(specBytes("session", 3600, "{}"), nil, nil)
	h.service.send(t, job)
	_ = h.daemon.PollOnce(context.Background())
	<-h.runtime.runStarted
	_ = os.Remove(h.daemon.MountRootsFile)
	h.daemon.EnforceMountRoots(context.Background())
	if h.runtime.called("stop") != 0 {
		t.Fatal("a launch without host folders was stopped by a root edit")
	}
	close(release)
	h.daemon.Wait()
}

// TestMountRootsMatchThePythonRuntime proves launch.py and mounts.py read
// the operator's file exactly as agentgate-hostd does and refuse the same
// trees: the same list of protected trees, and the same refusals.
func TestMountRootsMatchThePythonRuntime(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable; the cross-language check did not run")
	}
	dir, root, file := realRoots(t)
	script := `import json, os, sys
sys.path.insert(0, sys.argv[1])
import mounts
out = {'protected': list(mounts.LAUNCH_PROTECTED), 'secrets': list(mounts.LAUNCH_SECRET_COMPONENTS)}
try:
    out['roots'] = mounts.load_host_roots(sys.argv[2], owner=os.geteuid())
except mounts.MountError as error:
    out['error'] = str(error)
results = {}
for source in sys.argv[3:]:
    try:
        mounts.check_host_roots(source, out.get('roots') or [], mountinfo=os.devnull)
        results[source] = 'ok'
    except mounts.MountError as error:
        results[source] = 'refused'
out['results'] = results
print(json.dumps(out))`
	sources := []string{root, filepath.Join(root, "repo", "sub"), filepath.Join(dir, "srv", "dataevil"), root + "/../dataevil", filepath.Join(root, "absent")}
	if err := os.Symlink(filepath.Join(dir, "outside"), filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	sources = append(sources, filepath.Join(root, "escape"))
	run := func(path string) map[string]any {
		cmd := exec.Command(python, append([]string{"-I", "-c", script, "../../poc/ssh-diagnostic", path}, sources...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("python: %v %s", err, out)
		}
		var v map[string]any
		if err := json.Unmarshal(out, &v); err != nil {
			t.Fatalf("python output %s", out)
		}
		return v
	}
	view := run(file)
	protected, _ := json.Marshal(view["protected"])
	want, _ := json.Marshal(hostproto.ProtectedMountTrees)
	if !bytes.Equal(protected, want) {
		t.Fatalf("mounts.LAUNCH_PROTECTED %s differs from hostproto.ProtectedMountTrees %s", protected, want)
	}
	secrets, _ := json.Marshal(view["secrets"])
	if want, _ := json.Marshal(hostproto.SecretComponents()); !bytes.Equal(secrets, want) {
		t.Fatalf("mounts.LAUNCH_SECRET_COMPONENTS %s differs from hostproto's %s", secrets, want)
	}
	roots, _ := json.Marshal(view["roots"])
	if string(roots) != `["`+root+`"]` {
		t.Fatalf("python roots %s (error %v)", roots, view["error"])
	}
	goRoots, _ := LoadMountRoots(file, nil)
	fsys := systemMountFS()
	fsys.mountPoints = func() ([]string, error) { return nil, nil }
	results := view["results"].(map[string]any)
	for _, source := range sources {
		_, goErr := checkHostFolder(source, goRoots, nil, fsys, file)
		goView := "ok"
		if goErr != nil {
			goView = "refused"
		}
		if results[source] != goView {
			t.Errorf("%s: python %v, go %s (%v)", source, results[source], goView, goErr)
		}
	}
	// Python refuses the same malformed files.
	for _, body := range []string{`{"version":"agentgate.hostd-mount-roots.v1","roots":["/etc"]}`, `{"version":"agentgate.hostd-mount-roots.v1","roots":["/srv/a/.local/b"]}`,
		`{"version":"agentgate.hostd-mount-roots.v1","roots":["/var/lib/agentgate-hostd/x"]}`, `{"version":"agentgate.hostd-mount-roots.v1","roots":["/home/alice"]}`, `{"version":"agentgate.hostd-mount-roots.v1","roots":[],"x":1}`,
		`{"version":"agentgate.hostd-mount-roots.v1","roots":["/srv/a"],"roots":[]}`, `{"version":"x","roots":[]}`} {
		bad := filepath.Join(filepath.Dir(file), "bad.json")
		if err := os.WriteFile(bad, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, goErr := LoadMountRoots(bad, nil); goErr == nil {
			t.Fatalf("go accepted %s", body)
		}
		if v := run(bad); v["error"] == nil {
			t.Fatalf("python accepted %s", body)
		}
	}
}
