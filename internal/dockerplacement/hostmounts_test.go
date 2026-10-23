// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dockerplacement

import (
	"strings"
	"testing"
)

func mountedTarget() (Target, inspect) {
	target, docker := testTarget()
	target.HostMounts = []HostMount{
		{Path: HostMountRoot + "/repo", Source: "/srv/repo", ReadOnly: true},
		{Path: HostMountRoot + "/scratch", Source: "/srv/scratch", ReadOnly: false},
	}
	docker.Mounts = append(docker.Mounts,
		mount{Type: "bind", Source: "/srv/repo", Destination: HostMountRoot + "/repo", RW: false},
		mount{Type: "bind", Source: "/srv/scratch", Destination: HostMountRoot + "/scratch", RW: true})
	return target, docker
}

func TestHostMountsAreAbsentByDefault(t *testing.T) {
	target, docker := testTarget()
	if err := target.Validate(); err != nil {
		t.Fatal(err)
	}
	docker.Mounts = append(docker.Mounts, mount{Type: "bind", Source: "/srv/repo", Destination: HostMountRoot + "/repo"})
	if validateInspect(target, docker) == nil {
		t.Fatal("an unapproved host folder bind passed")
	}
}

func TestHostMountsMatchExactlyTheApprovedBinds(t *testing.T) {
	target, docker := mountedTarget()
	if err := target.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := validateInspect(target, docker); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*inspect){
		"read-only made writable": func(d *inspect) { d.Mounts[1].RW = true },
		"writable made read-only": func(d *inspect) { d.Mounts[2].RW = false },
		"other source":            func(d *inspect) { d.Mounts[1].Source = "/srv/other" },
		"other destination":       func(d *inspect) { d.Mounts[1].Destination = HostMountRoot + "/other" },
		"volume instead of bind":  func(d *inspect) { d.Mounts[1].Type = "volume" },
		"missing approved mount":  func(d *inspect) { d.Mounts = d.Mounts[:2] },
		"duplicate approved mount": func(d *inspect) {
			d.Mounts[2] = d.Mounts[1]
		},
		"extra host bind": func(d *inspect) {
			d.Mounts = append(d.Mounts, mount{Type: "bind", Source: "/srv/x", Destination: HostMountRoot + "/x"})
		},
		"docker socket": func(d *inspect) {
			d.Mounts = append(d.Mounts, mount{Type: "bind", Source: "/var/run/docker.sock", Destination: HostMountRoot + "/sock", RW: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := docker
			candidate.Mounts = append([]mount{}, docker.Mounts...)
			change(&candidate)
			if validateInspect(target, candidate) == nil {
				t.Fatal("an unapproved host folder mount passed")
			}
		})
	}
}

func TestHostMountValidationRefusesUnsafeShapes(t *testing.T) {
	for name, change := range map[string]func(*Target){
		"root source":           func(t *Target) { t.HostMounts[0].Source = "/" },
		"etc source":            func(t *Target) { t.HostMounts[0].Source = "/etc" },
		"below etc":             func(t *Target) { t.HostMounts[0].Source = "/etc/ssl" },
		"parent of docker data": func(t *Target) { t.HostMounts[0].Source = "/var/lib" },
		"docker data":           func(t *Target) { t.HostMounts[0].Source = "/var/lib/docker/volumes" },
		"var run":               func(t *Target) { t.HostMounts[0].Source = "/var/run" },
		"root home":             func(t *Target) { t.HostMounts[0].Source = "/root/project" },
		"proc":                  func(t *Target) { t.HostMounts[0].Source = "/proc/1" },
		"relative source":       func(t *Target) { t.HostMounts[0].Source = "srv/repo" },
		"unclean source":        func(t *Target) { t.HostMounts[0].Source = "/srv/../etc" },
		"workspace source":      func(t *Target) { t.HostMounts[0].Source = t.WorkspaceSource },
		"parent of workspace":   func(t *Target) { t.HostMounts[0].Source = "/var/lib/docker" },
		"socket directory":      func(t *Target) { t.HostMounts[0].Source = "/srv"; t.SocketPath = "/srv/docker.sock" },
		"overlapping sources":   func(t *Target) { t.HostMounts[1].Source = "/srv/repo/sub" },
		"same source twice":     func(t *Target) { t.HostMounts[1].Source = t.HostMounts[0].Source },
		"same path twice":       func(t *Target) { t.HostMounts[1].Path = t.HostMounts[0].Path },
		"outside mount root":    func(t *Target) { t.HostMounts[0].Path = "/usr/bin" },
		"nested mount path":     func(t *Target) { t.HostMounts[0].Path = HostMountRoot + "/repo/sub" },
		"mount root itself":     func(t *Target) { t.HostMounts[0].Path = HostMountRoot },
		"uppercase name":        func(t *Target) { t.HostMounts[0].Path = HostMountRoot + "/Repo" },
		"dot name":              func(t *Target) { t.HostMounts[0].Path = HostMountRoot + "/.." },
		"too many": func(t *Target) {
			for i := 0; i < MaxHostMounts; i++ {
				t.HostMounts = append(t.HostMounts, HostMount{Path: HostMountRoot + "/m" + strings.Repeat("x", i+1), Source: "/data/m" + strings.Repeat("x", i+1)})
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			target, _ := mountedTarget()
			target.HostMounts = append([]HostMount{}, target.HostMounts...)
			change(&target)
			if target.Validate() == nil {
				t.Fatal("an unsafe host folder mount passed validation")
			}
		})
	}
}

func TestMountinfoRequiresExactReadOnlyTopLevelMounts(t *testing.T) {
	approved := []HostMount{{Path: HostMountRoot + "/repo", ReadOnly: true}, {Path: HostMountRoot + "/my\\space", ReadOnly: false}}
	base := "36 35 98:0 / / ro,relatime master:1 - ext3 /dev/root rw\n" +
		"40 36 0:5 /srv/repo " + HostMountRoot + "/repo ro,nosuid shared:2 - ext4 /dev/sda1 rw\n" +
		"41 36 0:5 /srv/s " + HostMountRoot + "/my\\134space rw,nosuid - ext4 /dev/sda1 rw\n"
	entries, err := parseMountinfo([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if err = checkMountinfo(entries, approved); err != nil {
		t.Fatal(err)
	}
	writable := strings.Replace(base, HostMountRoot+"/repo ro,", HostMountRoot+"/repo rw,", 1)
	if entries, err = parseMountinfo([]byte(writable)); err != nil || checkMountinfo(entries, approved) == nil {
		t.Fatal("a writable kernel mount passed a read-only approval")
	}
	nested := base + "42 40 0:6 / " + HostMountRoot + "/repo/inner rw - tmpfs tmpfs rw\n"
	if entries, err = parseMountinfo([]byte(nested)); err != nil || checkMountinfo(entries, approved) == nil {
		t.Fatal("a further mount below a host folder passed")
	}
	redirected := strings.Replace(base, HostMountRoot+"/repo ro,", "/usr/repo ro,", 1)
	if entries, err = parseMountinfo([]byte(redirected)); err != nil || checkMountinfo(entries, approved) == nil {
		t.Fatal("a redirected mount passed")
	}
	if _, err = parseMountinfo([]byte("36 35 98:0 / /a\\13 rw - ext4 /dev/root rw\n")); err == nil {
		t.Fatal("a truncated escape was accepted")
	}
	if _, err = parseMountinfo([]byte("short line\n")); err == nil {
		t.Fatal("an incomplete record was accepted")
	}
}
