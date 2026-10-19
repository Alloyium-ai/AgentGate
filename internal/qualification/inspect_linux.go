// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualification

import (
	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/noderuntime"
	"alloyium.local/kernel-poc/internal/platform"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Measurement names only supported measurement operations. It cannot install a
// hook, launch a process, read a signer key, or assert a capability state.
type Measurement struct {
	Kind        string                `json:"kind"`
	Path        string                `json:"path,omitempty"`
	Files       []runtimeclosure.File `json:"files"`
	OwnedPrefix string                `json:"owned_prefix,omitempty"`
	RootReceipt string                `json:"root_receipt,omitempty"`
}
type LocalConfig struct {
	Expected      Binding                `json:"expected"`
	InventoryFile string                 `json:"inventory_file"`
	Measurements  map[string]Measurement `json:"measurements"`
}
type LocalInspector struct {
	config LocalConfig
	self   string
}
type SystemClock struct{}

func (SystemClock) Now() (time.Time, uint64, error) {
	var t, after unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &t); err != nil {
		return time.Time{}, 0, err
	}
	if t.Sec < 0 || uint64(t.Sec) > math.MaxUint64/uint64(time.Second) {
		return time.Time{}, 0, errors.New("negative monotonic clock")
	}
	wall := time.Now()
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &after); err != nil {
		return time.Time{}, 0, err
	}
	beforeNS := uint64(t.Sec)*uint64(time.Second) + uint64(t.Nsec)
	if after.Sec < 0 || uint64(after.Sec) > math.MaxUint64/uint64(time.Second) {
		return time.Time{}, 0, errors.New("monotonic clock overflow")
	}
	afterNS := uint64(after.Sec)*uint64(time.Second) + uint64(after.Nsec)
	if afterNS < beforeNS || afterNS-beforeNS > uint64(PairingBound) {
		return time.Time{}, 0, errors.New("qualification clock pairing exceeded its bound")
	}
	return wall, beforeNS, nil
}

func NewLocalInspector(c LocalConfig) (*LocalInspector, error) {
	if err := validBinding(c.Expected, false); err != nil {
		return nil, err
	}
	if c.Expected.PolicyDigest != "" || !protectedPath(c.InventoryFile) || len(c.Measurements) != len(c.Expected.ArtifactDigests) || len(c.Measurements) > 64 || c.Measurements["qualification"].Kind != "file" || c.Measurements["target-probe"].Kind != "file" || c.Measurements["domain-root"].Kind != "cgroup-root" {
		return nil, errors.New("qualification requires complete supported target measurements")
	}
	for name, m := range c.Measurements {
		if !hex64.MatchString(c.Expected.ArtifactDigests[name]) {
			return nil, errors.New("qualification measurement has no pinned artifact")
		}
		expectedKind := "file"
		if name == "domain-root" {
			expectedKind = "cgroup-root"
		}
		if strings.HasPrefix(name, "runtime.") && strings.HasSuffix(name, ".files") {
			expectedKind = "runtime-closure"
		}
		if strings.HasPrefix(name, "runtime.") && strings.HasSuffix(name, ".package") {
			expectedKind = "tree"
		}
		if name == "resolver" {
			expectedKind = "resolver"
		}
		if m.Kind != expectedKind {
			return nil, errors.New("qualification measurement kind differs from its artifact role")
		}
		switch m.Kind {
		case "file", "tree":
			if !protectedPath(m.Path) || m.Files != nil || m.OwnedPrefix != "" || m.RootReceipt != "" {
				return nil, errors.New("invalid file or tree measurement")
			}
		case "runtime-closure":
			if m.Path != "" || m.OwnedPrefix != "" || m.RootReceipt != "" {
				return nil, errors.New("invalid runtime closure measurement")
			}
			if _, err := runtimeclosure.New(m.Files); err != nil {
				return nil, err
			}
		case "cgroup-root":
			if m.Path != "" || m.Files != nil || !safeID.MatchString(m.OwnedPrefix) || !hex64.MatchString(m.RootReceipt) {
				return nil, errors.New("invalid root cgroup measurement")
			}
		case "resolver":
			if !protectedPath(m.Path) || m.Files != nil || m.OwnedPrefix != "" || m.RootReceipt != "" {
				return nil, errors.New("invalid pinned resolver measurement")
			}
		default:
			return nil, fmt.Errorf("unsupported qualification measurement: %s", m.Kind)
		}
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return &LocalInspector{owned(c), self}, nil
}

func protectedPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && path != "/tmp" && !strings.HasPrefix(path, "/tmp/") && !strings.ContainsAny(path, "\x00\r\n")
}
func protectedParents(path string) error {
	if !protectedPath(path) {
		return errors.New("a protected absolute path is required")
	}
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		var st unix.Stat_t
		if unix.Lstat(p, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 != 0 {
			return errors.New("qualification file parent custody differs")
		}
		if p == "/" {
			return nil
		}
	}
}

// ReadProtected reads bounded non-secret configuration or inventory bytes.
func ReadProtected(path string, limit int64) ([]byte, error) {
	if limit <= 0 || limit > 8<<20 {
		return nil, errors.New("qualification input bound is invalid")
	}
	if err := protectedParents(path); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var before, after, actual unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Uid != 0 || before.Nlink != 1 || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0022 != 0 || before.Size <= 0 || before.Size > limit {
		return nil, errors.New("qualification input custody or bound differs")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != before.Size || unix.Fstat(fd, &after) != nil || unix.Lstat(path, &actual) != nil || !sameInputStat(before, after) || !sameInputStat(before, actual) {
		return nil, errors.New("qualification input changed during readback")
	}
	// Metadata alone cannot detect every same-size write on a coarse filesystem.
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	again, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || !bytes.Equal(raw, again) || unix.Fstat(fd, &after) != nil || unix.Lstat(path, &actual) != nil || !sameInputStat(before, after) || !sameInputStat(before, actual) {
		return nil, errors.New("qualification input changed during final hash readback")
	}
	return raw, nil
}

func sameInputStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func hashKernel(ctx context.Context, path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 64<<10)
	var count int64
	for {
		if err = ctx.Err(); err != nil {
			return "", err
		}
		n, e := f.Read(buf)
		count += int64(n)
		if count > limit {
			return "", errors.New("kernel measurement exceeds the bound")
		}
		if n > 0 {
			_, _ = h.Write(buf[:n])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", e
		}
	}
	if count == 0 {
		return "", errors.New("kernel measurement is empty")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (i *LocalInspector) Snapshot(ctx context.Context) (Binding, error) {
	var zero Binding
	if ctx == nil || ctx.Err() != nil {
		return zero, errors.New("qualification measurement context is unavailable")
	}
	if os.Geteuid() != 0 || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return zero, errors.New("qualification requires the owned root Linux amd64 target")
	}
	b := owned(i.config.Expected)
	b.PolicyDigest = ""
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return zero, err
	}
	b.BootID = strings.TrimSpace(string(boot))
	var uname unix.Utsname
	if err = unix.Uname(&uname); err != nil {
		return zero, err
	}
	b.Kernel = unix.ByteSliceToString(uname.Release[:])
	b.Architecture = "x86_64"
	if b.BTFSHA256, err = hashKernel(ctx, "/sys/kernel/btf/vmlinux", 256<<20); err != nil {
		return zero, err
	}
	config, err := ReadProtected("/boot/config-"+b.Kernel, 2<<20)
	if err != nil {
		return zero, err
	}
	b.KernelConfigSHA256 = digestBytes(config)
	invRaw, err := ReadProtected(i.config.InventoryFile, 8<<20)
	if err != nil {
		return zero, err
	}
	var inventory platform.Inventory
	if err = lifecycle.DecodeTransport(bytes.NewReader(invRaw), &inventory); err != nil {
		return zero, err
	}
	lsm, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return zero, err
	}
	if inventory.SchemaVersion != platform.InventoryVersion || inventory.Boot != b.BootID || inventory.Kernel != b.Kernel || inventory.Architecture != b.Architecture || inventory.BTFDigest != b.BTFSHA256 || inventory.ConfigDigest != b.KernelConfigSHA256 || inventory.ProbeDigest != b.ArtifactDigests["target-probe"] || inventory.LSM != strings.TrimSpace(string(lsm)) || !strings.Contains(","+inventory.LSM+",", ",bpf,") {
		return zero, errors.New("the protected inventory differs from the actual target")
	}
	b.InventorySHA256 = digestBytes(invRaw)
	if err = i.measureArtifacts(ctx); err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(b, i.config.Expected) {
		return zero, errors.New("the actual target differs from the qualification request")
	}
	return b, nil
}

func (i *LocalInspector) measureArtifacts(ctx context.Context) error {
	names := make([]string, 0, len(i.config.Measurements))
	for name := range i.config.Measurements {
		names = append(names, name)
	}
	sort.Strings(names)
	files := map[string]runtimeclosure.File{}
	for _, name := range names {
		m := i.config.Measurements[name]
		expected := i.config.Expected.ArtifactDigests[name]
		switch m.Kind {
		case "resolver":
			config, err := noderuntime.ReadConfig(m.Path)
			if err != nil {
				return err
			}
			resolver, err := noderuntime.ConfiguredResolver(config)
			if err != nil || resolver == nil || noderuntime.ResolverDigest(resolver.Evidence()) != expected {
				return errors.New("the protected pinned resolver differs from the qualification artifact")
			}
		case "file":
			var st unix.Stat_t
			if unix.Lstat(m.Path, &st) != nil {
				return errors.New("a qualification artifact is absent")
			}
			file := runtimeclosure.File{Path: m.Path, SHA256: expected, Bytes: st.Size, Mode: st.Mode & 07777, GID: st.Gid}
			if prior, ok := files[m.Path]; ok && prior != file {
				return errors.New("one artifact path has conflicting measurements")
			}
			files[m.Path] = file
			if name == "qualification" {
				actual, e := os.Stat(i.self)
				pinned, e2 := os.Lstat(m.Path)
				if e != nil || e2 != nil || !os.SameFile(actual, pinned) {
					return errors.New("the running report producer differs from its artifact")
				}
			}
		case "tree":
			if err := jobartifacts.VerifyTree(ctx, m.Path, expected); err != nil {
				return err
			}
		case "runtime-closure":
			set, err := runtimeclosure.New(m.Files)
			if err != nil || set.Digest() != expected {
				return errors.New("runtime closure digest differs")
			}
			if _, err = set.Verify(ctx); err != nil {
				return err
			}
		case "cgroup-root":
			proof, err := domainstore.MeasureRoot(m.OwnedPrefix, m.RootReceipt)
			if err != nil || proof.Digest() != expected {
				return errors.New("the current root cgroup proof differs")
			}
		}
	}
	list := make([]runtimeclosure.File, 0, len(files))
	for _, f := range files {
		list = append(list, f)
	}
	set, err := runtimeclosure.New(list)
	if err != nil {
		return err
	}
	_, err = set.Verify(ctx)
	return err
}
