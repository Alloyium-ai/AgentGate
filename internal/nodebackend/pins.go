// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package nodebackend joins protected domains with the concrete kernel runtime.
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"errors"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
)

type componentPin struct{ name, counter string }

var resourcePins = []componentPin{{"files", "stats"}, {"peers", "net_stats"}, {"sockets", "sock_stats"}, {"custody", "cust_stats"}, {"process", "proc_stats"}}

// PinReader supplies actual pinned counters to either the node or its independent
// watchdog. It performs no map update and calls no Store method under its lock.
type PinReader struct {
	node  string
	proof domainstore.RootProof
}

func NewPinReader(node string, proof domainstore.RootProof) (*PinReader, error) {
	if node == "" {
		return nil, errors.New("the pinned counter reader requires a node identity")
	}
	if err := kernel.Preflight(); err != nil {
		return nil, err
	}
	actual, err := domainstore.MeasureRoot(proof.OwnedPrefix, proof.QualificationReceiptDigest)
	if err != nil {
		return nil, err
	}
	if actual != proof {
		return nil, errors.New("the pinned counter root proof differs")
	}
	return &PinReader{node: node, proof: proof}, nil
}
func (p *PinReader) name(b lifecycle.Binding, allocated bool) (string, error) {
	if p == nil || b.NodeID != p.node || b.BootID != p.proof.BootID || b.Validate(!allocated) != nil || (allocated && b.CgroupID == 0) {
		return "", errors.New("the pinned kernel binding differs")
	}
	return domainstore.ReservationName(p.proof.OwnedPrefix, b)
}
func (p *PinReader) root() error {
	actual, err := domainstore.MeasureRoot(p.proof.OwnedPrefix, p.proof.QualificationReceiptDigest)
	if err != nil {
		return err
	}
	if actual != p.proof {
		return errors.New("the pinned kernel root or boot changed")
	}
	var fs unix.Statfs_t
	if err = unix.Statfs("/sys/fs/bpf", &fs); err != nil {
		return err
	}
	if uint64(fs.Type) != uint64(unix.BPF_FS_MAGIC) {
		return errors.New("the pinned kernel filesystem differs")
	}
	return nil
}
func privatePinDirectory(path string) error {
	for _, p := range []string{"/sys/fs/bpf", path} {
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&022 != 0 {
			return errors.New("the kernel pin directory custody differs")
		}
	}
	return nil
}
func readCounter(path string) (kernel.Counters, error) {
	var zero kernel.Counters
	if err := privatePinDirectory(filepath.Dir(path)); err != nil {
		return zero, err
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return zero, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&022 != 0 {
		return zero, errors.New("the kernel counter pin custody differs")
	}
	m, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{Flags: unix.BPF_F_RDONLY})
	if err != nil {
		return zero, err
	}
	defer m.Close()
	info, err := m.Info()
	if err != nil {
		return zero, err
	}
	if info.Type != ebpf.Array || info.KeySize != 4 || info.ValueSize != 16 || info.MaxEntries != 1 {
		return zero, errors.New("the pinned counter ABI differs")
	}
	if err = m.Lookup(uint32(0), &zero); err != nil {
		return zero, err
	}
	return zero, nil
}
func (p *PinReader) ResourceCounters(ctx context.Context, b lifecycle.Binding) (map[string]kernel.Counters, error) {
	name, err := p.name(b, true)
	if err != nil {
		return nil, err
	}
	if err = p.root(); err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(domainstore.RootPath, name), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Ino != b.CgroupID {
		return nil, errors.New("the counter domain inode differs")
	}
	out := map[string]kernel.Counters{}
	for _, component := range resourcePins {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		value, e := readCounter(filepath.Join("/sys/fs/bpf", name+"-"+component.name, component.counter))
		if e != nil {
			return nil, e
		}
		out[component.name] = value
	}
	return out, nil
}
func (p *PinReader) ReadCounters(ctx context.Context, b lifecycle.Binding) (uint64, uint64, error) {
	values, err := p.ResourceCounters(ctx, b)
	if err != nil {
		return 0, 0, err
	}
	var records, lost uint64
	for _, value := range values {
		records += value.Decisions
		lost += value.Lost
	}
	observer, err := p.ObservationCounters(ctx, b)
	if err != nil {
		return records, lost, err
	}
	lost += observer.Lost
	return records, lost, nil
}
func (p *PinReader) ObservationCounters(ctx context.Context, b lifecycle.Binding) (kernel.Counters, error) {
	name, err := p.name(b, true)
	if err != nil {
		return kernel.Counters{}, err
	}
	if err = ctx.Err(); err != nil {
		return kernel.Counters{}, err
	}
	if err = p.root(); err != nil {
		return kernel.Counters{}, err
	}
	return readCounter(filepath.Join("/sys/fs/bpf", name+"-syscalls", "audit_stats"))
}

// cleanupPins follows authenticated whole-domain termination. It verifies the
// actual empty inode again and removes only the known component directories.
func (p *PinReader) cleanupPins(ctx context.Context, b lifecycle.Binding) error {
	name, err := p.name(b, true)
	if err != nil {
		return err
	}
	if err = p.root(); err != nil {
		return err
	}
	fd, err := unix.Open(filepath.Join(domainstore.RootPath, name), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Ino != b.CgroupID {
		return errors.New("the cleanup domain inode differs")
	}
	raw, err := readAt(fd, "cgroup.events")
	if err != nil {
		return err
	}
	if !strings.Contains(string(raw), "populated 0") {
		return errors.New("the cleanup domain remains populated")
	}
	components := append([]componentPin{}, resourcePins...)
	components = append(components, componentPin{"syscalls", "audit_stats"}, componentPin{"anonymous", "stats"})
	for _, component := range components {
		if err = ctx.Err(); err != nil {
			return err
		}
		dir := filepath.Join("/sys/fs/bpf", name+"-"+component.name)
		if _, err = os.Lstat(dir); os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if err = privatePinDirectory(dir); err != nil {
			return err
		}
		entries, e := os.ReadDir(dir)
		if e != nil {
			return e
		}
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			var pin unix.Stat_t
			if err = unix.Lstat(path, &pin); err != nil {
				return err
			}
			if pin.Mode&unix.S_IFMT != unix.S_IFREG || pin.Uid != 0 || pin.Mode&022 != 0 {
				return errors.New("the cleanup pin custody differs")
			}
			if err = os.Remove(path); err != nil {
				return err
			}
		}
		if err = os.Remove(dir); err != nil {
			return err
		}
	}
	return p.VerifyRemoved(ctx, b)
}
func (p *PinReader) VerifyRemoved(ctx context.Context, b lifecycle.Binding) error {
	name, err := p.name(b, false)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = p.root(); err != nil {
		return err
	}
	entries, err := os.ReadDir("/sys/fs/bpf")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == name || strings.HasPrefix(entry.Name(), name+"-") {
			return errors.New("owned kernel pins remain")
		}
	}
	return nil
}

var _ domainstore.CounterReader = (*PinReader)(nil)
var _ domainstore.RightsVerifier = (*PinReader)(nil)
