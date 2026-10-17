// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package kernel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const PathSize = 160

type Policy struct {
	Generation  uint64
	ExpiresNS   uint64
	AllowedIP   uint32
	AllowedPort uint32
	Workspace   [PathSize]byte
}

type Counters struct{ Decisions, Lost uint64 }

type Event struct {
	Sequence, Generation, Cgroup, MonoNS uint64
	PID, UID, Hook, Allowed, IP, Port    uint32
	Path                                 [PathSize]byte
}

type Runtime struct {
	Collection   *ebpf.Collection
	Links        []link.Link
	Reader       *ringbuf.Reader
	Domain       string
	ID           uint64
	Pins         string
	policyMu     sync.Mutex
	statsMap     string
	sharedDomain bool
	hooks        []string
}

func Preflight() error {
	marker, err := os.ReadFile("/etc/alloyium-disposable-vm")
	if err != nil || !strings.HasPrefix(string(marker), "kernel-poc-") {
		return errors.New("refuse kernel load: disposable VM marker absent")
	}
	vendor, err := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	if err != nil || !strings.Contains(string(vendor), "QEMU") {
		return errors.New("refuse kernel load: QEMU VM required")
	}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return err
	}
	release := strings.TrimRight(string(uts.Release[:]), "\x00")
	if release != "6.8.0-142-generic" {
		return fmt.Errorf("unsupported VM kernel: %s", release)
	}
	lsms, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil || !strings.Contains(","+strings.TrimSpace(string(lsms))+",", ",bpf,") {
		return errors.New("BPF LSM absent from active VM LSM list")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return err
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return err
	}
	return rlimit.RemoveMemlock()
}

func MonotonicNS() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec), nil
}

type CgroupProgram struct {
	Name   string
	Attach ebpf.AttachType
}
type TracepointProgram struct{ Name, Group, Event string }
type Profile struct {
	Initialize         func(*Runtime) error
	LSMPrograms        []string
	CgroupPrograms     []CgroupProgram
	TracepointPrograms []TracepointProgram
	ProgramOptions     ebpf.ProgramOptions
	EventsMap          string
	CountersMap        string
	MapReplacements    map[string]*ebpf.Map
	// A coupled component can share another runtime's ring and counters.
	// Only the original runtime owns the reader and counts that stream.
	NoEventReader bool
}

func validateProfile(profile Profile) error {
	if profile.Initialize == nil || len(profile.LSMPrograms)+len(profile.CgroupPrograms)+len(profile.TracepointPrograms) == 0 {
		return errors.New("an explicit fixture initializer and program list are required")
	}
	if profile.NoEventReader && (profile.EventsMap == "" || profile.CountersMap == "" || profile.MapReplacements[profile.EventsMap] == nil || profile.MapReplacements[profile.CountersMap] == nil) {
		return errors.New("a shared audit reader requires exact event and counter map replacements")
	}
	names := map[string]bool{}
	check := func(name string) error {
		if name == "" || names[name] {
			return errors.New("fixture programs require unique nonempty names")
		}
		names[name] = true
		return nil
	}
	for _, name := range profile.LSMPrograms {
		if err := check(name); err != nil {
			return err
		}
	}
	for _, program := range profile.CgroupPrograms {
		if err := check(program.Name); err != nil {
			return err
		}
	}
	for _, program := range profile.TracepointPrograms {
		if err := check(program.Name); err != nil {
			return err
		}
		if !tracepointName(program.Group) || !tracepointName(program.Event) {
			return errors.New("fixture tracepoints require exact group and event names")
		}
	}
	return nil
}

func tracepointName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if c != '_' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func New(object, domain string) (*Runtime, error) {
	return NewProfile(object, domain, Profile{
		Initialize:     func(r *Runtime) error { return r.Install(Policy{}) },
		LSMPrograms:    []string{"write_open"},
		CgroupPrograms: []CgroupProgram{{"connect4", ebpf.AttachCGroupInet4Connect}, {"connect6", ebpf.AttachCGroupInet6Connect}},
	})
}

// NewProfile loads an explicit private fixture profile. Preflight remains mandatory.
func NewProfile(object, domain string, profile Profile) (*Runtime, error) {
	return newProfile(object, domain, profile, 0, "")
}

// AttachOwnedProfile adds one component to a verified empty owned domain.
// The owner must stop the complete domain before removing any component.
func AttachOwnedProfile(object, domain, component string, expectedID uint64, profile Profile) (*Runtime, error) {
	if expectedID == 0 || !validComponentName(component) {
		return nil, errors.New("a nonzero owned domain and unique component name are required")
	}
	return newProfile(object, domain, profile, expectedID, component)
}
func validComponentName(name string) bool {
	if len(name) == 0 || len(name) > 48 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
func (r *Runtime) Hooks() []string { return append([]string{}, r.hooks...) }

func newProfile(object, domain string, profile Profile, expectedID uint64, component string) (_ *Runtime, err error) {
	if err = validateProfile(profile); err != nil {
		return nil, err
	}
	if err = Preflight(); err != nil {
		return nil, err
	}
	if filepath.Dir(domain) != "/sys/fs/cgroup" || !strings.HasPrefix(filepath.Base(domain), "alloyium-poc-") {
		return nil, errors.New("domain must be a fresh root-level POC cgroup")
	}
	if expectedID == 0 {
		if err = os.Mkdir(domain, 0700); err != nil {
			return nil, err
		}
	}
	var st syscall.Stat_t
	if err = syscall.Lstat(domain, &st); err != nil {
		return nil, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Uid != 0 || expectedID != 0 && st.Ino != expectedID {
		return nil, errors.New("owned cgroup path identity differs")
	}
	if expectedID != 0 {
		raw, readErr := os.ReadFile(filepath.Join(domain, "cgroup.events"))
		if readErr != nil {
			return nil, readErr
		}
		if !strings.Contains(string(raw), "populated 0\n") {
			return nil, errors.New("component attachment requires an empty owned domain")
		}
	}
	if profile.EventsMap == "" {
		profile.EventsMap = "events"
	}
	if profile.CountersMap == "" {
		profile.CountersMap = "stats"
	}
	r := &Runtime{Domain: domain, statsMap: profile.CountersMap, ID: st.Ino, sharedDomain: expectedID != 0}
	defer func() {
		if err != nil {
			r.Close()
		}
	}()
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		return nil, err
	}
	r.Collection, err = ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: profile.ProgramOptions, MapReplacements: profile.MapReplacements})
	if err != nil {
		return nil, fmt.Errorf("load BPF: %w", err)
	}
	mapNames := []string{}
	for name := range r.Collection.Maps {
		mapNames = append(mapNames, name)
	}
	mapPins, pinErr := mapPinNames(mapNames)
	if pinErr != nil {
		return nil, pinErr
	}
	if r.Collection.Maps[profile.EventsMap] == nil || r.Collection.Maps[profile.CountersMap] == nil {
		return nil, errors.New("fixture evidence maps are unavailable")
	}
	if err = profile.Initialize(r); err != nil {
		return nil, err
	}
	for _, name := range profile.LSMPrograms {
		program := r.Collection.Programs[name]
		if program == nil {
			return nil, fmt.Errorf("fixture LSM program %s is unavailable", name)
		}
		l, attachErr := link.AttachLSM(link.LSMOptions{Program: program})
		if attachErr != nil {
			return nil, fmt.Errorf("attach fixture LSM %s: %w", name, attachErr)
		}
		r.Links = append(r.Links, l)
		r.hooks = append(r.hooks, name)
	}
	for _, program := range profile.CgroupPrograms {
		loaded := r.Collection.Programs[program.Name]
		if loaded == nil {
			return nil, fmt.Errorf("fixture cgroup program %s is unavailable", program.Name)
		}
		l, attachErr := link.AttachCgroup(link.CgroupOptions{Path: domain, Attach: program.Attach, Program: loaded})
		if attachErr != nil {
			return nil, fmt.Errorf("attach fixture cgroup program %s: %w", program.Name, attachErr)
		}
		r.Links = append(r.Links, l)
		r.hooks = append(r.hooks, program.Name)
	}
	for _, program := range profile.TracepointPrograms {
		loaded := r.Collection.Programs[program.Name]
		if loaded == nil {
			return nil, fmt.Errorf("fixture tracepoint program %s is unavailable", program.Name)
		}
		l, attachErr := link.Tracepoint(program.Group, program.Event, loaded, nil)
		if attachErr != nil {
			return nil, fmt.Errorf("attach fixture tracepoint %s: %w", program.Name, attachErr)
		}
		r.Links = append(r.Links, l)
		r.hooks = append(r.hooks, program.Name)
	}
	if !profile.NoEventReader {
		r.Reader, err = ringbuf.NewReader(r.Collection.Maps[profile.EventsMap])
		if err != nil {
			return nil, err
		}
	}
	// Pins retain both objects and attachments if the enforcer exits abruptly.
	pinName := filepath.Base(domain)
	if component != "" {
		pinName += "-" + component
	}
	pins := filepath.Join("/sys/fs/bpf", pinName)
	if err = os.Mkdir(pins, 0700); err != nil {
		return nil, err
	}
	r.Pins = pins
	for name, m := range r.Collection.Maps {
		if err = m.Pin(filepath.Join(r.Pins, mapPins[name])); err != nil {
			return nil, fmt.Errorf("pin fixture map %s: %w", name, err)
		}
	}
	for i, l := range r.Links {
		if err = l.Pin(filepath.Join(r.Pins, fmt.Sprintf("link-%d", i))); err != nil {
			return nil, fmt.Errorf("pin fixture link %d: %w", i, err)
		}
	}
	return r, nil
}

func (r *Runtime) Install(p Policy) error {
	return r.WithPolicyUpdate(func() error { return r.Collection.Maps["policies"].Update(r.ID, p, ebpf.UpdateAny) })
}

// WithPolicyUpdate serializes trusted policy writers and excludes teardown.
// Each component must also check its own generation and immutable binding.
func (r *Runtime) WithPolicyUpdate(update func() error) error {
	r.policyMu.Lock()
	defer r.policyMu.Unlock()
	if r.Collection == nil || r.Domain == "" || update == nil {
		return errors.New("the fixture runtime is closed or its update is absent")
	}
	return update()
}
func (r *Runtime) Move(pid int) error {
	if pid <= 1 || r.ID == 0 || r.Domain == "" {
		return errors.New("a live owned process and domain are required")
	}
	if err := os.WriteFile(filepath.Join(r.Domain, "cgroup.procs"), []byte(fmt.Sprint(pid)), 0600); err != nil {
		return err
	}
	return r.VerifyMember(pid)
}
func memberOf(raw, name string) bool {
	found := false
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "0::") {
			if found {
				return false
			}
			found = true
			path := strings.TrimPrefix(line, "0::")
			if filepath.Clean(path) != path || path != "/"+name && !strings.HasPrefix(path, "/"+name+"/") {
				return false
			}
		}
	}
	return found
}
func (r *Runtime) VerifyMember(pid int) error {
	if pid <= 1 || r.ID == 0 || r.Domain == "" {
		return errors.New("a live owned membership is required")
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(r.Domain, &st); err != nil {
		return err
	}
	if st.Ino != r.ID {
		return errors.New("the owned domain inode changed")
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return err
	}
	if !memberOf(string(raw), filepath.Base(r.Domain)) {
		return errors.New("the process cgroup readback differs")
	}
	return nil
}
func (r *Runtime) Counters() (Counters, error) {
	var value Counters
	if r == nil {
		return value, errors.New("the kernel counter runtime is absent")
	}
	r.policyMu.Lock()
	defer r.policyMu.Unlock()
	if r.Collection == nil {
		return value, errors.New("the kernel counter runtime is closed")
	}
	name := r.statsMap
	if name == "" {
		name = "stats"
	}
	counter := r.Collection.Maps[name]
	if counter == nil {
		return value, errors.New("the kernel counter map is absent")
	}
	err := counter.Lookup(uint32(0), &value)
	return value, err
}

func (r *Runtime) Drain() ([]Event, error) {
	if r.Reader == nil {
		return nil, errors.New("this coupled runtime has no independent audit reader")
	}
	r.Reader.SetDeadline(time.Now().Add(time.Second))
	var events []Event
	for {
		record, err := r.Reader.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return events, nil
		}
		if err != nil {
			return nil, err
		}
		var event Event
		if err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return nil, err
		}
		events = append(events, event)
		if len(events) > 10000 {
			return nil, errors.New("audit event limit exceeded")
		}
	}
}

func (r *Runtime) StopWorkload() error {
	if r.Domain == "" {
		return nil
	}
	// Dispose all descendants before removing policy or attachments.
	if r.Domain != "" {
		if err := os.WriteFile(filepath.Join(r.Domain, "cgroup.kill"), []byte("1"), 0600); err != nil {
			return err
		}
		empty := false
		for i := 0; i < 100; i++ {
			state, err := os.ReadFile(filepath.Join(r.Domain, "cgroup.events"))
			if err != nil {
				return err
			}
			if strings.Contains(string(state), "populated 0") {
				empty = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !empty {
			return errors.New("cleanup retains enforcement: managed domain remains populated")
		}
	}
	return nil
}
func (r *Runtime) Empty() (bool, error) {
	if r.Domain == "" {
		return true, nil
	}
	state, err := os.ReadFile(filepath.Join(r.Domain, "cgroup.events"))
	return err == nil && strings.Contains(string(state), "populated 0"), err
}
func (r *Runtime) Close() error {
	r.policyMu.Lock()
	defer r.policyMu.Unlock()
	if r.Domain == "" {
		return nil
	}
	if err := r.StopWorkload(); err != nil {
		return err
	}
	if r.Reader != nil {
		r.Reader.Close()
	}
	if r.Pins != "" {
		entries, err := os.ReadDir(r.Pins)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		for _, e := range entries {
			if err = os.Remove(filepath.Join(r.Pins, e.Name())); err != nil {
				return err
			}
		}
		if err = os.Remove(r.Pins); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	for _, l := range r.Links {
		l.Close()
	}
	if r.Collection != nil {
		r.Collection.Close()
	}
	if !r.sharedDomain {
		if err := os.Remove(r.Domain); err != nil {
			return err
		}
	}
	r.Domain = ""
	r.Pins = ""
	r.Collection = nil
	r.Reader = nil
	r.Links = nil
	return nil
}

func Recover(domain string) (*Runtime, error) {
	if err := Preflight(); err != nil {
		return nil, err
	}
	if filepath.Dir(domain) != "/sys/fs/cgroup" || !strings.HasPrefix(filepath.Base(domain), "alloyium-poc-") {
		return nil, errors.New("invalid recovery domain")
	}
	var st syscall.Stat_t
	if err := syscall.Stat(domain, &st); err != nil {
		return nil, err
	}
	r := &Runtime{Domain: domain, ID: st.Ino, Pins: filepath.Join("/sys/fs/bpf", filepath.Base(domain)), Collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	for _, name := range []string{"policies", "stats", "events"} {
		m, err := ebpf.LoadPinnedMap(filepath.Join(r.Pins, name), nil)
		if err != nil {
			r.Collection.Close()
			return nil, err
		}
		r.Collection.Maps[name] = m
	}
	reader, err := ringbuf.NewReader(r.Collection.Maps["events"])
	if err != nil {
		r.Collection.Close()
		return nil, err
	}
	r.Reader = reader
	return r, nil
}
