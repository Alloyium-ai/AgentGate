// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package execbroker

import (
	"alloyium.local/kernel-poc/internal/kernel"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"strings"
	"time"
)

// ListenerClosure is an observation. It never continues a syscall or grants a
// permission. The parent still checks the exact workload exit and full cleanup.
type ListenerClosure struct {
	Protocol      string               `json:"protocol"`
	Domain        uint64               `json:"domain,string"`
	Generation    uint64               `json:"generation,string"`
	MonotonicNS   uint64               `json:"monotonic_ns,string"`
	PollFlags     int16                `json:"poll_flags"`
	DomainInode   uint64               `json:"domain_inode,string"`
	Events        []byte               `json:"events"`
	Empty         bool                 `json:"empty"`
	ReadbackError string               `json:"readback_error,omitempty"`
	Readbacks     []ListenerPopulation `json:"readbacks,omitempty"`
}

type ListenerPopulation struct {
	MonotonicNS uint64 `json:"monotonic_ns,string"`
	Events      []byte `json:"events"`
	Empty       bool   `json:"empty"`
}

func (e ListenerClosure) Error() string { raw, _ := json.Marshal(e); return string(raw) }

func emptyClosureEvents(raw []byte) (bool, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return false, errors.New("the listener population readback exceeds its bound")
	}
	seen := map[string]bool{}
	populated := ""
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || seen[fields[0]] || (fields[0] != "populated" && fields[0] != "frozen") || (fields[1] != "0" && fields[1] != "1") {
			return false, errors.New("the listener population readback differs")
		}
		seen[fields[0]] = true
		if fields[0] == "populated" {
			populated = fields[1]
		}
	}
	if populated == "" {
		return false, errors.New("the listener population readback is missing")
	}
	return populated == "0", nil
}
func observeListenerClosure(c Config, flags int16) ListenerClosure {
	o := ListenerClosure{Protocol: "agentgate.listener-closure.v1", Domain: c.DomainID, Generation: c.Generation, PollFlags: flags}
	var err error
	if o.MonotonicNS, err = kernel.MonotonicNS(); err != nil {
		o.ReadbackError = "the listener monotonic readback failed"
		return o
	}
	fd, err := unix.Open(c.Domain, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		o.ReadbackError = "the listener domain readback failed"
		return o
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &st) != nil || unix.Fstatfs(fd, &fs) != nil || st.Ino != c.DomainID || st.Uid != 0 || st.Mode&022 != 0 || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		o.ReadbackError = "the listener domain identity differs"
		return o
	}
	o.DomainInode = st.Ino
	events, err := unix.Openat(fd, "cgroup.events", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		o.ReadbackError = "the listener events readback failed"
		return o
	}
	f := os.NewFile(uintptr(events), "listener domain events")
	defer f.Close()
	o.Events, err = io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		o.ReadbackError = "the listener events readback failed"
		return o
	}
	o.Empty, err = emptyClosureEvents(o.Events)
	if err != nil {
		o.ReadbackError = "the listener events readback differs"
		return o
	}
	mono, err := kernel.MonotonicNS()
	if err != nil {
		o.ReadbackError = "the listener final clock readback failed"
		return o
	}
	o.Readbacks = append(o.Readbacks, ListenerPopulation{MonotonicNS: mono, Events: append([]byte{}, o.Events...), Empty: o.Empty})
	if !o.Empty {
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for attempt := 0; attempt < 32; attempt++ {
			<-ticker.C
			raw, empty, e := listenerPopulation(fd)
			if e != nil {
				o.ReadbackError = "the listener repeated population readback failed"
				break
			}
			now, e := kernel.MonotonicNS()
			if e != nil || now <= mono {
				o.ReadbackError = "the listener repeated clock readback failed"
				break
			}
			mono = now
			o.Readbacks = append(o.Readbacks, ListenerPopulation{MonotonicNS: mono, Events: raw, Empty: empty})
			if empty {
				break
			}
		}
	}
	return o
}

func listenerPopulation(fd int) ([]byte, bool, error) {
	events, err := unix.Openat(fd, "cgroup.events", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, false, err
	}
	f := os.NewFile(uintptr(events), "listener repeated events")
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return nil, false, err
	}
	empty, err := emptyClosureEvents(raw)
	return raw, empty, err
}
