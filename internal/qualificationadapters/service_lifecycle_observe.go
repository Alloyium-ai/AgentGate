// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"golang.org/x/sys/unix"
)

func validateServiceLifecycleActor(snapshot processSnapshot, parent uint32) error {
	fields := processFields(snapshot.Status)
	if snapshot.PID <= 1 || snapshot.StartTimeTicks == 0 || len(snapshot.Tasks) != 1 || snapshot.Tasks[0] != strconv.Itoa(snapshot.PID) || fields["PPid"] != strconv.FormatUint(uint64(parent), 10) {
		return errors.New("the lifecycle actor identity or parent differs")
	}
	for _, name := range []string{"Uid", "Gid"} {
		if strings.Join(strings.Fields(fields[name]), " ") != "65534 65534 65534 65534" {
			return errors.New("the lifecycle actor runtime identity differs")
		}
	}
	for _, name := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		value, err := strconv.ParseUint(fields[name], 16, 64)
		if err != nil || value != 0 {
			return errors.New("the lifecycle actor retains a capability")
		}
	}
	if fields["NoNewPrivs"] != "1" || fields["Seccomp"] != "2" || fields["Groups"] != "" || fields["Threads"] != "1" {
		return errors.New("the lifecycle actor privilege or filter readback differs")
	}
	return nil
}
func readServiceLifecycleActors(ctx context.Context, recipe serviceLifecycleRecipe, binding lifecycle.Binding, nodePID int) ([]byte, []processSnapshot, uint64, error) {
	store, err := jobartifacts.New(filepath.Join(recipe.Spec.OwnedRoot, "streams"), binding.NodeID, 1<<20)
	if err != nil {
		return nil, nil, 0, err
	}
	defer store.Close()
	name, err := domainstore.ReservationName(recipe.FixtureRoot.OwnedPrefix, binding)
	if err != nil {
		return nil, nil, 0, err
	}
	domain := filepath.Join(domainstore.RootPath, name)
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		wire, _, err := store.Outputs(binding)
		if err != nil {
			return nil, nil, 0, err
		}
		if len(wire) >= 96 {
			actors, err := DecodeLifecycleRecords(wire)
			if err != nil {
				return wire, nil, 0, err
			}
			if actors[0].ParentPID != uint32(nodePID) {
				return wire, nil, 0, errors.New("the lifecycle worker parent is not the measured node")
			}
			var stat unix.Stat_t
			if unix.Lstat(domain, &stat) != nil || stat.Ino != binding.CgroupID || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 {
				return wire, nil, 0, errors.New("the lifecycle actual cgroup inode differs")
			}
			snapshots := []processSnapshot{}
			for index, actor := range actors {
				snapshot, err := inspectProcess(int(actor.PID), recipe.Spec.Manifest.Executable, recipe.Spec.Manifest.ExecutableDigest)
				if err != nil {
					return wire, snapshots, stat.Ino, err
				}
				if err = validateServiceLifecycleActor(snapshot, actor.ParentPID); err != nil {
					return wire, snapshots, stat.Ino, err
				}
				if !memberSnapshot(snapshot, domain) {
					return wire, snapshots, stat.Ino, errors.New("the lifecycle descendant left the owned root")
				}
				expectedChildren := ""
				if index < 2 {
					expectedChildren = strconv.FormatUint(uint64(actor.ChildPID), 10)
				}
				if strings.TrimSpace(snapshot.Children) != expectedChildren {
					return wire, snapshots, stat.Ino, errors.New("the lifecycle actual descendant edges differ")
				}
				snapshots = append(snapshots, snapshot)
			}
			return wire, snapshots, stat.Ino, nil
		}
		select {
		case <-ctx.Done():
			return wire, nil, 0, ctx.Err()
		case <-timeout.C:
			return wire, nil, 0, errors.New("the lifecycle worker tree did not become observable")
		case <-tick.C:
		}
	}
}
func serviceLifecycleAfter(actors []processSnapshot) []serviceLifecycleAfterProcess {
	after := []serviceLifecycleAfterProcess{}
	for _, actor := range actors {
		item := serviceLifecycleAfterProcess{PID: actor.PID}
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", actor.PID))
		if err != nil {
			item.Error = err.Error()
			item.Errno = serviceLifecycleErrno(err)
		} else {
			item.Stat = raw
			item.StartTicks, err = serviceLifecycleStatTicks(raw, actor.PID)
			if err == nil {
				raw, err = os.ReadFile(fmt.Sprintf("/proc/%d/status", actor.PID))
				item.Status = string(raw)
			}
			if err == nil {
				raw, err = os.ReadFile(fmt.Sprintf("/proc/%d/stat", actor.PID))
				if err == nil {
					var ticks uint64
					ticks, err = serviceLifecycleStatTicks(raw, actor.PID)
					if err == nil && ticks != item.StartTicks {
						err = errors.New("the final process identity changed during readback")
					}
				}
			}
			if err != nil {
				item.Error = err.Error()
				item.Errno = serviceLifecycleErrno(err)
			}
		}
		after = append(after, item)
	}
	return after
}
func serviceLifecycleStatTicks(raw []byte, pid int) (uint64, error) {
	text := string(raw)
	start, end := strings.IndexByte(text, '('), strings.LastIndexByte(text, ')')
	if pid <= 1 || start < 0 || end <= start || strings.TrimSpace(text[:start]) != strconv.Itoa(pid) {
		return 0, errors.New("the final process stat identity differs")
	}
	fields := strings.Fields(text[end+1:])
	if len(fields) < 20 {
		return 0, errors.New("the final process stat is truncated")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || ticks == 0 {
		return 0, errors.New("the final process start time is invalid")
	}
	return ticks, nil
}
func serviceLifecycleActorsTerminated(actors []processSnapshot, after []serviceLifecycleAfterProcess) bool {
	if len(actors) != len(after) {
		return false
	}
	for index, actor := range actors {
		observed := after[index]
		if observed.PID != actor.PID {
			return false
		}
		if observed.Error != "" {
			if observed.Errno != int(unix.ENOENT) {
				return false
			}
			continue
		}
		ticks, err := serviceLifecycleStatTicks(observed.Stat, observed.PID)
		if err != nil || ticks != observed.StartTicks {
			return false
		}
		if observed.Errno != 0 || observed.StartTicks == 0 || observed.StartTicks == actor.StartTimeTicks && !strings.HasPrefix(processFields(observed.Status)["State"], "Z") {
			return false
		}
	}
	return true
}
func serviceLifecycleFinalState(recipe serviceLifecycleRecipe) (string, int, []string) {
	name, err := domainstore.ReservationName(recipe.FixtureRoot.OwnedPrefix, recipe.Spec.Binding)
	if err != nil {
		return "", -1, []string{"invalid-reservation"}
	}
	domain := filepath.Join(domainstore.RootPath, name)
	var stat unix.Stat_t
	statErr := unix.Lstat(domain, &stat)
	errno := 0
	if statErr != nil {
		var actual unix.Errno
		if errors.As(statErr, &actual) {
			errno = int(actual)
		} else {
			errno = -1
		}
	}
	entries, err := os.ReadDir("/sys/fs/bpf")
	if err != nil {
		return domain, errno, []string{"pin-inventory-unavailable"}
	}
	pins := []string{}
	for _, entry := range entries {
		if entry.Name() == name || strings.HasPrefix(entry.Name(), name+"-") {
			pins = append(pins, entry.Name())
		}
	}
	return domain, errno, pins
}

func serviceLifecycleErrno(err error) int {
	if err == nil {
		return 0
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		return int(errno)
	}
	return -1
}
