// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package heldprocess

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"strconv"
	"strings"
)

type identity struct {
	state string
	start uint64
}

func parseIdentity(raw string) (identity, error) {
	end := strings.LastIndex(raw, ")")
	if end < 0 {
		return identity{}, errors.New("held process stat is invalid")
	}
	fields := strings.Fields(raw[end+1:])
	if len(fields) < 20 {
		return identity{}, errors.New("held process stat is incomplete")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return identity{}, errors.New("held process start identity is invalid")
	}
	return identity{fields[0], start}, nil
}
func readIdentity(pid int) (identity, error) {
	if pid <= 1 {
		return identity{}, errors.New("unsafe held process PID")
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return identity{}, err
	}
	return parseIdentity(string(raw))
}
func status(raw string, requireSeccomp bool) error {
	values := map[string][]string{}
	for _, line := range strings.Split(raw, "\n") {
		parts := strings.Fields(line)
		if len(parts) > 1 {
			values[strings.TrimSuffix(parts[0], ":")] = parts[1:]
		}
	}
	for _, name := range []string{"Uid", "Gid"} {
		if len(values[name]) != 4 {
			return errors.New("held process credentials are incomplete")
		}
		for _, v := range values[name] {
			if v != "65534" {
				return errors.New("held process credentials differ")
			}
		}
	}
	for _, name := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		if len(values[name]) != 1 {
			return errors.New("held process capabilities are incomplete")
		}
		n, e := strconv.ParseUint(values[name][0], 16, 64)
		if e != nil || n != 0 {
			return errors.New("held process retains capabilities")
		}
	}
	for key, want := range map[string]string{"NoNewPrivs": "1", "Threads": "1"} {
		if len(values[key]) != 1 || values[key][0] != want {
			return errors.New("held process privilege or thread state differs")
		}
	}
	if requireSeccomp && (len(values["Seccomp"]) != 1 || values["Seccomp"][0] != "2") {
		return errors.New("held process syscall filter is absent")
	}
	return nil
}
func barrier(raw string) bool {
	v := strings.Fields(raw)
	return len(v) > 1 && v[0] == "0" && v[1] == "0x3"
}
func (h *Held) verify(stopped bool) error {
	if err := unix.PidfdSendSignal(h.pidfd, 0, nil, 0); err != nil {
		return err
	}
	if h.spec.Docker && (h.launcherPidfd < 0 || unix.PidfdSendSignal(h.launcherPidfd, 0, nil, 0) != nil) {
		return errors.New("the trusted Docker launcher stopped before its held child")
	}
	first, err := readIdentity(h.process.PID)
	if err != nil {
		return err
	}
	if first.start != h.process.StartTimeTicks || stopped && first.state != "T" && first.state != "t" {
		return errors.New("held process start or stopped state differs")
	}
	prefix := fmt.Sprintf("/proc/%d/", h.process.PID)
	raw, err := os.ReadFile(prefix + "status")
	if err != nil {
		return err
	}
	if err = status(string(raw), h.spec.RequireSeccomp); err != nil {
		return err
	}
	if h.spec.NamespaceInode != 0 {
		var st unix.Stat_t
		if err = unix.Stat(prefix+"ns/mnt", &st); err != nil {
			return err
		}
		if uint64(st.Dev) != h.spec.NamespaceDevice || st.Ino != h.spec.NamespaceInode {
			return errors.New("the held mount namespace differs")
		}
	}
	if h.spec.Docker {
		for _, item := range []struct {
			path          string
			device, inode uint64
		}{
			{"ns/net", h.spec.NetworkDevice, h.spec.NetworkInode},
			{"ns/pid", h.spec.PIDDevice, h.spec.PIDInode},
			{"root", h.spec.RootDevice, h.spec.RootInode},
		} {
			var st unix.Stat_t
			if err = unix.Stat(prefix+item.path, &st); err != nil ||
				uint64(st.Dev) != item.device || st.Ino != item.inode {
				return errors.New("the held Docker namespace or root differs")
			}
		}
	}
	raw, err = os.ReadFile(prefix + "syscall")
	if err != nil {
		return err
	}
	if !barrier(string(raw)) {
		return errors.New("trusted helper is outside its held read barrier")
	}
	target, err := os.Readlink(prefix + "fd/3")
	if err != nil {
		return err
	}
	if target != h.pipe {
		return errors.New("trusted helper barrier pipe differs")
	}
	if err = artifact(h.spec.Executable, h.spec.SHA256); err != nil {
		return err
	}
	actual, err := os.ReadFile(prefix + "exe")
	if err != nil {
		return err
	}
	hash := sha256.Sum256(actual)
	if hex.EncodeToString(hash[:]) != h.spec.SHA256 {
		return errors.New("running trusted helper artifact differs")
	}
	last, err := readIdentity(h.process.PID)
	if err != nil {
		return err
	}
	if first != last {
		return errors.New("held process identity changed during verification")
	}
	return nil
}
