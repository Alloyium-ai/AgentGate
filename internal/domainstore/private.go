// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package domainstore

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type signedRecord struct {
	Protocol string          `json:"protocol"`
	Payload  json.RawMessage `json:"payload"`
	MAC      string          `json:"mac"`
}

func openPrivateDirectory(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || path == "/tmp" || strings.HasPrefix(path, "/tmp/") {
		return -1, errors.New("a protected state directory is required")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if openErr != nil {
			return -1, errors.New("the state directory path is linked or unavailable")
		}
		fd = next
		var info unix.Stat_t
		mask := uint32(0022)
		if i == len(parts)-1 {
			mask = 0077
		}
		if unix.Fstat(fd, &info) != nil || info.Uid != 0 || info.Mode&mask != 0 {
			unix.Close(fd)
			return -1, errors.New("the state directory chain must remain root-owned and protected")
		}
	}
	return fd, nil
}
func readPrivate(fd int, name string, limit int64) ([]byte, error) {
	opened, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(opened), name)
	defer file.Close()
	var info unix.Stat_t
	if unix.Fstat(opened, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != 0 || info.Mode&0077 != 0 || info.Nlink != 1 || info.Size > limit {
		return nil, errors.New("a protected state file is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("a protected state file exceeds its bound")
	}
	return raw, nil
}
func (s *Store) lock(ctx context.Context) (func(), error) {
	fd, err := unix.Openat(s.stateFD, ".lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, errors.New("the reservation lock is unavailable")
	}
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Uid != 0 || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Mode&0077 != 0 || info.Nlink != 1 {
		unix.Close(fd)
		return nil, errors.New("the reservation lock custody differs")
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { unix.Flock(fd, unix.LOCK_UN); unix.Close(fd) }, nil
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			unix.Close(fd)
			return nil, errors.New("the reservation lock failed")
		}
		select {
		case <-ctx.Done():
			unix.Close(fd)
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
func (s *Store) mac(raw []byte) string {
	hash := hmac.New(sha256.New, s.key)
	hash.Write([]byte("agentgate-domain-ownership-v1\n"))
	hash.Write(raw)
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}
func (s *Store) read(name string, value any) error {
	raw, err := readPrivate(s.stateFD, name, 128<<10)
	if err != nil {
		return err
	}
	var signed signedRecord
	if json.Unmarshal(raw, &signed) != nil || signed.Protocol != "agentgate.domain.ownership.v1" || !hmac.Equal([]byte(signed.MAC), []byte(s.mac(signed.Payload))) || json.Unmarshal(signed.Payload, value) != nil {
		return errors.New("the reservation ownership record is corrupt")
	}
	return nil
}
func (s *Store) write(name string, value any, exclusive bool) error {
	payload, err := json.Marshal(value)
	if err != nil || len(payload) > 64<<10 {
		return errors.New("the reservation record exceeds its bound")
	}
	raw, err := json.Marshal(signedRecord{Protocol: "agentgate.domain.ownership.v1", Payload: payload, MAC: s.mac(payload)})
	if err != nil {
		return err
	}
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return err
	}
	stage := ".stage-" + base64.RawURLEncoding.EncodeToString(random)
	fd, err := unix.Openat(s.stateFD, stage, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("the reservation stage cannot open")
	}
	defer unix.Unlinkat(s.stateFD, stage, 0)
	file := os.NewFile(uintptr(fd), stage)
	_, err = file.Write(raw)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errors.New("the reservation stage is not durable")
	}
	flags := uint(0)
	if exclusive {
		flags = unix.RENAME_NOREPLACE
	}
	if err = unix.Renameat2(s.stateFD, stage, s.stateFD, name, flags); err != nil {
		return errors.New("the reservation record conflicts or cannot commit")
	}
	if unix.Fsync(s.stateFD) != nil {
		return errors.New("the reservation directory is not durable")
	}
	return nil
}
