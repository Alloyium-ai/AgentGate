// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobartifacts

import (
	"alloyium.local/kernel-poc/internal/childwire"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Store struct {
	root        string
	fd          int
	node        string
	outputLimit int64
}
type Streams struct {
	Paths     childwire.IOPaths
	Directory string
}

func New(root, node string, outputLimit int64) (*Store, error) {
	if !canonical(root) || node == "" || outputLimit <= 0 || outputLimit > 16<<20 {
		return nil, errors.New("the job artifact store requires a protected root and bounded outputs")
	}
	if err := privateParents(filepath.Join(root, "entry")); err != nil {
		return nil, err
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &Store{root: root, fd: fd, node: node, outputLimit: outputLimit}, nil
}
func (s *Store) Close() error {
	if s.fd < 0 {
		return nil
	}
	err := unix.Close(s.fd)
	s.fd = -1
	return err
}
func (s *Store) Paths(binding lifecycle.Binding) (Streams, error) {
	if binding.Validate(binding.CgroupID == 0) != nil || binding.NodeID != s.node {
		return Streams{}, errors.New("the job artifact binding differs")
	}
	digest := sha256.Sum256([]byte(binding.NodeID + "\n" + binding.RunID))
	directory := filepath.Join(s.root, "job-"+hex.EncodeToString(digest[:]))
	return Streams{Directory: directory, Paths: childwire.IOPaths{Input: filepath.Join(directory, "input"), Output: filepath.Join(directory, "output"), Error: filepath.Join(directory, "error")}}, nil
}

// OnlyJob rejects a Docker bind that would expose any other job's streams to
// the shared runtime UID. The caller holds its run reservation while checking.
func (s *Store) OnlyJob(binding lifecycle.Binding) error {
	streams, err := s.Paths(binding)
	if err != nil {
		return err
	}
	// A fresh open-file description leaves the retained descriptor's offset
	// unchanged across repeated checks.
	duplicate, err := unix.Openat(s.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	reader := os.NewFile(uintptr(duplicate), s.root)
	defer reader.Close()
	entries, err := reader.ReadDir(2)
	if err != nil {
		return err
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(streams.Directory) || !entries[0].IsDir() {
		return errors.New("the Docker stream root contains another entry")
	}
	return nil
}

// Remove erases only the three files created for a completed job. It is called
// after the terminal record is durable and the whole job domain is empty.
func (s *Store) Remove(binding lifecycle.Binding) error {
	streams, err := s.Paths(binding)
	if err != nil {
		return err
	}
	name := filepath.Base(streams.Directory)
	if !strings.HasPrefix(name, "job-") {
		return errors.New("the job stream name differs")
	}
	dir, err := unix.Openat(s.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	defer unix.Close(dir)
	view, err := unix.Openat(dir, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	reader := os.NewFile(uintptr(view), name)
	entries, readErr := reader.ReadDir(4)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	for _, entry := range entries {
		if entry.Name() != "input" && entry.Name() != "output" && entry.Name() != "error" {
			return errors.New("the completed job stream directory contains a foreign entry")
		}
	}
	for _, entry := range []string{"input", "output", "error"} {
		var st unix.Stat_t
		if err = unix.Fstatat(dir, entry, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 65534 || st.Nlink != 1 || st.Mode&077 != 0 {
			return errors.New("the completed job stream custody differs")
		}
	}
	for _, entry := range []string{"input", "output", "error"} {
		if err = unix.Unlinkat(dir, entry, 0); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return err
		}
	}
	if err = unix.Fsync(dir); err != nil {
		return err
	}
	if err = unix.Unlinkat(s.fd, name, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return unix.Fsync(s.fd)
}
func writeStream(dir int, name string, data []byte) error {
	fd, err := unix.Openat(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = unix.Fchown(fd, 65534, 65534); err != nil {
		return err
	}
	return file.Sync()
}

// Prepare creates distinct stream artifacts. It accepts no caller-supplied path.
func (s *Store) Prepare(binding lifecycle.Binding, expectedInput string, input []byte) (Streams, error) {
	if len(input) > lifecycle.MaxInputBytes {
		return Streams{}, errors.New("the actual job input exceeds its bound")
	}
	digest := sha256.Sum256(input)
	if hex.EncodeToString(digest[:]) != expectedInput {
		return Streams{}, errors.New("the actual job input digest differs")
	}
	streams, err := s.Paths(binding)
	if err != nil {
		return Streams{}, err
	}
	name := filepath.Base(streams.Directory)
	if err = unix.Mkdirat(s.fd, name, 0755); err != nil {
		return Streams{}, err
	}
	dir, err := unix.Openat(s.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return Streams{}, err
	}
	defer unix.Close(dir)
	// The node uses umask0077. Set this owned directory's exact traverse mode
	// through its retained descriptor; private node parents remain unchanged.
	if err = unix.Fchmod(dir, 0711); err != nil {
		return Streams{}, err
	}
	var mode unix.Stat_t
	if err = unix.Fstat(dir, &mode); err != nil {
		return Streams{}, err
	}
	if mode.Uid != 0 || mode.Mode&0777 != 0711 {
		return Streams{}, errors.New("the owned stream directory mode differs")
	}
	for _, value := range []struct {
		name string
		data []byte
	}{{"input", input}, {"output", []byte{}}, {"error", []byte{}}} {
		if err = writeStream(dir, value.name, value.data); err != nil {
			return Streams{}, err
		}
	}
	if err = unix.Fsync(dir); err != nil {
		return Streams{}, err
	}
	if err = unix.Fsync(s.fd); err != nil {
		return Streams{}, err
	}
	return streams, nil
}
func (s *Store) readStream(binding lifecycle.Binding, name string) ([]byte, error) {
	streams, err := s.Paths(binding)
	if err != nil {
		return nil, err
	}
	dir, err := unix.Openat(s.fd, filepath.Base(streams.Directory), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Uid != 65534 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&077 != 0 || st.Nlink != 1 || st.Size < 0 || st.Size > s.outputLimit {
		return nil, errors.New("the job output custody or size differs")
	}
	raw, err := io.ReadAll(io.LimitReader(file, s.outputLimit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > s.outputLimit {
		return nil, errors.New("the job output exceeds its byte bound")
	}
	return raw, nil
}

// Outputs reads only bounded owned artifacts. Call it after whole-domain stop.
func (s *Store) Outputs(binding lifecycle.Binding) (output, diagnostic []byte, err error) {
	output, err = s.readStream(binding, "output")
	if err != nil {
		return nil, nil, err
	}
	diagnostic, err = s.readStream(binding, "error")
	return output, diagnostic, err
}
