// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package workload

import (
	"alloyium.local/kernel-poc/internal/grant"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Job declares the executable. It does not claim executable or read confinement.
type Job struct {
	Executable string   `json:"executable"`
	Arguments  []string `json:"arguments"`
	Workspace  string   `json:"workspace"`
}

func Read(reader io.Reader) (Job, error) {
	var job Job
	data, err := io.ReadAll(io.LimitReader(reader, 32769))
	if err != nil {
		return job, err
	}
	if len(data) > 32768 {
		return job, errors.New("workload declaration exceeds the limit")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&job); err != nil {
		return job, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return job, errors.New("one workload declaration required")
	}
	return job, job.Validate()
}
func cleanAbsolute(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.ContainsRune(value, 0) && !strings.HasPrefix(value, "/tmp/") && value != "/tmp"
}
func (j Job) Validate() error {
	if !cleanAbsolute(j.Executable) || !cleanAbsolute(j.Workspace) || j.Workspace == "/" || len(j.Workspace) >= 127 || len(j.Arguments) > 64 {
		return errors.New("absolute executable and bounded private workspace required")
	}
	size := len(j.Executable) + len(j.Workspace)
	for _, arg := range j.Arguments {
		size += len(arg)
		if strings.ContainsRune(arg, 0) {
			return errors.New("workload argument contains a null byte")
		}
	}
	if size > 16384 {
		return errors.New("workload arguments exceed the limit")
	}
	return nil
}
func (j Job) CheckFiles() error {
	for _, path := range []string{j.Executable, j.Workspace} {
		actual, err := filepath.EvalSymlinks(path)
		if err != nil || actual != path {
			return errors.New("workload executable and workspace must use unlinked paths")
		}
	}
	info, err := os.Stat(j.Executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return errors.New("workload executable is unavailable")
	}
	info, err = os.Stat(j.Workspace)
	if err != nil || !info.IsDir() {
		return errors.New("workload workspace is unavailable")
	}
	return nil
}
func (j Job) Digest() string { data, _ := json.Marshal(j); return grant.Digest(data) }
