// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"alloyium.local/kernel-poc/internal/kernel"
	"github.com/cilium/ebpf"
)

// The verification kit and the host agent use these two read-only commands.
// preflight reports the existing kernel preflight verbatim; load-check loads
// each program of each object on its own, reports the verifier log verbatim
// (bounded) and attaches nothing.

const maxVerifierLog = 256 << 10

type preflightReport struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Kernel string `json:"kernel,omitempty"`
}

type programLoad struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	OK           bool   `json:"ok"`
	Error        string `json:"error,omitempty"`
	VerifierLog  string `json:"verifier_log,omitempty"`
	LogTruncated bool   `json:"verifier_log_truncated,omitempty"`
}

type objectLoad struct {
	Object   string        `json:"object"`
	SHA256   string        `json:"sha256"`
	OK       bool          `json:"ok"`
	Error    string        `json:"error,omitempty"`
	Programs []programLoad `json:"programs"`
}

func kernelRelease() string {
	raw, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return string(trimNewline(raw))
}

func trimNewline(raw []byte) []byte {
	for len(raw) > 0 && (raw[len(raw)-1] == '\n' || raw[len(raw)-1] == '\r') {
		raw = raw[:len(raw)-1]
	}
	return raw
}

func preflightCommand(out io.Writer, check func() error) error {
	report := preflightReport{OK: true, Kernel: kernelRelease()}
	if err := check(); err != nil {
		report.OK, report.Error = false, err.Error()
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(encoded))
	return err
}

// programLoader loads one single-program collection spec. Tests replace it.
type programLoader func(*ebpf.CollectionSpec) error

func realLoader(spec *ebpf.CollectionSpec) error {
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelInstruction | ebpf.LogLevelStats}})
	if err != nil {
		return err
	}
	collection.Close()
	return nil
}

func boundedLog(text string) (string, bool) {
	if len(text) <= maxVerifierLog {
		return text, false
	}
	// The end of a verifier log names the failing instruction.
	return text[len(text)-maxVerifierLog:], true
}

func checkObject(path string, load programLoader) objectLoad {
	result := objectLoad{Object: filepath.Base(path), Programs: []programLoad{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	sum := sha256.Sum256(raw)
	result.SHA256 = hex.EncodeToString(sum[:])
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	names := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		names = append(names, name)
	}
	sort.Strings(names)
	result.OK = len(names) > 0
	for _, name := range names {
		single := spec.Copy()
		for other := range single.Programs {
			if other != name {
				delete(single.Programs, other)
			}
		}
		item := programLoad{Name: name, Type: spec.Programs[name].Type.String(), OK: true}
		if loadErr := load(single); loadErr != nil {
			item.OK = false
			item.Error = loadErr.Error()
			var verifier *ebpf.VerifierError
			if errors.As(loadErr, &verifier) {
				item.VerifierLog, item.LogTruncated = boundedLog(fmt.Sprintf("%+v", verifier))
			}
			result.OK = false
		}
		result.Programs = append(result.Programs, item)
	}
	return result
}

func loadCheckCommand(args []string, out io.Writer, check func() error, load programLoader) error {
	if len(args) < 2 || len(args) > 9 {
		return errors.New("usage: pilot-network-diagnostic load-check OBJECT...")
	}
	if err := check(); err != nil {
		return err
	}
	results := make([]objectLoad, 0, len(args)-1)
	ok := true
	for _, path := range args[1:] {
		item := checkObject(path, load)
		ok = ok && item.OK
		results = append(results, item)
	}
	encoded, err := json.Marshal(struct {
		Kernel  string       `json:"kernel"`
		OK      bool         `json:"ok"`
		Objects []objectLoad `json:"objects"`
	}{kernelRelease(), ok, results})
	if err != nil {
		return err
	}
	if _, err = fmt.Fprintln(out, string(encoded)); err != nil {
		return err
	}
	if !ok {
		return errors.New("one or more BPF programs failed to load")
	}
	return nil
}

func verifyCommands(args []string) (func() error, bool) {
	if len(args) == 0 {
		return nil, false
	}
	switch args[0] {
	case "preflight":
		return func() error {
			if len(args) != 1 {
				return errors.New("usage: pilot-network-diagnostic preflight")
			}
			return preflightCommand(os.Stdout, kernel.Preflight)
		}, true
	case "load-check":
		return func() error { return loadCheckCommand(args, os.Stdout, kernel.Preflight, realLoader) }, true
	}
	return nil, false
}
