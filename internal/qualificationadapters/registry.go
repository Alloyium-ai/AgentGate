// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package qualificationadapters executes fixed owned qualification actors.
package qualificationadapters

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/qualification"
	"golang.org/x/sys/unix"
)

type Config struct {
	NodeConfigFile string
	ServiceImage   string
	Artifacts      map[string]string
	ScratchRoot    string
}

func protectedDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || path == "/tmp" || strings.HasPrefix(path, "/tmp/") {
		return errors.New("a protected canonical qualification root is required")
	}
	for current := path; ; current = filepath.Dir(current) {
		var st unix.Stat_t
		if unix.Lstat(current, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 {
			return errors.New("qualification root custody differs")
		}
		if current == "/" {
			return nil
		}
	}
}

// New is the compiled registry. A caller cannot supply an adapter command or case claim.
func New(config Config) ([]qualification.Adapter, error) {
	if err := protectedDirectory(config.ScratchRoot); err != nil {
		return nil, err
	}
	owned := Config{ScratchRoot: config.ScratchRoot, NodeConfigFile: config.NodeConfigFile, ServiceImage: config.ServiceImage, Artifacts: map[string]string{}}
	for name, path := range config.Artifacts {
		owned.Artifacts[name] = path
	}
	return []qualification.Adapter{&candidateDenial{config: owned}}, nil
}

type candidateDenial struct{ config Config }

func (*candidateDenial) ID() string { return "agentgate.candidate-denial-adapter.v1" }

func validateRequest(request qualification.Request) error {
	digest, err := request.Document.Digest()
	if err != nil || digest != request.Binding.PolicyDigest || request.Binding.SchemaDigest != policy.SchemaDigest() {
		return errors.New("qualification candidate binding differs")
	}
	contracts, err := qualification.Contracts(request.Document)
	if err != nil || !reflect.DeepEqual(contracts, request.Contracts) {
		return errors.New("qualification contracts differ from the compiled catalog")
	}
	if request.Document.Runtime == nil || request.Document.Files == nil || request.Document.Programs == nil {
		return errors.New("qualification requires the complete candidate policy")
	}
	return nil
}

func (a *candidateDenial) measured(request qualification.Request, name string, executable bool) (string, error) {
	path := a.config.Artifacts[name]
	digest := request.Binding.ArtifactDigests[name]
	if path == "" || digest == "" {
		return "", fmt.Errorf("qualification artifact is unavailable: %s", name)
	}
	var err error
	if executable {
		err = jobartifacts.VerifyExecutable(path, digest)
	} else {
		err = jobartifacts.VerifyDataFile(path, digest, 64<<20)
	}
	return path, err
}

func (a *candidateDenial) Run(ctx context.Context, request qualification.Request) (qualification.Result, error) {
	if err := validateRequest(request); err != nil {
		return qualification.Result{}, err
	}
	return a.run(ctx, request)
}

func sourceBootMatches(request qualification.Request) error {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(raw)) != request.Binding.BootID {
		return errors.New("qualification boot differs from the live target")
	}
	return nil
}
