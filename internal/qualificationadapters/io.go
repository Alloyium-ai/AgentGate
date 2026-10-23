// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"alloyium.local/kernel-poc/internal/dockerplacement"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/qualification"
	"golang.org/x/sys/unix"
)

type ownedIO struct {
	input, output string
	files         map[string]unix.Stat_t
	dirs          []string
}

func strictDescendant(root, path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && strings.HasPrefix(path, root+string(filepath.Separator))
}

// The fixed actor can use the pilot's measured stream mount only when the
// source and target paths are identical. A different mount path needs a
// namespace-aware actor and must remain unqualified.
func (a *candidateDenial) pilotStreamRoot(d policy.Document) string {
	t := a.config.PilotTarget
	if t == nil || d.Files == nil || d.Network == nil || d.Network.Pilot == nil || t.ArtifactPath == "" ||
		t.ArtifactSource != t.ArtifactPath || !filepath.IsAbs(t.ArtifactPath) ||
		filepath.Clean(t.ArtifactPath) != t.ArtifactPath {
		return ""
	}
	for _, rule := range d.Files.Rules {
		if rule.ID == "job-streams" && rule.Effect == "allow" && rule.Selector.Kind == "subtree" &&
			rule.Selector.Path == t.ArtifactPath && slices.Contains(rule.Operations, "read") &&
			slices.Contains(rule.Operations, "write") {
			return t.ArtifactPath
		}
	}
	return ""
}

func (a *candidateDenial) pilotIO(ctx context.Context, request qualification.Request, out *ownedIO) (string, error) {
	root := a.pilotStreamRoot(request.Document)
	if root == "" || protectedDirectory(root) != nil {
		return "", errors.New("the candidate has no measured policy stream root")
	}
	handles, err := dockerplacement.Open(ctx, *a.config.PilotTarget)
	if err != nil {
		return "", err
	}
	defer handles.Close()
	var actual unix.Stat_t
	if handles.Measurement.ImageSourceRevision != request.Binding.SourceRevision ||
		unix.Lstat(root, &actual) != nil || uint64(actual.Dev) != handles.Measurement.ArtifactDevice ||
		actual.Ino != handles.Measurement.ArtifactInode || actual.Uid != 0 || actual.Mode&0022 != 0 {
		return "", errors.New("the pilot stream root differs from the measured Docker mount")
	}
	directory, err := os.MkdirTemp(root, ".qualification-")
	if err != nil {
		return "", err
	}
	out.dirs = append(out.dirs, directory)
	if err = os.Chmod(directory, 0711); err != nil {
		return "", err
	}
	out.input, out.output = filepath.Join(directory, "input"), filepath.Join(directory, "output")
	if policy.FileEffect(*request.Document.Files, out.input, "read") != "allow" ||
		policy.FileEffect(*request.Document.Files, out.output, "read") != "allow" ||
		policy.FileEffect(*request.Document.Files, out.output, "write") != "allow" {
		return "", errors.New("the measured pilot streams lack signed read and write rights")
	}
	return root, nil
}
func (a *candidateDenial) prepareIO(ctx context.Context, request qualification.Request) (out *ownedIO, err error) {
	out = &ownedIO{files: map[string]unix.Stat_t{}}
	root := a.config.ScratchRoot
	d := request.Document
	for _, rule := range d.Files.Rules {
		if rule.Effect != "allow" || rule.Selector.Kind != "exact" || !strictDescendant(a.config.ScratchRoot, rule.Selector.Path) {
			continue
		}
		if (rule.ID == "input" || rule.ID == "job-input") && slices.Equal(rule.Operations, []string{"read"}) {
			out.input = rule.Selector.Path
		}
		if (rule.ID == "output" || rule.ID == "job-output") && slices.Contains(rule.Operations, "read") && slices.Contains(rule.Operations, "write") {
			out.output = rule.Selector.Path
		}
	}
	if out.input == "" && out.output == "" && a.pilotStreamRoot(d) != "" {
		root, err = a.pilotIO(ctx, request, out)
		if err != nil {
			return out, err
		}
	}
	if out.input == "" || out.output == "" || out.input == out.output {
		return out, errors.New("the candidate has no exact owned regular input/output selectors")
	}
	for _, path := range []string{out.input, out.output} {
		if err = out.parents(root, filepath.Dir(path)); err != nil {
			return out, err
		}
		file, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if e != nil {
			return out, e
		}
		var created unix.Stat_t
		if e = unix.Fstat(int(file.Fd()), &created); e != nil {
			file.Close()
			os.Remove(path)
			return out, e
		}
		out.files[path] = created
		if e = file.Chown(65534, 65534); e == nil && path == out.input {
			_, e = file.Write([]byte{0})
		}
		if e == nil {
			var stat unix.Stat_t
			e = unix.Fstat(int(file.Fd()), &stat)
			out.files[path] = stat
		}
		closeErr := file.Close()
		if e != nil {
			return out, e
		}
		if closeErr != nil {
			return out, closeErr
		}
	}
	return out, nil
}
func (o *ownedIO) parents(root, path string) error {
	if path == root {
		return protectedDirectory(root)
	}
	if !strictDescendant(root, path) {
		return errors.New("qualification stream parent escapes its owned root")
	}
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		if err = o.parents(root, filepath.Dir(path)); err != nil {
			return err
		}
		if err = os.Mkdir(path, 0711); err != nil {
			return err
		}
		if err = os.Chmod(path, 0711); err != nil {
			return err
		}
		o.dirs = append(o.dirs, path)
	}
	return protectedDirectory(path)
}
func (o *ownedIO) control(value byte) error {
	file, err := os.OpenFile(o.input, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Dev != o.files[o.input].Dev || stat.Ino != o.files[o.input].Ino {
		return errors.New("qualification input object changed")
	}
	_, err = file.WriteAt([]byte{value}, 0)
	return err
}
func (o *ownedIO) close() error {
	if o == nil {
		return nil
	}
	var failures []error
	for path, expected := range o.files {
		var actual unix.Stat_t
		if unix.Lstat(path, &actual) != nil || actual.Dev != expected.Dev || actual.Ino != expected.Ino || actual.Nlink != 1 {
			failures = append(failures, errors.New("qualification stream object changed before cleanup"))
			continue
		}
		failures = append(failures, os.Remove(path))
	}
	for i := len(o.dirs) - 1; i >= 0; i-- {
		failures = append(failures, os.Remove(o.dirs[i]))
	}
	return errors.Join(failures...)
}
