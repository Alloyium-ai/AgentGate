// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// Runner runs the host-side programs agentgate up delegates to (docker,
// agentgate-hostd). Commands are argument vectors, never shell strings, and
// run with a minimal environment.
type Runner interface {
	LookPath(name string) (string, error)
	Run(ctx context.Context, cmd Cmd) (Result, error)
}

// Cmd is one program invocation. Stdin may carry a secret (the first
// administrator's password); it is never logged and the caller zeroes it.
type Cmd struct {
	Path   string
	Args   []string
	Stdin  []byte
	Env    []string
	Stream io.Writer // a live copy of the output for the operator, or nil
}

// Result is a finished command.
type Result struct {
	Stdout []byte
	Stderr []byte
	Exit   int
}

const maxCommandOutput = 1 << 20

// passEnv are the variables a delegated command inherits.
var passEnv = []string{"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", "AGENTGATE_IMAGE", "COMPOSE_PROJECT_NAME"}

// ExecRunner runs real programs.
type ExecRunner struct{}

// LookPath finds a program in PATH.
func (ExecRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

type boundedBuffer struct {
	buf  bytes.Buffer
	tee  io.Writer
	over bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.tee != nil {
		b.tee.Write(p)
	}
	if room := maxCommandOutput - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
			b.over = true
		} else {
			b.buf.Write(p)
		}
	} else {
		b.over = true
	}
	return len(p), nil
}

// Run executes cmd and returns its bounded output and exit status. A
// non-zero exit is a Result, not an error.
func (ExecRunner) Run(ctx context.Context, c Cmd) (Result, error) {
	if !filepath.IsAbs(c.Path) {
		return Result{}, errors.New("a delegated command needs an absolute path")
	}
	cmd := exec.CommandContext(ctx, c.Path, c.Args...)
	env := []string{}
	for _, name := range passEnv {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	cmd.Env = append(env, c.Env...)
	if c.Stdin != nil {
		cmd.Stdin = bytes.NewReader(c.Stdin)
	}
	out, errOut := &boundedBuffer{tee: c.Stream}, &boundedBuffer{tee: c.Stream}
	cmd.Stdout, cmd.Stderr = out, errOut
	err := cmd.Run()
	res := Result{Stdout: out.buf.Bytes(), Stderr: errOut.buf.Bytes()}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		res.Exit = exit.ExitCode()
		if res.Exit < 0 {
			res.Exit = 128
		}
	default:
		return res, err
	}
	return res, nil
}
