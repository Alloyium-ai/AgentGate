// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"bufio"
	"context"
	"crypto/subtle"
	"io"
	"strings"
)

// Terminal is the CLI's view of the controlling terminal. The real one uses
// the process's standard streams; tests use a fake.
type Terminal interface {
	// IsTerminal reports whether stream 0, 1 or 2 is a terminal.
	IsTerminal(stream int) bool
	// ReadSecret prompts on standard error and reads one line from the
	// terminal with echo off. The caller zeroes the result.
	ReadSecret(ctx context.Context, prompt string) ([]byte, error)
}

const maxSecretInput = 16 << 10

// readLine prompts on standard error and reads one visible line.
func (e *env) readLine(ctx context.Context, prompt string) (string, error) {
	if !e.app.Term.IsTerminal(0) {
		return "", usageError("%s needs an interactive terminal", strings.TrimSuffix(strings.TrimSpace(prompt), ":"))
	}
	io.WriteString(e.app.Stderr, prompt)
	type result struct {
		line string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := e.stdin().ReadString('\n')
		done <- result{line, err}
	}()
	select {
	case <-ctx.Done():
		return "", &Error{Exit: ExitInterrupted, Code: "interrupted", Message: "Interrupted."}
	case r := <-done:
		if r.err != nil && r.line == "" {
			return "", usageError("no answer was given")
		}
		return strings.TrimRight(r.line, "\r\n"), nil
	}
}

func (e *env) stdin() *bufio.Reader {
	if e.in == nil {
		e.in = bufio.NewReaderSize(e.app.Stdin, 4096)
	}
	return e.in
}

// confirm asks a yes/no question on the terminal. It never answers itself:
// without a terminal it fails with a usage error naming the flag to use.
func (e *env) confirm(ctx context.Context, question, flagHint string) error {
	if e.g.yes {
		return nil
	}
	if !e.app.Term.IsTerminal(0) || !e.app.Term.IsTerminal(2) {
		return usageError("%s: no terminal to confirm on; pass %s to confirm in a script", question, flagHint)
	}
	answer, err := e.readLine(ctx, question+" [y/N]: ")
	if err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return nil
	}
	return &Error{Exit: ExitUsage, Code: "not_confirmed", Message: "Not confirmed; nothing was changed."}
}

// readNewSecret reads a secret twice from the terminal, or once from a
// non-terminal standard input. It never reads argv or the environment.
func (e *env) readNewSecret(ctx context.Context, label string, confirmTwice bool) ([]byte, error) {
	if e.app.Term.IsTerminal(0) {
		first, err := e.app.Term.ReadSecret(ctx, label+" (input hidden): ")
		if err != nil {
			return nil, err
		}
		if len(first) == 0 {
			return nil, usageError("the value is empty")
		}
		if !confirmTwice {
			return first, nil
		}
		second, err := e.app.Term.ReadSecret(ctx, "Repeat to confirm: ")
		if err != nil {
			zero(first)
			return nil, err
		}
		defer zero(second)
		if subtle.ConstantTimeCompare(first, second) != 1 {
			zero(first)
			return nil, usageError("the two entries differ; nothing was sent")
		}
		return first, nil
	}
	return e.readStdinSecret()
}

// readStdinSecret reads standard input to its end, bounded, and strips one
// trailing newline.
func (e *env) readStdinSecret() ([]byte, error) {
	buf := make([]byte, 0, 512)
	r := e.stdin()
	for {
		if len(buf) > maxSecretInput {
			zero(buf)
			return nil, usageError("the value on standard input exceeds %d bytes", maxSecretInput)
		}
		if len(buf) == cap(buf) {
			grown := make([]byte, len(buf), 2*cap(buf))
			copy(grown, buf)
			zero(buf)
			buf = grown
		}
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err == io.EOF {
			break
		}
		if err != nil {
			zero(buf)
			return nil, failure("cannot read standard input")
		}
	}
	if len(buf) > maxSecretInput {
		zero(buf)
		return nil, usageError("the value on standard input exceeds %d bytes", maxSecretInput)
	}
	if n := len(buf); n > 0 && buf[n-1] == '\n' {
		buf = buf[:n-1]
		if n := len(buf); n > 0 && buf[n-1] == '\r' {
			buf = buf[:n-1]
		}
	}
	if len(buf) == 0 {
		return nil, usageError("standard input was empty; pipe the value in, or run on a terminal to be prompted")
	}
	return buf, nil
}
