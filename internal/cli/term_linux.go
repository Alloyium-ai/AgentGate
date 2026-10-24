// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"context"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// StdTerminal is the process's terminal.
type StdTerminal struct {
	Stdin, Stdout, Stderr *os.File
}

// IsTerminal reports whether a standard stream is a terminal.
func (t StdTerminal) IsTerminal(stream int) bool {
	f := map[int]*os.File{0: t.Stdin, 1: t.Stdout, 2: t.Stderr}[stream]
	if f == nil {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// ReadSecret turns echo off, reads one line and restores the terminal, also
// when the context ends first.
func (t StdTerminal) ReadSecret(ctx context.Context, prompt string) ([]byte, error) {
	fd := int(t.Stdin.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, usageError("reading a secret needs a terminal")
	}
	quiet := *old
	quiet.Lflag &^= unix.ECHO
	quiet.Lflag |= unix.ICANON | unix.ISIG
	if err = unix.IoctlSetTermios(fd, unix.TCSETS, &quiet); err != nil {
		return nil, failure("cannot turn terminal echo off")
	}
	restore := func() { unix.IoctlSetTermios(fd, unix.TCSETS, old) }
	io.WriteString(t.Stderr, prompt)
	type result struct {
		value []byte
		err   error
	}
	done := make(chan result, 1)
	go func() {
		buf := make([]byte, 0, 256)
		one := make([]byte, 1)
		for {
			n, err := t.Stdin.Read(one)
			if n == 1 {
				if one[0] == '\n' {
					break
				}
				if len(buf) >= maxSecretInput {
					zero(buf)
					done <- result{nil, usageError("the value exceeds %d bytes", maxSecretInput)}
					return
				}
				if len(buf) == cap(buf) {
					grown := make([]byte, len(buf), 2*cap(buf))
					copy(grown, buf)
					zero(buf)
					buf = grown
				}
				buf = append(buf, one[0])
			}
			if err != nil {
				break
			}
		}
		if n := len(buf); n > 0 && buf[n-1] == '\r' {
			buf = buf[:n-1]
		}
		done <- result{buf, nil}
	}()
	select {
	case <-ctx.Done():
		restore()
		io.WriteString(t.Stderr, "\n")
		return nil, &Error{Exit: ExitInterrupted, Code: "interrupted", Message: "Interrupted."}
	case r := <-done:
		restore()
		io.WriteString(t.Stderr, "\n")
		return r.value, r.err
	}
}
