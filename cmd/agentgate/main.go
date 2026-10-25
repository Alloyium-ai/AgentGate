// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Command agentgate is the single command-line client of the AgentGate
// control plane. See docs/CLI.md; the logic lives in internal/cli.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"alloyium.local/kernel-poc/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	app := &cli.App{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Getenv: os.Getenv,
		Term:   cli.StdTerminal{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr},
		Runner: cli.ExecRunner{},
	}
	code := app.Main(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
