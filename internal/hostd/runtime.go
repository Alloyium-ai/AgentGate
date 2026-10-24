// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// LauncherEvent is one JSON line from launch.py run.
type LauncherEvent struct {
	Event    string          `json:"event"`
	State    string          `json:"state,omitempty"`
	LaunchID string          `json:"launch_id,omitempty"`
	Stream   string          `json:"stream,omitempty"`
	Offset   int64           `json:"offset,omitempty"`
	Data     string          `json:"data,omitempty"`
	Reason   string          `json:"reason,omitempty"`
	Error    string          `json:"error,omitempty"`
	Receipt  json.RawMessage `json:"receipt,omitempty"`
}

// RuntimeInfo is what the launch runtime reports about the target.
type RuntimeInfo struct {
	Runtime      string   `json:"runtime"`
	Capabilities []string `json:"capabilities"`
	Preflight    struct {
		OK     bool   `json:"ok"`
		Error  string `json:"error"`
		Kernel string `json:"kernel"`
	} `json:"preflight"`
	Instance       string `json:"instance"`
	SourceRevision string `json:"source_revision"`
}

// StopStatus is the launch runtime's answer to a stop request.
type StopStatus struct {
	State           string `json:"state"`
	Reason          string `json:"reason"`
	AlreadyTerminal bool   `json:"already_terminal"`
	StopRequested   bool   `json:"stop_requested"`
	Reconciled      bool   `json:"reconciled"`
}

// ReconcileItem is one launch the runtime tore down after a crash.
type ReconcileItem struct {
	LaunchID string `json:"launch_id"`
	State    string `json:"state"`
	Reason   string `json:"reason"`
}

// ErrUnknownLaunch means the runtime never saw that launch.
var ErrUnknownLaunch = errors.New("hostd: the launch is unknown on this target")

// ErrRuntimeBusy means another guarded command holds the instance.
var ErrRuntimeBusy = errors.New("hostd: another guarded command or launch is running on this target")

// Runtime is the launch runtime on the target. Tests replace it.
type Runtime interface {
	Info(ctx context.Context) (RuntimeInfo, error)
	Run(ctx context.Context, job []byte, emit func(LauncherEvent)) error
	Stop(ctx context.Context, launchID string, graceSeconds int, reason string) (StopStatus, error)
	Receipt(ctx context.Context, launchID string) (json.RawMessage, error)
	Reconcile(ctx context.Context, reason string) ([]ReconcileItem, error)
	StageProfile(ctx context.Context, profileID string, version int, policy []byte) (json.RawMessage, error)
	Snapshot(ctx context.Context, name, source string, maxBytes int64, maxEntries int) (json.RawMessage, error)
	Pull(ctx context.Context, image string) error
	Provision(ctx context.Context) (string, error)
}

// Bounds for launcher output.
const (
	maxLauncherLine   = 2 << 20
	maxLauncherOutput = 32 << 20
	maxStderrTail     = 16 << 10
	launcherExitBusy  = 75
	launcherExitInput = 2
)

// CommandRuntime runs launch.py (or the appliance proxy) as a child process.
type CommandRuntime struct {
	Launcher    []string
	Provisioner []string
	// StopWait bounds how long a cancelled Run waits for the launcher to tear
	// down after SIGTERM before it is killed.
	StopWait time.Duration
}

var cleanEnv = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}

func (r *CommandRuntime) command(ctx context.Context, args ...string) *exec.Cmd {
	argv := append(append([]string{}, r.Launcher...), args...)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = cleanEnv
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Cancel asks for a graceful teardown first; the launcher then stops the
	// agent, kills the domain and writes its receipt.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	wait := r.StopWait
	if wait == 0 {
		wait = 150 * time.Second
	}
	cmd.WaitDelay = wait
	return cmd
}

type tailBuffer struct {
	buf   []byte
	limit int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.limit {
		t.buf = append([]byte(nil), t.buf[len(t.buf)-t.limit:]...)
	}
	return len(p), nil
}

func runtimeError(err error, stderr []byte) error {
	var exit *exec.ExitError
	message := strings.TrimSpace(strings.ToValidUTF8(string(stderr), "?"))
	if errors.As(err, &exit) {
		switch {
		case exit.ExitCode() == launcherExitBusy:
			return fmt.Errorf("%w: %s", ErrRuntimeBusy, message)
		case strings.Contains(message, "unknown launch"):
			return fmt.Errorf("%w: %s", ErrUnknownLaunch, message)
		}
		return fmt.Errorf("hostd: launch runtime exited %d: %s", exit.ExitCode(), message)
	}
	return fmt.Errorf("hostd: launch runtime: %v: %s", err, message)
}

func (r *CommandRuntime) output(ctx context.Context, stdin []byte, limit int64, args ...string) ([]byte, error) {
	cmd := r.command(ctx, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout bytes.Buffer
	stderr := &tailBuffer{limit: maxStderrTail}
	cmd.Stdout = &limitWriter{w: &stdout, left: limit}
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return nil, runtimeError(err, stderr.buf)
	}
	return stdout.Bytes(), nil
}

type limitWriter struct {
	w    io.Writer
	left int64
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.left {
		return 0, errors.New("hostd: launch runtime output exceeds its bound")
	}
	l.left -= int64(len(p))
	return l.w.Write(p)
}

func decodeOne(raw []byte, out any) error {
	if err := json.Unmarshal(bytes.TrimSpace(raw), out); err != nil {
		return fmt.Errorf("hostd: launch runtime reply: %w", err)
	}
	return nil
}

func (r *CommandRuntime) Info(ctx context.Context) (RuntimeInfo, error) {
	var info RuntimeInfo
	raw, err := r.output(ctx, nil, 1<<20, "capabilities")
	if err != nil {
		return info, err
	}
	return info, decodeOne(raw, &info)
}

// Run streams the launcher's JSON lines to emit until it exits.
func (r *CommandRuntime) Run(ctx context.Context, job []byte, emit func(LauncherEvent)) error {
	cmd := r.command(ctx, "run")
	cmd.Stdin = bytes.NewReader(job)
	stderr := &tailBuffer{limit: maxStderrTail}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(io.LimitReader(stdout, maxLauncherOutput), 64<<10)
	var readErr error
	for {
		line, tooLong, lineErr := readLine(reader, maxLauncherLine)
		if lineErr != nil {
			if !errors.Is(lineErr, io.EOF) {
				readErr = lineErr
			}
			break
		}
		if tooLong {
			readErr = errors.New("hostd: a launcher line exceeds its bound")
			continue
		}
		var event LauncherEvent
		if json.Unmarshal(line, &event) == nil && event.Event != "" {
			emit(event)
		}
	}
	// Keep draining so the launcher never blocks on a full pipe.
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if waitErr != nil {
		return runtimeError(waitErr, stderr.buf)
	}
	return readErr
}

// readLine returns one line without its newline; an over-long line is
// consumed and reported instead of growing memory.
func readLine(reader *bufio.Reader, limit int) ([]byte, bool, error) {
	var line []byte
	tooLong := false
	for {
		chunk, isPrefix, err := reader.ReadLine()
		if err != nil {
			return nil, false, err
		}
		if !tooLong {
			if len(line)+len(chunk) > limit {
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		if !isPrefix {
			return line, tooLong, nil
		}
	}
}

func (r *CommandRuntime) Stop(ctx context.Context, launchID string, graceSeconds int, reason string) (StopStatus, error) {
	var status StopStatus
	raw, err := r.output(ctx, nil, 1<<20, "stop", launchID, "--grace", strconv.Itoa(graceSeconds), "--reason", reason)
	if err != nil {
		return status, err
	}
	return status, decodeOne(raw, &status)
}

func (r *CommandRuntime) Receipt(ctx context.Context, launchID string) (json.RawMessage, error) {
	raw, err := r.output(ctx, nil, 32<<20, "receipt", launchID)
	if err != nil {
		if strings.Contains(err.Error(), "no receipt yet") {
			return nil, nil
		}
		return nil, err
	}
	raw = bytes.TrimSpace(raw)
	if !json.Valid(raw) {
		return nil, errors.New("hostd: the launch receipt is not JSON")
	}
	return raw, nil
}

func (r *CommandRuntime) Reconcile(ctx context.Context, reason string) ([]ReconcileItem, error) {
	var items []ReconcileItem
	raw, err := r.output(ctx, nil, 1<<20, "reconcile", "--reason", reason)
	if err != nil {
		return nil, err
	}
	return items, decodeOne(raw, &items)
}

func (r *CommandRuntime) StageProfile(ctx context.Context, profileID string, version int, policy []byte) (json.RawMessage, error) {
	raw, err := r.output(ctx, policy, 1<<20, "stage-profile", profileID, strconv.Itoa(version))
	if err != nil {
		return nil, err
	}
	return json.RawMessage(bytes.TrimSpace(raw)), nil
}

func (r *CommandRuntime) Snapshot(ctx context.Context, name, source string, maxBytes int64, maxEntries int) (json.RawMessage, error) {
	raw, err := r.output(ctx, nil, 1<<20, "snapshot", name, source, "--max-bytes", strconv.FormatInt(maxBytes, 10), "--max-entries", strconv.Itoa(maxEntries))
	if err != nil {
		return nil, err
	}
	return json.RawMessage(bytes.TrimSpace(raw)), nil
}

func (r *CommandRuntime) Pull(ctx context.Context, image string) error {
	_, err := r.output(ctx, nil, 1<<20, "pull", image)
	return err
}

// Provision runs the bring-up command and returns its bounded output. It
// succeeds only when the command exits zero and prints ready=true.
func (r *CommandRuntime) Provision(ctx context.Context) (string, error) {
	if len(r.Provisioner) == 0 {
		return "", nil
	}
	cmd := exec.CommandContext(ctx, r.Provisioner[0], r.Provisioner[1:]...)
	cmd.Env = cleanEnv
	var stdout bytes.Buffer
	stderr := &tailBuffer{limit: maxStderrTail}
	cmd.Stdout = &limitWriter{w: &stdout, left: 1 << 20}
	cmd.Stderr = stderr
	err := cmd.Run()
	text := strings.ToValidUTF8(stdout.String(), "?")
	if err != nil {
		return text, fmt.Errorf("hostd: bring-up failed: %s", strings.TrimSpace(strings.ToValidUTF8(string(stderr.buf), "?")))
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "ready=true" {
			return text, nil
		}
	}
	return text, errors.New("hostd: bring-up finished without reporting ready=true")
}
