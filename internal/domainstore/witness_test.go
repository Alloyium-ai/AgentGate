//go:build agentgate_domain_witness

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package domainstore

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type witnessBarrier struct {
	pid                 int
	start               uint64
	token, pipe, digest string
}

func (w witnessBarrier) VerifyHeld(ctx context.Context, _ lifecycle.Binding, p lifecycle.HeldProcess) error {
	if ctx.Err() != nil || p.PID != w.pid || p.StartTimeTicks != w.start || p.BarrierID != w.token {
		return errors.New("the witness barrier identity differs")
	}
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/3", p.PID))
	if err != nil || target != w.pipe {
		return errors.New("the witness barrier pipe differs")
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/exe", p.PID))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != w.digest {
		return errors.New("the measured witness helper changed")
	}
	raw, err = os.ReadFile(fmt.Sprintf("/proc/%d/status", p.PID))
	if err != nil {
		return err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if key, value, ok := strings.Cut(line, ":"); ok {
			fields[key] = strings.TrimSpace(value)
		}
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		if fields[key] != "0000000000000000" {
			return errors.New("the witness helper retained a capability")
		}
	}
	if fields["NoNewPrivs"] != "1" || fields["Threads"] != "1" || fields["Uid"] != "10001\t10001\t10001\t10001" || fields["Gid"] != "10001\t10001\t10001\t10001" {
		return errors.New("the witness helper credentials differ")
	}
	return nil
}

type heldWitness struct {
	command   *exec.Cmd
	process   lifecycle.HeldProcess
	release   *os.File
	ready     *bufio.Reader
	readyFile *os.File
	barrier   witnessBarrier
}

func holdWitness(t *testing.T, helper string) *heldWitness {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(nonce)
	command := exec.Command(helper, token)
	command.ExtraFiles = []*os.File{reader, readyWriter}
	command.SysProcAttr = &unixSysProcAttrWitness
	pipe, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", reader.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	reader.Close()
	readyWriter.Close()
	t.Cleanup(func() { writer.Close(); readyReader.Close(); command.Process.Kill(); command.Wait() })
	if err = readyReader.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ready := bufio.NewReader(readyReader)
	line, err := ready.ReadString('\n')
	if err != nil || line != token+"\n" {
		t.Fatal("the measured witness helper did not reach its barrier", err)
	}
	start, err := lifecycle.ProcessStartTime(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		raw, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/syscall", command.Process.Pid))
		fields := strings.Fields(string(raw))
		if readErr == nil && len(fields) > 1 {
			call, _ := strconv.ParseUint(fields[0], 0, 64)
			fd, _ := strconv.ParseUint(fields[1], 0, 64)
			if call == uint64(unix.SYS_READ) && fd == 3 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the helper did not block on the exact barrier read")
		}
		select {
		case <-time.After(time.Millisecond):
		}
	}
	if err = command.Process.Signal(unix.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	process := lifecycle.HeldProcess{PID: command.Process.Pid, StartTimeTicks: start, BarrierID: token}
	waitStopped(t, process)
	raw, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return &heldWitness{command, process, writer, ready, readyReader, witnessBarrier{command.Process.Pid, start, token, pipe, hex.EncodeToString(sum[:])}}
}

// The helper drops to an isolated nonroot identity before its measured static exec.
// Its children intentionally lack parent-death signals so the domain kill proves custody.
var unixSysProcAttrWitness = syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 10001, Gid: 10001}, Pdeathsig: syscall.SIGKILL}

func (w *heldWitness) resume(t *testing.T) {
	t.Helper()
	if _, err := w.release.WriteString(w.process.BarrierID); err != nil {
		t.Fatal(err)
	}
	if err := w.command.Process.Signal(unix.SIGCONT); err != nil {
		t.Fatal(err)
	}
	if err := w.readyFile.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	line, err := w.ready.ReadString('\n')
	if err != nil || line != "descendants-ready\n" {
		t.Fatal("the witness descendants did not start", err)
	}
}
func witnessLimits(t *testing.T, root int, name string) {
	t.Helper()
	fd, _, err := openDomain(root, name)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	for key, value := range map[string]string{"cpu.max": "100000 100000", "memory.max": "134217728", "pids.max": "16"} {
		if err = writeControl(fd, key, value); err != nil {
			t.Fatal("the disposable target lacks an explicit resource limit", key, err)
		}
	}
}
func TestDisposableDomainDescendants(t *testing.T) {
	helper := os.Getenv("AGENTGATE_DOMAIN_HELPER")
	state := os.Getenv("AGENTGATE_DOMAIN_STATE")
	prefix := os.Getenv("AGENTGATE_DOMAIN_PREFIX")
	if helper == "" || state == "" || !strings.HasPrefix(prefix, "alloyium-poc-job-") {
		t.Fatal("explicit disposable target inputs are required")
	}
	proof, err := MeasureRoot(prefix, strings.Repeat("f", 64))
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(Config{NodeID: "disposable-domain-witness", StateDir: state, Proof: proof, StopTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	root, err := store.root()
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(root)
	b := bindingFixture(proof)
	b.NodeID = store.config.NodeID
	b.BootID = proof.BootID
	for index, mode := range []string{"normal", "corrupt-reservation"} {
		t.Run(mode, func(t *testing.T) {
			b.RunID = fmt.Sprintf("domain-witness-%d", index)
			b.GrantID = fmt.Sprintf("domain-witness-grant-%d", index)
			b.Generation = uint64(index + 1)
			reservation, reserveErr := store.Reserve(context.Background(), b)
			if reserveErr != nil {
				t.Fatal(reserveErr)
			}
			actual, createErr := store.Create(context.Background(), reservation)
			if createErr != nil {
				t.Fatal(createErr)
			}
			fd, id, openErr := openDomain(root, reservation.Name)
			if openErr != nil || id != actual.CgroupID {
				t.Fatal("actual cgroup identity differs", openErr)
			}
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_, _ = stopDomain(cleanup, fd)
				unix.Close(fd)
				_ = unix.Unlinkat(root, reservation.Name, unix.AT_REMOVEDIR)
			})
			witnessLimits(t, root, reservation.Name)
			held := holdWitness(t, helper)
			store.config.BarrierVerifier = held.barrier
			if _, placeErr := store.PlaceHeld(context.Background(), actual, held.process); placeErr != nil {
				t.Fatal(placeErr)
			}
			held.resume(t)
			deadline := time.Now().Add(time.Second)
			for {
				raw, readErr := readControl(fd, "cgroup.procs")
				if readErr != nil {
					t.Fatal(readErr)
				}
				if len(strings.Fields(string(raw))) >= 3 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the complete descendant domain did not appear")
				}
				select {
				case <-time.After(time.Millisecond):
				}
			}
			if mode == "normal" {
				_, stopErr := store.StopOwnedDomain(context.Background(), actual, "disposable-domain-test")
				if stopErr == nil || stopErr.Error() != "the domain stopped but kernel counters are unavailable" {
					t.Fatal("the counterless component falsely claimed kernel evidence", stopErr)
				}
			} else {
				path := filepath.Join(state, reservationFile(store.config.NodeID, actual.RunID))
				raw, readErr := os.ReadFile(path)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if err = os.WriteFile(path, []byte(strings.Replace(string(raw), actual.GrantID, "corrupt-grant", 1)), 0600); err != nil {
					t.Fatal(err)
				}
				bindings, listErr := store.ListOwnedDomains(context.Background())
				if listErr == nil {
					t.Fatal("a corrupt reservation retained admission")
				}
				for _, binding := range bindings {
					if binding.RunID == actual.RunID {
						t.Fatal("an orphan fabricated job identity")
					}
				}
				entries, readErr := os.ReadDir(state)
				if readErr != nil {
					t.Fatal(readErr)
				}
				orphanReceipt := false
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), "orphan-") {
						var receipt OrphanReceipt
						if store.read(entry.Name(), &receipt) == nil && receipt.CgroupID == actual.CgroupID && receipt.Empty && receipt.PinsRetained {
							orphanReceipt = true
						}
					}
				}
				if !orphanReceipt {
					t.Fatal("the orphan stop receipt is missing")
				}
			}
			empty, _, emptyErr := domainEmpty(fd)
			if emptyErr != nil || !empty {
				t.Fatal("the owned descendant domain remains populated", emptyErr)
			}
			raw, readErr := readControl(fd, "cgroup.procs")
			if readErr != nil || len(strings.TrimSpace(string(raw))) != 0 {
				t.Fatal("the domain retains a live descendant", readErr)
			}
			held.command.Wait()
			t.Logf("DOMAIN_CUSTODY_PASS mode=%s cgroup_id=%d descendants=2 empty=true pins_retained=true kernel_counters=unavailable full_policy_qualified=false", mode, actual.CgroupID)
		})
	}
}

func TestCleanupDomainNamespace(t *testing.T) {
	prefix := os.Getenv("AGENTGATE_DOMAIN_PREFIX")
	if !strings.HasPrefix(prefix, "alloyium-poc-job-") || !ownedPrefix.MatchString(prefix) {
		t.Fatal("an exact owned witness prefix is required")
	}
	proof, err := MeasureRoot(prefix, strings.Repeat("f", 64))
	if err != nil {
		t.Fatal(err)
	}
	store := &Store{config: Config{Proof: proof, StopTimeout: 2 * time.Second}}
	root, err := store.root()
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(root)
	entries, err := os.ReadDir(RootPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !store.ownedName(entry.Name()) {
			continue
		}
		fd, _, openErr := openDomain(root, entry.Name())
		if openErr != nil {
			t.Fatal(openErr)
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, stopErr := stopDomain(cleanup, fd)
		cancel()
		unix.Close(fd)
		if stopErr != nil {
			t.Fatal(stopErr)
		}
		if err = unix.Unlinkat(root, entry.Name(), unix.AT_REMOVEDIR); err != nil {
			t.Fatal(err)
		}
	}
	t.Log("DOMAIN_NAMESPACE_CLEANUP_PASS")
}

func TestDisposableReservationResolution(t *testing.T) {
	state := os.Getenv("AGENTGATE_DOMAIN_STATE")
	prefix := os.Getenv("AGENTGATE_DOMAIN_PREFIX")
	if state == "" || !strings.HasPrefix(prefix, "alloyium-poc-job-") {
		t.Fatal("explicit disposable reservation inputs are required")
	}
	proof, err := MeasureRoot(prefix, strings.Repeat("f", 64))
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(Config{NodeID: "disposable-resolution-witness", StateDir: state, Proof: proof, StopTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	root, err := store.root()
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(root)
	b := bindingFixture(proof)
	b.NodeID = store.config.NodeID
	b.RunID = "resolution-never-allocated"
	b.GrantID = "resolution-no-domain-grant"
	reserved, err := store.Reserve(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	stopped, err := store.StopReservation(context.Background(), b, "resolution-no-domain")
	if err != nil || !stopped.NoDomain || !stopped.Empty || !stopped.RightsRemoved || stopped.Reservation.Binding.CgroupID != 0 || stopped.CountersAvailable {
		t.Fatal("the absent allocation did not retain explicit no-domain custody", err)
	}
	if _, _, err = openDomain(root, reserved.Name); !errors.Is(err, unix.ENOENT) {
		t.Fatal("no-domain cleanup created or selected a cgroup")
	}
	if _, err = store.Create(context.Background(), reserved); err == nil {
		t.Fatal("a stopped allocation revived")
	}
	var durable ReservationStop
	if err = store.read("reservation-stop-"+stopped.Digest+".json", &durable); err != nil || durable.Digest != stopDigest(durable) {
		t.Fatal("no-domain custody is not durable", err)
	}
	t.Log("RESERVATION_NO_DOMAIN_PASS cgroup_id=0 kill_called=false counters_available=false")
	b.RunID = "resolution-creating"
	b.GrantID = "resolution-creating-grant"
	b.Generation++
	creating, err := store.Reserve(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	creating.State = "creating"
	if err = store.save(&creating); err != nil {
		t.Fatal(err)
	}
	if err = unix.Mkdirat(root, creating.Name, 0755); err != nil {
		t.Fatal(err)
	}
	fd, id, err := openDomain(root, creating.Name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = stopDomain(cleanup, fd)
		unix.Close(fd)
		_ = unix.Unlinkat(root, creating.Name, unix.AT_REMOVEDIR)
	})
	witnessLimits(t, root, creating.Name)
	actual, err := store.Resolve(context.Background(), b)
	if err != nil || actual.Binding.CgroupID != id || id == 0 || actual.State != "created" {
		t.Fatal("creating custody lost its actual inode", err)
	}
	stopped, err = store.StopReservation(context.Background(), b, "resolution-created-stop")
	if err == nil || err.Error() != "the domain stopped but kernel counters are unavailable" || stopped.NoDomain || !stopped.Empty || stopped.Reservation.Binding.CgroupID != id || stopped.CountersAvailable || stopped.ReadbackDigest == "" {
		t.Fatal("resolved stop hid its actual binding or unknown counters", err)
	}
	if empty, _, readErr := domainEmpty(fd); readErr != nil || !empty {
		t.Fatal("the resolved reservation remains populated", readErr)
	}
	t.Logf("RESERVATION_RESOLVE_PASS cgroup_id=%d empty=true pins_retained=true counters_available=false full_policy_qualified=false", id)
	domains, inventoryErr := store.ListOwnedDomains(context.Background())
	if inventoryErr != nil || len(domains) != 0 {
		t.Fatal("a terminated empty domain stayed in active watchdog inventory", inventoryErr)
	}
	// This witness creates no BPF pins. The explicit verifier represents that
	// component-only fact and makes no full-runtime counter or qualification claim.
	store.config.RightsVerifier = witnessNoPins{}
	snapshot := actual.Binding
	if err = store.ReconcileEmpty(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	retired, retireErr := store.StopOwnedDomain(context.Background(), snapshot, "late-watchdog-snapshot")
	if retireErr == nil || !strings.Contains(retireErr.Error(), "counters") || !retired.Retired || !retired.NoDomain || !retired.Empty || !retired.Terminated || !retired.RightsRemoved || retired.CountersAvailable || retired.Binding.CgroupID != id || retired.Digest != lifecycle.WatchdogStopDigest(retired) {
		t.Fatal("a stale snapshot lost authenticated retirement or invented counters", retireErr)
	}
	if _, _, err = openDomain(root, creating.Name); !errors.Is(err, unix.ENOENT) {
		t.Fatal("retirement selected or recreated a cgroup")
	}
	var receipt lifecycle.WatchdogStopEvidence
	if store.read("stop-"+retired.Digest+".json", &receipt) != nil || receipt.Digest != retired.Digest {
		t.Fatal("independent retirement is not durable")
	}
	t.Logf("WATCHDOG_COMPLETION_RACE_PASS cgroup_id=%d no_domain=true rights_removed=true counters_available=false kill_called=false full_policy_qualified=false", id)
}

type witnessNoPins struct{}

func (witnessNoPins) VerifyRemoved(context.Context, lifecycle.Binding) error { return nil }
