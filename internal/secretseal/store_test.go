// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package secretseal

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

var (
	policyA = policyDigest([]string{"api.a.example"}, []hostproto.BrokerRule{{Methods: []string{"POST"}, Path: "/v1", Match: "prefix"}})
	policyB = policyDigest([]string{"api.b.example"}, []hostproto.BrokerRule{{Methods: []string{"GET"}, Path: "/x", Match: "exact"}})
	valueA  = []byte("value-one-for-A-1234")
	valueB  = []byte("value-two-for-B-5678")
)

// requireWhole checks that name's record is one sealed state in full: the
// value, version, fingerprint and policy digest of the same Accept.
func requireWhole(t *testing.T, s *Store, name string, version uint64, value []byte, policy string) {
	t.Helper()
	st, ok, err := s.Stored(name)
	if err != nil || !ok || st.Version != version || st.PolicyDigest != policy {
		t.Fatalf("stored %+v %v %v, want version %d policy %s", st, ok, err, version, policy[:8])
	}
	held, ok, err := s.Load(name)
	if err != nil || !ok {
		t.Fatalf("load %v %v", ok, err)
	}
	defer held.Wipe()
	if !bytes.Equal(held.Value, value) || held.StoredSecret != st || s.Fingerprint("local", name, held.Value) != st.Fingerprint {
		t.Fatalf("the record holds another value than its version %d and policy %s describe", st.Version, st.PolicyDigest[:8])
	}
}

// requireNoStray checks that no file in the store but name's record holds
// value: a temporary record is zeroed and removed.
func requireNoStray(t *testing.T, s *Store, name string, value []byte) {
	t.Helper()
	entries, _ := os.ReadDir(s.dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), pendingPrefix) {
			t.Errorf("a temporary record remains: %s", e.Name())
		}
		if e.Name() == name+recordSuffix {
			continue
		}
		if raw, _ := os.ReadFile(filepath.Join(s.dir, e.Name())); bytes.Contains(raw, value) {
			t.Errorf("%s holds the value", e.Name())
		}
	}
}

// Regression for the second review's TestReviewTornAcceptUsesNewValueUnderOldPolicy:
// with the file-size limit letting a 20-byte value through but not its
// metadata, Accept used to leave value B on disk under the version,
// fingerprint and policy A of the previous value.
func TestATornAcceptKeepsTheWholePreviousRecord(t *testing.T) {
	f := newFixture(t, "local")
	s1, _ := SealAt(f.pub, "local", "k", policyA, valueA, now)
	if _, err := f.store.Accept(f.key, &s1.Envelope, now); err != nil {
		t.Fatal(err)
	}
	s2, _ := SealAt(f.pub, "local", "k", policyB, valueB, now.Add(time.Minute))
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 64, Max: old.Max}); err != nil {
		t.Skip("cannot set RLIMIT_FSIZE:", err)
	}
	_, acceptErr := f.store.Accept(f.key, &s2.Envelope, now.Add(time.Minute))
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(acceptErr, ErrStore) {
		t.Fatalf("a write the file-size limit cut short was reported as %v", acceptErr)
	}
	requireWhole(t, f.store, "k", s1.Envelope.Version, valueA, policyA)
	requireNoStray(t, f.store, "k", valueB)
	// The same envelope is accepted once the disk has room.
	if _, err := f.store.Accept(f.key, &s2.Envelope, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	requireWhole(t, f.store, "k", s2.Envelope.Version, valueB, policyB)
	requireNoStray(t, f.store, "k", valueA)
}

// faultOps fails, or stops the process, at its at'th file system call.
type faultOps struct {
	osOps
	at    int
	calls int
	crash bool
	names []string
}

type crashed struct{}

func (f *faultOps) step(name string) error {
	f.calls++
	f.names = append(f.names, name)
	if f.calls != f.at {
		return nil
	}
	if f.crash {
		panic(crashed{})
	}
	return fmt.Errorf("injected %s failure", name)
}

func (f *faultOps) createTemp(path string) (int, error) {
	if err := f.step("create"); err != nil {
		return -1, err
	}
	return f.osOps.createTemp(path)
}

func (f *faultOps) write(fd int, data []byte) (int, error) {
	if f.calls+1 == f.at {
		// A crash or failure mid-write leaves a partial temporary record.
		f.osOps.write(fd, data[:len(data)/2])
	}
	if err := f.step("write"); err != nil {
		return len(data) / 2, err
	}
	return f.osOps.write(fd, data)
}

func (f *faultOps) fsync(fd int) error {
	if err := f.step("fsync"); err != nil {
		return err
	}
	return f.osOps.fsync(fd)
}

func (f *faultOps) close(fd int) error {
	if err := f.step("close"); err != nil {
		f.osOps.close(fd)
		return err
	}
	return f.osOps.close(fd)
}

func (f *faultOps) rename(from, to string) error {
	if err := f.step("rename"); err != nil {
		return err
	}
	return f.osOps.rename(from, to)
}

func (f *faultOps) syncDir(dir string) error {
	if err := f.step("syncdir"); err != nil {
		return err
	}
	return f.osOps.syncDir(dir)
}

func (f *faultOps) pwrite(fd int, data []byte, off int64) (int, error) {
	if err := f.step("zero"); err != nil {
		return 0, err
	}
	return f.osOps.pwrite(fd, data, off)
}

// run calls op and reports whether the injected crash stopped it.
func run(op func() error) (err error, stopped bool) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(crashed); !ok {
				panic(r)
			}
			stopped = true
		}
	}()
	return op(), false
}

// TestARecordCommitIsWholeAfterAFailureOrCrashAtEveryStep injects a failure,
// and separately a crash (nothing after the step runs, as when the process
// dies or the power fails), at each file system call of Accept and Delete.
// After a restart the store always holds one whole record: the previous one
// when the step came before the rename, the new one after it, and no
// temporary file with a value survives the restart.
func TestARecordCommitIsWholeAfterAFailureOrCrashAtEveryStep(t *testing.T) {
	probe := &faultOps{}
	f := newFixture(t, "local")
	s1, _ := SealAt(f.pub, "local", "k", policyA, valueA, now)
	f.store.Accept(f.key, &s1.Envelope, now)
	f.store.ops = probe
	s2, _ := SealAt(f.pub, "local", "k", policyB, valueB, now.Add(time.Minute))
	if _, err := f.store.Accept(f.key, &s2.Envelope, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	acceptSteps := append([]string(nil), probe.names...)
	renameAt := 0
	for i, n := range acceptSteps {
		if n == "rename" {
			renameAt = i + 1
		}
	}
	if renameAt == 0 || strings.Join(acceptSteps, ",") != "create,write,fsync,close,rename,syncdir,zero,fsync" {
		t.Fatalf("Accept's steps changed: %v", acceptSteps)
	}
	for _, crash := range []bool{false, true} {
		for at := 1; at <= len(acceptSteps); at++ {
			t.Run(fmt.Sprintf("accept-%s-crash=%v", acceptSteps[at-1], crash), func(t *testing.T) {
				f := newFixture(t, "local")
				s1, _ := SealAt(f.pub, "local", "k", policyA, valueA, now)
				if _, err := f.store.Accept(f.key, &s1.Envelope, now); err != nil {
					t.Fatal(err)
				}
				f.store.ops = &faultOps{at: at, crash: crash}
				s2, _ := SealAt(f.pub, "local", "k", policyB, valueB, now.Add(time.Minute))
				err, stopped := run(func() error { _, err := f.store.Accept(f.key, &s2.Envelope, now.Add(time.Minute)); return err })
				if stopped != crash || (!crash && at <= renameAt+1 && err == nil) {
					t.Fatalf("stopped %v err %v", stopped, err)
				}
				// The host agent restarts: a fresh open sweeps what was left.
				reopened, err := OpenStore(f.dir)
				if err != nil {
					t.Fatal(err)
				}
				// A failing or crashing step does not happen, so the rename
				// is the commit point either way.
				if at <= renameAt {
					requireWhole(t, reopened, "k", s1.Envelope.Version, valueA, policyA)
					requireNoStray(t, reopened, "k", valueB)
				} else {
					requireWhole(t, reopened, "k", s2.Envelope.Version, valueB, policyB)
				}
				// Whatever happened, the older envelope stays a replay.
				if _, err := reopened.Accept(f.key, &s1.Envelope, now.Add(time.Minute)); !errors.Is(err, ErrReplay) {
					t.Fatalf("the first envelope again: %v", err)
				}
			})
		}
	}
	// Delete commits a tombstone the same way.
	for _, crash := range []bool{false, true} {
		for at := 1; at <= len(acceptSteps); at++ {
			t.Run(fmt.Sprintf("delete-%s-crash=%v", acceptSteps[at-1], crash), func(t *testing.T) {
				f := newFixture(t, "local")
				s1, _ := SealAt(f.pub, "local", "k", policyA, valueA, now)
				if _, err := f.store.Accept(f.key, &s1.Envelope, now); err != nil {
					t.Fatal(err)
				}
				f.store.ops = &faultOps{at: at, crash: crash}
				_, stopped := run(func() error { return f.store.Delete("k", now.Add(time.Second)) })
				if stopped != crash {
					t.Fatalf("stopped %v", stopped)
				}
				reopened, err := OpenStore(f.dir)
				if err != nil {
					t.Fatal(err)
				}
				if at <= renameAt {
					requireWhole(t, reopened, "k", s1.Envelope.Version, valueA, policyA)
				} else if _, ok, err := reopened.Stored("k"); ok || err != nil {
					t.Fatalf("deleted record: %v %v", ok, err)
				}
				// Deleted or not, the envelope that set it is a replay.
				if _, err := reopened.Accept(f.key, &s1.Envelope, now.Add(2*time.Second)); !errors.Is(err, ErrReplay) {
					t.Fatalf("replay: %v", err)
				}
			})
		}
	}
}

// A record whose value no longer reproduces its fingerprint (edited, or
// damaged on disk) is refused whole, never served under its metadata.
func TestARecordWhoseValueChangedIsRefused(t *testing.T) {
	f := newFixture(t, "local")
	s1, _ := SealAt(f.pub, "local", "k", policyA, valueA, now)
	if _, err := f.store.Accept(f.key, &s1.Envelope, now); err != nil {
		t.Fatal(err)
	}
	path := f.store.recordPath("k")
	raw, _ := os.ReadFile(path)
	line, _, _ := bytes.Cut(raw, []byte("\n"))
	for name, edited := range map[string][]byte{
		"value swapped":   append(append(append([]byte{}, line...), '\n'), valueB...),
		"value truncated": raw[:len(raw)-1],
		"value extended":  append(append([]byte{}, raw...), 'x'),
		"no value line":   line,
	} {
		if err := os.WriteFile(path, edited, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := f.store.Load("k"); ok || !errors.Is(err, ErrStore) {
			t.Errorf("%s: loaded (%v %v)", name, ok, err)
		}
		if _, ok, err := f.store.Stored("k"); ok || !errors.Is(err, ErrStore) {
			t.Errorf("%s: reported as stored (%v %v)", name, ok, err)
		}
	}
}

// The earlier two-file layout is refused whole and reported, never read.
func TestALegacyTwoFileStoreIsRefused(t *testing.T) {
	for _, file := range []string{"anthropic", "anthropic.meta.json"} {
		f := newFixture(t, "local")
		if err := os.WriteFile(filepath.Join(f.dir, file), []byte(fakeValue), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(f.dir); !errors.Is(err, ErrLegacyStore) {
			t.Fatalf("%s: %v", file, err)
		}
		sealed, _ := SealAt(f.pub, "local", "anthropic", testPolicy, []byte(fakeValue), now)
		if _, err := f.store.Accept(f.key, &sealed.Envelope, now); !errors.Is(err, ErrLegacyStore) {
			t.Fatalf("%s: Accept on a legacy store: %v", file, err)
		}
		if err := f.store.Delete("anthropic", now); !errors.Is(err, ErrLegacyStore) {
			t.Fatalf("%s: Delete on a legacy store: %v", file, err)
		}
	}
}

// Concurrent puts, deletes and loads on one name (separate Store values, as
// separate host agent jobs open it) never show a value under another value's
// record, and a deleted value's envelope stays refused. Run with -race.
func TestConcurrentPutDeleteAndLoadStayWhole(t *testing.T) {
	f := newFixture(t, "local")
	type sealedValue struct {
		env    Envelope
		value  []byte
		policy string
	}
	var sealed []sealedValue
	for i := 0; i < 24; i++ {
		policy, value := policyA, []byte(fmt.Sprintf("value-%02d-for-A-xxxx", i))
		if i%2 == 1 {
			policy, value = policyB, []byte(fmt.Sprintf("value-%02d-for-B-yyyy", i))
		}
		s, err := SealAt(f.pub, "local", "k", policy, value, now.Add(time.Duration(i)*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		sealed = append(sealed, sealedValue{env: s.Envelope, value: value, policy: policy})
	}
	byValue := map[string]string{}
	for _, s := range sealed {
		byValue[string(s.value)] = s.policy
	}
	at := now.Add(time.Second)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			s, err := OpenStore(f.dir)
			if err != nil {
				errs <- err
				return
			}
			for i := w; i < len(sealed); i += 4 {
				env := sealed[i].env
				if _, err := s.Accept(f.key, &env, at); err != nil && !errors.Is(err, ErrReplay) {
					errs <- err
				}
				if i%5 == 0 {
					if err := s.Delete("k", at); err != nil {
						errs <- err
					}
				}
			}
		}(w)
	}
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := OpenStore(f.dir)
			if err != nil {
				errs <- err
				return
			}
			for i := 0; i < 60; i++ {
				held, ok, err := s.Load("k")
				if err != nil {
					errs <- err
					return
				}
				if ok {
					if policy, known := byValue[string(held.Value)]; !known || policy != held.PolicyDigest ||
						s.Fingerprint("local", "k", held.Value) != held.Fingerprint {
						errs <- errors.New("a value was served under another value's record")
					}
					held.Wipe()
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	requireNoStray(t, f.store, "k", []byte("-for-"))
	// Every envelope is now at or below the stored version: all are replays,
	// deleted or not.
	for _, s := range sealed {
		env := s.env
		if _, err := f.store.Accept(f.key, &env, at); !errors.Is(err, ErrReplay) {
			t.Fatalf("version %d after the run: %v", env.Version, err)
		}
	}
}
