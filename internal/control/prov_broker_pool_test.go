// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// brokerFixture is a target holding one stored secret and the spec of a
// launch that uses it.
func brokerFixture(t *testing.T) (*provFixture, *fakeHost, Target, map[string]any) {
	f := newProv(t)
	h, target := f.enrolledTarget()
	p := f.profile("dev", false)
	h.poll()
	f.storeSecret(h, secretInput("model-api", f.sealFor(h, "model-api", "synthetic-credential-0123456789"), p.Name), nil)
	m := specMap("dev")
	m["secrets"] = []any{map[string]any{"ref": "model-api", "expose": map[string]any{"env": "MODEL_BASE_URL"}}}
	return f, h, target, m
}

// heldBlock is a launch's allocation: its block and whether it is released.
func heldBlock(t *testing.T, f *provFixture, launchID string) (uint32, bool) {
	t.Helper()
	var block uint32
	var released string
	if err := f.s.DB.QueryRow("SELECT block,released FROM broker_allocations WHERE launch_id=?", launchID).Scan(&block, &released); err != nil {
		t.Fatalf("launch %s holds no broker allocation: %v", launchID, err)
	}
	return block, released != ""
}

// launchPreferring is a launch id whose preferred block is block.
func launchPreferring(t *testing.T, block uint32) string {
	t.Helper()
	for i := 0; i < 1<<22; i++ {
		if id := fmt.Sprintf("%032x", i); brokerPreferredBlock(id) == block {
			return id
		}
	}
	t.Fatalf("no launch id prefers block %d", block)
	return ""
}

func inTx(t *testing.T, f *provFixture, run func(tx *sql.Tx)) {
	t.Helper()
	tx, err := f.s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	run(tx)
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// Two launches whose ids hash to one block used to get the same /29 on one
// host (the host then refused the second). The service now hands out the
// next free block, in order and wrapping, per target.
func TestBrokerBlocksAreAllocatedPerTargetInADeterministicOrder(t *testing.T) {
	f := newProv(t)
	seen := map[uint32]string{}
	var first, second string
	for i := 0; first == ""; i++ {
		id := fmt.Sprintf("%032x", i)
		if other, ok := seen[brokerPreferredBlock(id)]; ok {
			first, second = other, id
		}
		seen[brokerPreferredBlock(id)] = id
	}
	preferred := brokerPreferredBlock(first)
	inTx(t, f, func(tx *sql.Tx) {
		a := must(f.s.allocateBroker(tx, "target-a", first))
		b := must(f.s.allocateBroker(tx, "target-a", second))
		if a != brokerEndpointOf(preferred) || b != brokerEndpointOf(preferred%brokerBlocks+1) {
			t.Fatalf("a hash collision on one target: %+v %+v (preferred %d)", a, b, preferred)
		}
		// Another target's pool is its own.
		if c := must(f.s.allocateBroker(tx, "target-b", second+"b")); c == a && brokerPreferredBlock(second+"b") != preferred {
			t.Fatalf("target-b %+v", c)
		}
	})
	// The search wraps past the last block.
	late := uint32(brokerBlocks - 2)
	id := launchPreferring(t, late)
	inTx(t, f, func(tx *sql.Tx) {
		for b := late; b <= brokerBlocks; b++ {
			if _, err := tx.Exec("INSERT INTO broker_allocations(launch_id,target_id,block,allocated,released) VALUES(?,?,?,?,'')", fmt.Sprintf("fill-%d", b), "target-c", b, stamp()); err != nil {
				t.Fatal(err)
			}
		}
		if got := must(f.s.allocateBroker(tx, "target-c", id)); got != brokerEndpointOf(1) {
			t.Fatalf("the search did not wrap: %+v", got)
		}
	})
	// The planned endpoint is the block's: .2 the broker, .3 the target.
	if e := brokerEndpointOf(1); e.Subnet != "172.30.0.8/29" || e.Address != "172.30.0.10" || e.TargetAddress != "172.30.0.11" || e.Port != 8443 {
		t.Fatalf("block 1 is %+v", e)
	}
	if b, ok := brokerBlockOf("172.30.255.248/29"); !ok || b != brokerBlocks {
		t.Fatalf("the last block: %d %v", b, ok)
	}
	for _, bad := range []string{"172.30.0.0/29", "172.30.0.9/29", "172.31.0.8/29", "172.30.0.8/28", "x"} {
		if _, ok := brokerBlockOf(bad); ok {
			t.Errorf("%s is a block", bad)
		}
	}
}

func TestConcurrentLaunchesOnOneTargetGetDistinctBrokerNetworks(t *testing.T) {
	f, _, target, m := brokerFixture(t)
	const n = 12
	ops := make([]Operation, n)
	for i := range ops {
		ops[i] = f.launcher()
	}
	plans := make([]LaunchPlan, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			value, err := f.s.CreateLaunch(ops[i], specBytes(t, m))
			if errs[i] = err; err == nil {
				plans[i] = value.(map[string]any)["plan"].(LaunchPlan)
			}
		}(i)
	}
	wg.Wait()
	subnets := map[string]bool{}
	for i := range plans {
		if errs[i] != nil || plans[i].Broker == nil {
			t.Fatalf("launch %d: %v", i, errs[i])
		}
		subnets[plans[i].Broker.Subnet] = true
	}
	var held int
	f.s.DB.QueryRow("SELECT count(*) FROM broker_allocations WHERE target_id=? AND released=''", target.ID).Scan(&held)
	if len(subnets) != n || held != n {
		t.Fatalf("%d launches got %d broker networks (%d held)", n, len(subnets), held)
	}
}

func TestAnExhaustedBrokerPoolRefusesTheLaunchClearly(t *testing.T) {
	f, _, target, m := brokerFixture(t)
	inTx(t, f, func(tx *sql.Tx) {
		for b := 1; b <= brokerBlocks; b++ {
			if _, err := tx.Exec("INSERT INTO broker_allocations(launch_id,target_id,block,allocated,released) VALUES(?,?,?,?,'')", fmt.Sprintf("held-%d", b), target.ID, b, stamp()); err != nil {
				t.Fatal(err)
			}
		}
	})
	var before int
	f.s.DB.QueryRow("SELECT count(*) FROM launches").Scan(&before)
	_, err := f.s.CreateLaunch(f.launcher(), specBytes(t, m))
	if status, code, _ := errorResult(err); status != 409 || code != "broker_pool_exhausted" {
		t.Fatalf("an exhausted pool: %d %s %v", status, code, err)
	}
	var after int
	f.s.DB.QueryRow("SELECT count(*) FROM launches").Scan(&after)
	if after != before {
		t.Fatal("a refused launch was recorded")
	}
	// A dry run allocates nothing and still shows an example endpoint.
	if plan := must(f.s.PlanLaunch(f.launcher(), specBytes(t, m))).(map[string]any)["plan"].(LaunchPlan); plan.Broker == nil {
		t.Fatal("the dry run has no endpoint")
	}
	// One released block is enough, and it is the one handed out.
	if _, err = f.s.DB.Exec("UPDATE broker_allocations SET released=? WHERE launch_id='held-4321'", stamp()); err != nil {
		t.Fatal(err)
	}
	_, plan := f.launch(f.launcher(), m)
	if plan.Broker.Subnet != brokerEndpointOf(4321).Subnet {
		t.Fatalf("the freed block was not used: %+v", plan.Broker)
	}
}

// A block is reused only once the host has confirmed the launch's teardown
// (its receipt) or the launch never reached the host; a launch whose host
// went silent keeps its block until a late receipt arrives.
func TestABrokerBlockIsReusedOnlyAfterTheHostConfirmsTheTeardown(t *testing.T) {
	f, h, target, m := brokerFixture(t)
	running := func() (Launch, hostproto.Job) {
		l, _ := f.launch(f.launcher(), m)
		must(f.s.DecideLaunch(f.approver(), l.ID, true, DecisionInput{Reason: "Reviewed the broker rules"}))
		var job hostproto.Job
		for _, j := range h.poll() {
			if j.Type == hostproto.JobLaunch && j.LaunchID == l.ID {
				job = j
			}
		}
		e := ev(1, f, hostproto.EventState)
		e.State = StateRunning
		must(h.events(job.ID, e))
		return l, job
	}
	finish := func(job hostproto.Job) {
		r := ev(2, f, hostproto.EventResult)
		r.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "exited", Receipt: h.receipt(job, true)}
		must(h.events(job.ID, r))
	}

	// Ended with the host's receipt: released, and the block is handed out
	// again to a launch that prefers it.
	a, job := running()
	blockA, released := heldBlock(t, f, a.ID)
	if released {
		t.Fatal("a running launch released its block")
	}
	finish(job)
	if got := f.state(a.ID); got.State != StateStopped {
		t.Fatalf("launch a is %s", got.State)
	}
	if _, released = heldBlock(t, f, a.ID); !released {
		t.Fatal("a launch the host confirmed did not release its block")
	}
	reuse := launchPreferring(t, blockA)
	inTx(t, f, func(tx *sql.Tx) {
		if got := must(f.s.allocateBroker(tx, target.ID, reuse)); got != brokerEndpointOf(blockA) {
			t.Fatalf("the released block was not reused: %+v", got)
		}
		tx.Exec("UPDATE broker_allocations SET released=? WHERE launch_id=?", stamp(), reuse)
	})

	// Rejected (never reached the host): released at once.
	rejected, _ := f.launch(f.launcher(), m)
	must(f.s.DecideLaunch(f.approver(), rejected.ID, false, DecisionInput{Reason: "Not now"}))
	if _, released = heldBlock(t, f, rejected.ID); !released {
		t.Fatal("a rejected launch kept its block")
	}

	// The host goes silent: the launch fails lost_host and keeps its block,
	// so a launch that prefers it gets the next one.
	c, _ := running()
	f.advance(40 * time.Second)
	must(f.s.Sweep())
	if got := f.state(c.ID); got.State != StateFailed || got.EvidenceMissing != MissingLostHost {
		t.Fatalf("launch c is %s %s", got.State, got.EvidenceMissing)
	}
	blockC, released := heldBlock(t, f, c.ID)
	if released {
		t.Fatal("a launch whose host went silent released its block")
	}
	other := launchPreferring(t, blockC)
	inTx(t, f, func(tx *sql.Tx) {
		if got := must(f.s.allocateBroker(tx, target.ID, other)); got == brokerEndpointOf(blockC) {
			t.Fatal("a block still on a silent host was handed out")
		}
	})
	// The host returns and reports: the late receipt releases the block.
	stops := h.poll(c.ID)
	if len(stops) != 1 || stops[0].Type != hostproto.JobStop {
		t.Fatalf("stops %+v", stops)
	}
	r := ev(1, f, hostproto.EventResult)
	r.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "stopped", Receipt: h.receipt(stops[0], true)}
	must(h.events(stops[0].ID, r))
	if _, released = heldBlock(t, f, c.ID); !released {
		t.Fatal("a late receipt did not release the block")
	}
	// An allocation is released once and never rebound.
	if _, err := f.s.DB.Exec("UPDATE broker_allocations SET released='' WHERE launch_id=?", c.ID); err == nil {
		t.Fatal("a released block was taken back")
	}
	if _, err := f.s.DB.Exec("UPDATE broker_allocations SET block=1 WHERE launch_id=?", c.ID); err == nil {
		t.Fatal("an allocation was rebound")
	}
}

func TestSchemaTenRecordsTheBrokerNetworksOfExistingLaunches(t *testing.T) {
	f, h, target, m := brokerFixture(t)
	ended, _ := f.launch(f.launcher(), m)
	must(f.s.DecideLaunch(f.approver(), ended.ID, false, DecisionInput{Reason: "Not now"}))
	pending, plan := f.launch(f.launcher(), m)
	_ = h
	// Back to version 9: no allocation table.
	if _, err := f.s.DB.Exec("DROP TABLE broker_allocations; PRAGMA user_version=9;"); err != nil {
		t.Fatal(err)
	}
	if err := f.s.migrate(); err != nil {
		t.Fatal(err)
	}
	var version int
	f.s.DB.QueryRow("PRAGMA user_version").Scan(&version)
	if version != SchemaVersion {
		t.Fatalf("version %d", version)
	}
	block, released := heldBlock(t, f, pending.ID)
	if released || brokerEndpointOf(block) != *plan.Broker {
		t.Fatalf("the pending launch's block %d (released %v), plan %+v", block, released, plan.Broker)
	}
	if _, released = heldBlock(t, f, ended.ID); !released {
		t.Fatal("the rejected launch's block is held")
	}
	_, next := f.launch(f.launcher(), m)
	if next.Broker.Subnet == plan.Broker.Subnet {
		t.Fatal("a new launch got the block of a migrated one")
	}
	var targets int
	f.s.DB.QueryRow("SELECT count(*) FROM broker_allocations WHERE target_id=? AND released=''", target.ID).Scan(&targets)
	if targets != 2 {
		t.Fatalf("held %d", targets)
	}
}
