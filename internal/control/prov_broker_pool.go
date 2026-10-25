// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"database/sql"
	"net/netip"
	"strconv"
)

// Broker network allocation. Every launch with secrets gets its own /29 of
// brokerPool on its target (8191 blocks; block 0 is never used). The service
// records each one in broker_allocations, so two launches on one target never
// get the same block while either may still have a broker network on its
// host: a launch first asks for the block its id hashes to (the same block
// the id always derived), then the next free one in order, wrapping. A block
// is released when the launch ends with the host's receipt (the host tears
// its broker down before it reports), when the launch ends without ever
// reaching its host (evidence_missing not_started), when a late receipt
// arrives for a launch that ended without one, or when the target is retired.
// A launch whose host went silent keeps its block. The host still refuses an
// endpoint that overlaps a network it has.

const brokerBlocks = 8191

// brokerPreferredBlock is the block a launch id hashes to.
func brokerPreferredBlock(launchID string) uint32 {
	sum := digest([]byte("agentgate.broker-network.v1\x00" + launchID))
	n, _ := strconv.ParseUint(sum[:8], 16, 32)
	return uint32(n%brokerBlocks) + 1
}

// brokerEndpointOf is the endpoint of one block: .2 the broker, .3 the target.
func brokerEndpointOf(block uint32) PlanBroker {
	base := netip.MustParsePrefix(brokerPoolText).Addr().As4()
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | block*8
	addr := func(i uint32) netip.Addr {
		x := v + i
		return netip.AddrFrom4([4]byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)})
	}
	return PlanBroker{Address: addr(2).String(), Port: brokerPort, Subnet: netip.PrefixFrom(addr(0), 29).String(), TargetAddress: addr(3).String()}
}

// brokerBlockOf is the block of a planned broker subnet, if it is one.
func brokerBlockOf(subnet string) (uint32, bool) {
	p, err := netip.ParsePrefix(subnet)
	pool := netip.MustParsePrefix(brokerPoolText)
	if err != nil || p.Bits() != 29 || !p.Addr().Is4() || !pool.Contains(p.Addr()) || p.Masked() != p {
		return 0, false
	}
	a, b := p.Addr().As4(), pool.Addr().As4()
	offset := (uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])) - (uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]))
	block := offset / 8
	return block, block >= 1 && block <= brokerBlocks
}

// allocateBroker reserves a block of the target's pool for a new launch in
// the caller's transaction (the launch's creation): the preferred block if it
// is free, else the next free one. The unique index on the active blocks of a
// target backs the search.
func (s *Store) allocateBroker(tx *sql.Tx, targetID, launchID string) (PlanBroker, error) {
	rows, err := tx.Query("SELECT block FROM broker_allocations WHERE target_id=? AND released=''", targetID)
	if err != nil {
		return PlanBroker{}, err
	}
	used := map[uint32]bool{}
	for rows.Next() {
		var b uint32
		if err = rows.Scan(&b); err != nil {
			rows.Close()
			return PlanBroker{}, err
		}
		used[b] = true
	}
	if err = rows.Close(); err != nil {
		return PlanBroker{}, err
	}
	start := brokerPreferredBlock(launchID)
	for i := uint32(0); i < brokerBlocks; i++ {
		block := (start-1+i)%brokerBlocks + 1
		if used[block] {
			continue
		}
		if _, err = tx.Exec("INSERT INTO broker_allocations(launch_id,target_id,block,allocated,released) VALUES(?,?,?,?,'')", launchID, targetID, block, stamp()); err != nil {
			return PlanBroker{}, err
		}
		return brokerEndpointOf(block), nil
	}
	return PlanBroker{}, fail(409, "broker_pool_exhausted", "Every broker network of the target is held by a launch that has not ended or whose host has not confirmed its teardown ("+strconv.Itoa(brokerBlocks)+" of "+brokerPoolText+"). Stop launches on the target, or wait for their hosts to report, then launch again.")
}

// releaseBroker frees the launch's block, if it holds one.
func releaseBroker(tx *sql.Tx, launchID string) error {
	_, err := tx.Exec("UPDATE broker_allocations SET released=? WHERE launch_id=? AND released=''", stamp(), launchID)
	return err
}

// releaseTargetBrokers frees every block of a retired target.
func releaseTargetBrokers(tx *sql.Tx, targetID string) error {
	_, err := tx.Exec("UPDATE broker_allocations SET released=? WHERE target_id=? AND released=''", stamp(), targetID)
	return err
}

// brokerReleasable says whether a launch that reached a terminal state with
// this receipt and evidence_missing reason no longer has a broker network on
// its host.
func brokerReleasable(receipt, missing string) bool {
	return receipt != "" || missing == MissingNotStarted
}

// backfillBrokerAllocations records the blocks of launches created before
// version 10: the block each plan names, held unless the launch ended in a
// way that released it. When two existing launches on one target hold the
// same block, the earlier one keeps the record (the host refuses the
// overlap, as before).
func backfillBrokerAllocations(tx *sql.Tx) error {
	rows, err := tx.Query("SELECT id,target_id,created,state,receipt,evidence_missing,COALESCE(json_extract(plan,'$.broker.subnet'),'') FROM launches WHERE json_valid(plan) ORDER BY created,id")
	if err != nil {
		return err
	}
	type held struct{ id, target, created, released string }
	var all []held
	blocks := map[string]uint32{}
	for rows.Next() {
		var h held
		var state, receipt, missing, subnet string
		if err = rows.Scan(&h.id, &h.target, &h.created, &state, &receipt, &missing, &subnet); err != nil {
			rows.Close()
			return err
		}
		block, ok := brokerBlockOf(subnet)
		if !ok {
			continue
		}
		if TerminalState(state) && brokerReleasable(receipt, missing) {
			h.released = stamp()
		}
		blocks[h.id] = block
		all = append(all, h)
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, h := range all {
		if _, err = tx.Exec("INSERT OR IGNORE INTO broker_allocations(launch_id,target_id,block,allocated,released) VALUES(?,?,?,?,?)", h.id, h.target, blocks[h.id], h.created, h.released); err != nil {
			return err
		}
	}
	return nil
}
