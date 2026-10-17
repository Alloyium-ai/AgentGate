// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"encoding/binary"
	"errors"
	"math"
)

// LifecycleProcess names an observed actor. A caller must verify its actual
// start time and cgroup before it uses the record as process-domain evidence.
type LifecycleProcess struct {
	Role         uint32 `json:"role"`
	PID          uint32 `json:"pid"`
	ParentPID    uint32 `json:"parent_pid"`
	ChildPID     uint32 `json:"child_pid"`
	GettidResult int32  `json:"gettid_result"`
}

// DecodeLifecycleRecords checks the fixed worker wire format and tree edges.
// It does not prove that a process remains live or inside a particular domain.
func DecodeLifecycleRecords(raw []byte) ([]LifecycleProcess, error) {
	if len(raw) != 96 {
		return nil, errors.New("the lifecycle worker requires three exact records")
	}
	actors := make([]LifecycleProcess, 3)
	roles := map[uint32]bool{}
	pids := map[uint32]bool{}
	for offset := 0; offset < len(raw); offset += 32 {
		record := raw[offset : offset+32]
		magic := binary.LittleEndian.Uint32(record)
		role := binary.LittleEndian.Uint32(record[4:])
		pid := binary.LittleEndian.Uint32(record[8:])
		parent := binary.LittleEndian.Uint32(record[12:])
		child := int64(binary.LittleEndian.Uint64(record[16:]))
		errno := binary.LittleEndian.Uint32(record[24:])
		gettid := int32(binary.LittleEndian.Uint32(record[28:]))
		if magic != 0x41474c32 || role < 1 || role > 3 || roles[role] || pid <= 1 || pid > math.MaxInt32 || pids[pid] || parent < 1 || parent > math.MaxInt32 || child < 0 || child > math.MaxInt32 || errno != 0 || gettid == 0 {
			return nil, errors.New("the lifecycle worker record identity or outcome differs")
		}
		actors[role-1] = LifecycleProcess{Role: role, PID: pid, ParentPID: parent, ChildPID: uint32(child), GettidResult: gettid}
		roles[role], pids[pid] = true, true
	}
	if actors[0].ChildPID != actors[1].PID || actors[1].ParentPID != actors[0].PID || actors[1].ChildPID != actors[2].PID || actors[2].ParentPID != actors[1].PID || actors[2].ChildPID != 0 {
		return nil, errors.New("the lifecycle worker descendant edges differ")
	}
	return actors, nil
}
