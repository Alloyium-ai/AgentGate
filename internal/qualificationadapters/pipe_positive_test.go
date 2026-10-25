//go:build agentgate_native_evidence

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// The retained actual actor supplies the base record sequence. A positive
// pipe claim must additionally bind both endpoint stats and the transferred
// byte to the exact successful pipe2 record.
func TestPositivePipeRecordRequiresBothEndpointsAndPayload(t *testing.T) {
	request, _, receipt := actualFixture(t)
	request.Document.Runtime.Seccomp.AllowSyscalls = append(request.Document.Runtime.Seccomp.AllowSyscalls, "pipe2")
	request.Document.Runtime.IPC.Pipes = []string{"create"}
	if err := candidateSupported(request); err != nil {
		t.Fatal(err)
	}
	index := -1
	for i, record := range receipt.Records {
		if record.ID == 14 {
			index = i
			break
		}
	}
	if index < 0 {
		t.Fatal("the retained actual actor lacks pipe2")
	}
	receipt.Records[index].Result, receipt.Records[index].Error = 0, 0
	base := func(id uint32, result int64) scalarRecord {
		return scalarRecord{ID: id, Result: result, PID: uint32(receipt.Active.PID)}
	}
	pipe := []scalarRecord{
		base(28, 0), base(29, unix.S_IFIFO|0600), base(30, 123456),
		base(31, 0), base(32, unix.S_IFIFO|0600), base(33, 123456),
		base(34, 1), base(35, 1), base(36, 0x5a),
	}
	receipt.Records = append(append(append([]scalarRecord{}, receipt.Records[:index+1]...), pipe...), receipt.Records[index+1:]...)
	check := func(records []scalarRecord) error {
		r := receipt
		r.Records = records
		var raw bytes.Buffer
		for _, record := range records {
			if err := binary.Write(&raw, binary.LittleEndian, record); err != nil {
				return err
			}
		}
		r.RawRecords = raw.Bytes()
		_, err := verifyRecords(request, r)
		return err
	}
	if err := check(receipt.Records); err != nil {
		t.Fatal("the bounded positive pipe record was rejected", err)
	}
	for name, changed := range map[string]func([]scalarRecord){
		"not a pipe":               func(records []scalarRecord) { records[index+2].Result = unix.S_IFSOCK },
		"different endpoint inode": func(records []scalarRecord) { records[index+6].Result++ },
		"changed payload":          func(records []scalarRecord) { records[index+9].Result++ },
		"failed pipe2":             func(records []scalarRecord) { records[index].Result = -1; records[index].Error = uint32(unix.EPERM) },
	} {
		t.Run(name, func(t *testing.T) {
			copyOf := append([]scalarRecord{}, receipt.Records...)
			changed(copyOf)
			if err := check(copyOf); err == nil {
				t.Fatal("changed positive pipe bytes passed")
			}
		})
	}
}

func TestPositiveCloneRecordRequiresChildWaitAndExit(t *testing.T) {
	request, _, receipt := listenerTargetFixture(t, "g")
	request.Document.Runtime.Seccomp.AllowSyscalls = append(request.Document.Runtime.Seccomp.AllowSyscalls, "clone", "wait4")
	if err := candidateSupported(request); err != nil {
		t.Fatal(err)
	}
	index := -1
	for i, record := range receipt.Records {
		if record.ID == 50 {
			index = i
			break
		}
	}
	if index < 0 {
		t.Fatal("the retained actor lacks its clone attempt")
	}
	child := int64(receipt.Active.PID + 1)
	records := append([]scalarRecord{}, receipt.Records...)
	records[index].Result, records[index].Error = child, 0
	wait := scalarRecord{ID: 53, Result: child, PID: uint32(receipt.Active.PID)}
	exit := scalarRecord{ID: 54, Result: 90 << 8, PID: uint32(receipt.Active.PID)}
	records = append(append(append([]scalarRecord{}, records[:index+1]...), wait, exit), records[index+1:]...)
	check := func(records []scalarRecord) error {
		r := receipt
		r.Records = records
		var raw bytes.Buffer
		for _, record := range records {
			if err := binary.Write(&raw, binary.LittleEndian, record); err != nil {
				return err
			}
		}
		r.RawRecords = raw.Bytes()
		_, err := verifyRecords(request, r)
		return err
	}
	if err := check(records); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func([]scalarRecord){
		"failed clone": func(r []scalarRecord) { r[index].Result, r[index].Error = -1, uint32(unix.EPERM) },
		"wrong wait":   func(r []scalarRecord) { r[index+1].Result++ },
		"wrong exit":   func(r []scalarRecord) { r[index+2].Result++ },
	} {
		t.Run(name, func(t *testing.T) {
			copyOf := append([]scalarRecord{}, records...)
			change(copyOf)
			if check(copyOf) == nil {
				t.Fatal("changed clone record passed")
			}
		})
	}
}
