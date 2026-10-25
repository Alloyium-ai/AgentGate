// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"context"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/qualification"
	"golang.org/x/sys/unix"
)

const servicePrepareReplyLossProtocol = "agentgate.fixed-prepare-reply-loss.v1"
const servicePrepareRequest = "POST /fixture/prepare HTTP/1.1\r\nHost: fixture\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"

// The parent sends a complete request over the private authenticated session
// and never reads its reply. Keeping the socket open distinguishes lease expiry
// from HTTP disconnect cleanup. No start command or workload follows.
type serviceLifecyclePrepareReplyLoss struct {
	Protocol      string                           `json:"protocol"`
	Request       []byte                           `json:"request"`
	SentNS        uint64                           `json:"sent_mono_ns,string"`
	SentBytes     int                              `json:"sent_bytes"`
	ReadBytes     int                              `json:"read_bytes"`
	Quarantined   serviceLifecycleJournalReadback  `json:"quarantined"`
	Lease         serviceLifecycleWatchdogReadback `json:"lease"`
	Stopped       serviceLifecycleJournalReadback  `json:"stopped"`
	DomainEmptyNS uint64                           `json:"domain_empty_mono_ns,string"`
}

func readServiceLifecycleRecord(raw []byte) (lifecycle.Record, error) {
	var record lifecycle.Record
	err := lifecycle.DecodeTransport(bytes.NewReader(raw), &record)
	return record, err
}

// Wait for the node's reply without consuming it. The reply is written after
// preparation has committed; opening a read-only SQLite connection while the
// node is still preparing can otherwise contend with its transaction.
func serviceLifecycleReplyPending(connection net.Conn) (bool, error) {
	conn, ok := connection.(syscall.Conn)
	if !ok {
		return false, errors.New("the private fixture connection has no raw socket")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return false, err
	}
	var count int
	var socketErr error
	if err = raw.Control(func(fd uintptr) {
		var one [1]byte
		count, _, socketErr = unix.Recvfrom(int(fd), one[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
	}); err != nil {
		return false, err
	}
	if errors.Is(socketErr, unix.EAGAIN) || errors.Is(socketErr, unix.EWOULDBLOCK) {
		return false, nil
	}
	if socketErr != nil {
		return false, socketErr
	}
	if count == 0 {
		return false, errors.New("the private fixture connection closed before its reply")
	}
	return true, nil
}

func runServiceLifecyclePrepareReplyLoss(ctx context.Context, scene *serviceLifecycleScene, client *serviceLifecycleHTTPClient) error {
	loss := &serviceLifecyclePrepareReplyLoss{Protocol: servicePrepareReplyLossProtocol, Request: []byte(servicePrepareRequest)}
	scene.PrepareReplyLoss = loss
	loss.SentNS = serviceMono()
	for loss.SentBytes < len(loss.Request) {
		n, err := client.connection.Write(loss.Request[loss.SentBytes:])
		loss.SentBytes += n
		if err != nil || n == 0 {
			return errors.Join(errors.New("the fixed prepare request was not fully sent"), err)
		}
	}
	// The node must finish its transaction and write the reply before the
	// parent opens a second SQLite connection. MSG_PEEK preserves unread reply
	// custody while detecting that point.
	window, cancel := context.WithTimeout(ctx, time.Duration(scene.NodeConfig.PreparationLeaseMS)*time.Millisecond+7*time.Second)
	defer cancel()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		ready, err := serviceLifecycleReplyPending(client.connection)
		if err != nil {
			return err
		}
		if ready {
			break
		}
		select {
		case <-window.Done():
			return errors.New("the unread prepare reply was not produced before its lease expired")
		case <-tick.C:
		}
	}
	// Read-only journal and watchdog observations cannot consume the HTTP reply.
	for {
		row, err := readServiceLifecycleJournalRun(window, *scene, scene.Recipe.Spec.Binding.RunID)
		if err == nil {
			record, decodeErr := readServiceLifecycleRecord(row.Raw)
			if decodeErr == nil && record.State == "quarantined" {
				loss.Quarantined = row
				break
			}
		}
		select {
		case <-window.Done():
			return errors.New("the unread prepare reply did not leave a durable quarantine")
		case <-tick.C:
		}
	}
	var err error
	loss.Lease, err = readServiceLifecycleWatchdog(window, *scene)
	if err != nil || len(loss.Lease.Rows) != 1 || loss.Lease.Rows[0].State != "armed" {
		return errors.Join(errors.New("the unread prepare reply lacks an armed independent lease"), err)
	}
	for {
		row, readErr := readServiceLifecycleJournalRun(window, *scene, scene.Recipe.Spec.Binding.RunID)
		if readErr == nil {
			record, decodeErr := readServiceLifecycleRecord(row.Raw)
			if decodeErr == nil && record.State == "stopped" {
				domain, errno, pins := serviceLifecycleFinalState(scene.Recipe)
				if domain != "" && errno == int(unix.ENOENT) && len(pins) == 0 {
					loss.Stopped, loss.DomainEmptyNS = row, serviceMono()
					return nil
				}
			}
		}
		select {
		case <-window.Done():
			return errors.New("the unread prepare reply did not expire into an empty stopped domain")
		case <-tick.C:
		}
	}
}

func verifyServiceLifecyclePrepareJournal(row serviceLifecycleJournalReadback, scene serviceLifecycleScene) (lifecycle.Record, error) {
	var record lifecycle.Record
	if row.Path != scene.NodeConfig.Journal || row.Path != filepath.Join(scene.Recipe.Spec.OwnedRoot, "private/node.db") || !validServiceLifecycleDatabase(row.Before) || row.Before != row.After || row.StartedNS == 0 || row.FinishedNS < row.StartedNS || len(row.Raw) == 0 || len(row.Raw) > 2<<20 || uniqueJSON(row.Raw) != nil {
		return record, errors.New("the unread prepare journal custody differs")
	}
	record, err := readServiceLifecycleRecord(row.Raw)
	if err != nil {
		return record, err
	}
	binding := record.Binding
	expected := scene.Recipe.Spec.Binding
	expected.CgroupID = binding.CgroupID
	if binding.CgroupID == 0 || !reflect.DeepEqual(binding, expected) || row.RunID != binding.RunID || row.AgentID != binding.AgentID || row.NodeID != binding.NodeID || row.BootID != binding.BootID || row.Generation != binding.Generation || row.Revision != record.Revision {
		return record, errors.New("the unread prepare journal binding differs")
	}
	return record, nil
}

func verifyServiceLifecyclePrepareReplyLoss(request qualification.Request, result qualification.Result, receipt serviceLifecycleReceipt, scene serviceLifecycleScene) error {
	loss := scene.PrepareReplyLoss
	image, err := serviceLifecycleImageDigest(receipt.ServiceImage)
	if err != nil || scene.Recipe.Spec.Manifest.ImageDigest != image || verifyServiceLifecycleRecipe(request, scene.Recipe) != nil || scene.Start.Validate() != nil || !reflect.DeepEqual(scene.Start.Spec, scene.Recipe.Spec) {
		return errors.New("the unread prepare fixture binding differs")
	}
	if scene.Mode != "prepare-reply-loss" || loss == nil || loss.Protocol != servicePrepareReplyLossProtocol || !bytes.Equal(loss.Request, []byte(servicePrepareRequest)) || loss.SentBytes != len(loss.Request) || loss.ReadBytes != 0 || len(scene.Calls) != 0 || len(scene.Actors) != 0 || scene.Active.Protocol != "" || scene.Prepared.Protocol != "" || scene.NodeLoss != nil || scene.Loss != nil || scene.AuditFile != nil || len(scene.CleanupErrors) != 0 || scene.FinalDomainErrno != int(unix.ENOENT) || len(scene.FinalPins) != 0 {
		return errors.New("the unread prepare scene scope or cleanup differs")
	}
	if scene.NodeSnapshot.ExecutableSHA256 != request.Binding.ArtifactDigests["node"] || scene.NodeSnapshot.PID <= 1 || loss.SentNS < result.StartedMonoNS || loss.SentNS >= loss.Quarantined.StartedNS || loss.DomainEmptyNS < loss.Stopped.FinishedNS || loss.DomainEmptyNS > result.FinishedMonoNS {
		return errors.New("the unread prepare clocks or node executable differ")
	}
	quarantined, err := verifyServiceLifecyclePrepareJournal(loss.Quarantined, scene)
	if err != nil {
		return err
	}
	stopped, err := verifyServiceLifecyclePrepareJournal(loss.Stopped, scene)
	if err != nil {
		return err
	}
	if quarantined.State != "quarantined" || quarantined.Process != nil || quarantined.Authorization != nil || quarantined.Watchdog == nil || len(quarantined.Evidence) != 1 || lifecycle.VerifyReadback(quarantined.Evidence[0], quarantined.Binding, "quarantined") != nil || quarantined.PreparationDeadlineNS <= loss.Quarantined.FinishedNS || quarantined.PreparationDeadlineNS > quarantined.Binding.DeadlineNS {
		return errors.New("the unread prepare quarantine differs")
	}
	if loss.Lease.Path != scene.NodeConfig.WatchdogStore || !validServiceLifecycleDatabase(loss.Lease.Before) || loss.Lease.Before != loss.Lease.After || len(loss.Lease.Rows) != 1 || loss.Lease.Rows[0].State != "armed" || !reflect.DeepEqual(loss.Lease.Rows[0].Ack, *quarantined.Watchdog) || loss.Lease.FinishedNS < loss.Quarantined.FinishedNS || loss.Lease.FinishedNS >= quarantined.PreparationDeadlineNS || lifecycle.VerifyWatchdogAck(*quarantined.Watchdog, quarantined.Binding, scene.WatchdogPublic, loss.Lease.FinishedNS) != nil {
		return errors.New("the unread prepare independent lease differs")
	}
	if stopped.State != "stopped" || stopped.StopReason != "preparation-lease-expired" || stopped.Revision <= quarantined.Revision || !reflect.DeepEqual(stopped.Binding, quarantined.Binding) || stopped.Process != nil || stopped.Authorization != nil || loss.Stopped.StartedNS < quarantined.PreparationDeadlineNS || len(stopped.Evidence) < 2 || lifecycle.VerifyReadback(stopped.Evidence[len(stopped.Evidence)-1], stopped.Binding, "stopped") != nil || !stopped.Evidence[len(stopped.Evidence)-1].Empty || !stopped.Evidence[len(stopped.Evidence)-1].RightsRemoved {
		return errors.New("the unread prepare expiry stop differs")
	}
	return nil
}
