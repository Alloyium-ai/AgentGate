// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/url"
	"path/filepath"
	"reflect"

	"alloyium.local/kernel-poc/internal/lifecycle"
	"golang.org/x/sys/unix"
)

type serviceLifecycleDatabaseIdentity struct {
	Device uint64 `json:"device,string"`
	Inode  uint64 `json:"inode,string"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mode   uint32 `json:"mode"`
	Links  uint64 `json:"links,string"`
}

type serviceLifecycleWatchdogReadback struct {
	Protocol   string                           `json:"protocol"`
	Path       string                           `json:"path"`
	Before     serviceLifecycleDatabaseIdentity `json:"before"`
	After      serviceLifecycleDatabaseIdentity `json:"after"`
	StartedNS  uint64                           `json:"started_mono_ns,string"`
	FinishedNS uint64                           `json:"finished_mono_ns,string"`
	Rows       []lifecycle.WatchdogLease        `json:"rows"`
}

func serviceLifecycleDatabaseStat(path string) (serviceLifecycleDatabaseIdentity, error) {
	var out serviceLifecycleDatabaseIdentity
	if err := protectedDirectory(filepath.Dir(path)); err != nil {
		return out, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return out, err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return out, err
	}
	out = serviceLifecycleDatabaseIdentity{Device: uint64(stat.Dev), Inode: stat.Ino, UID: stat.Uid, GID: stat.Gid, Mode: stat.Mode, Links: uint64(stat.Nlink)}
	if !validServiceLifecycleDatabase(out) {
		return out, errors.New("the actual watchdog database custody differs")
	}
	return out, nil
}

func validServiceLifecycleDatabase(stat serviceLifecycleDatabaseIdentity) bool {
	return stat.Device != 0 && stat.Inode != 0 && stat.UID == 0 && stat.Links == 1 && stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Mode&077 == 0
}

func readServiceLifecycleWatchdog(ctx context.Context, scene serviceLifecycleScene) (out serviceLifecycleWatchdogReadback, err error) {
	out.Protocol = "agentgate.fixture-watchdog-readback.v1"
	out.Path = scene.NodeConfig.WatchdogStore
	out.StartedNS = serviceMono()
	defer func() { out.FinishedNS = serviceMono() }()
	if out.Path != filepath.Join(scene.Recipe.Spec.OwnedRoot, "private/watchdog.db") {
		return out, errors.New("the fixture watchdog store path differs")
	}
	out.Before, err = serviceLifecycleDatabaseStat(out.Path)
	if err != nil {
		return out, err
	}
	out.Rows, err = readServiceLifecycleWatchdogRows(ctx, out.Path)
	if err != nil {
		return out, err
	}
	out.After, err = serviceLifecycleDatabaseStat(out.Path)
	if err == nil && out.Before != out.After {
		err = errors.New("the actual watchdog database identity changed")
	}
	return out, err
}

func verifyServiceLifecycleWatchdog(scene serviceLifecycleScene, cutoff uint64) error {
	r := scene.WatchdogState
	if r == nil || r.Protocol != "agentgate.fixture-watchdog-readback.v1" || r.Path != filepath.Join(scene.Recipe.Spec.OwnedRoot, "private/watchdog.db") || r.Path != scene.NodeConfig.WatchdogStore || !validServiceLifecycleDatabase(r.Before) || r.Before != r.After || r.StartedNS == 0 || r.FinishedNS < r.StartedNS || r.FinishedNS >= cutoff || len(r.Rows) != 1 || scene.Active.Record.Watchdog == nil {
		return errors.New("the actual active watchdog store readback differs")
	}
	row := r.Rows[0]
	if row.State != "active" || row.Revision == 0 || row.NoDomain || row.RetiredBootID != "" || row.EffectiveDeadlineNS != cutoff || row.HeartbeatDeadlineNS > cutoff || row.HeartbeatDeadlineNS <= r.FinishedNS || row.PreparationDeadlineNS != scene.Prepared.Record.PreparationDeadlineNS || !reflect.DeepEqual(row.Ack, *scene.Active.Record.Watchdog) || !reflect.DeepEqual(row.Ack.Binding, scene.Active.Record.Binding) || row.Ack.Daemon.PID != scene.NodeSnapshot.PID || row.Ack.Daemon.StartTimeTicks != scene.NodeSnapshot.StartTimeTicks || row.Ack.WatchdogID != "watchdog-"+digestJSON(scene.Recipe.Spec)[:20] || lifecycle.VerifyWatchdogAck(row.Ack, scene.Active.Record.Binding, scene.WatchdogPublic, r.FinishedNS) != nil {
		return errors.New("the actual watchdog activation lease differs")
	}
	starts := 0
	for _, call := range scene.Calls {
		if call.Path == "/fixture/start" {
			starts++
			if call.Status != 200 || call.MonoNS >= r.StartedNS {
				return errors.New("the watchdog store readback precedes activation")
			}
		}
	}
	if starts != 1 {
		return errors.New("the watchdog activation exchange is absent or repeated")
	}
	return nil
}

// The live watchdog owns all schema and lease writes. This handle can only read.
func openServiceLifecycleWatchdogDatabase(ctx context.Context, path string) (*sql.DB, error) {
	address := url.URL{Scheme: "file", Path: path}
	query := url.Values{"mode": {"ro"}, "_pragma": {"busy_timeout(5000)"}}
	address.RawQuery = query.Encode()
	database, err := sql.Open("sqlite", address.String())
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	var applicationID int
	if err = database.QueryRowContext(ctx, "PRAGMA application_id").Scan(&applicationID); err != nil || applicationID != 1095191619 {
		_ = database.Close()
		return nil, errors.New("the existing watchdog database marker differs")
	}
	return database, nil
}

func readServiceLifecycleWatchdogRows(ctx context.Context, path string) (out []lifecycle.WatchdogLease, err error) {
	database, err := openServiceLifecycleWatchdogDatabase(ctx, path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, database.Close()) }()
	rows, err := database.QueryContext(ctx, "SELECT run_id,state,revision,record FROM watchdog_leases WHERE state IN ('reserved','armed','active') ORDER BY run_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out = []lifecycle.WatchdogLease{}
	for rows.Next() {
		var run, state, raw string
		var revision uint64
		if err = rows.Scan(&run, &state, &revision, &raw); err != nil {
			return out, err
		}
		var lease lifecycle.WatchdogLease
		if lifecycle.DecodeTransport(bytes.NewReader([]byte(raw)), &lease) != nil || lease.Ack.Binding.RunID != run || lease.State != state || lease.Revision != revision || revision == 0 {
			return out, errors.New("the actual watchdog row columns differ")
		}
		out = append(out, lease)
	}
	return out, rows.Err()
}
