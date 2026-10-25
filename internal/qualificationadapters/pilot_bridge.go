// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/dockerplacement"
	"golang.org/x/sys/unix"
)

// This readback covers the mounted one-task interface only. It does not
// qualify the bridge process image or the upstream token's API scope.
type pilotBridgeReadback struct {
	TaskID                int    `json:"task_id"`
	ProjectID             int    `json:"project_id"`
	Status                string `json:"status"`
	SocketDevice          uint64 `json:"socket_device,string"`
	SocketInode           uint64 `json:"socket_inode,string"`
	ForeignStatus         int    `json:"foreign_status"`
	UpstreamNoTokenStatus int    `json:"upstream_no_token_status"`
	TokenAbsent           bool   `json:"token_absent"`
	SnapshotValidUntil    string `json:"snapshot_valid_until"`
}

func samePilotBridge(before, after pilotBridgeReadback, taskID int) bool {
	return before.TaskID == taskID && after.TaskID == taskID &&
		before.ProjectID > 0 && after.ProjectID > 0 && before.Status != "" && after.Status != "" &&
		before.SocketDevice != 0 && before.SocketInode != 0 &&
		before.SocketDevice == after.SocketDevice && before.SocketInode == after.SocketInode &&
		before.ForeignStatus == http.StatusForbidden && after.ForeignStatus == http.StatusForbidden &&
		(before.UpstreamNoTokenStatus == http.StatusUnauthorized || before.UpstreamNoTokenStatus == http.StatusForbidden) &&
		before.UpstreamNoTokenStatus == after.UpstreamNoTokenStatus &&
		before.TokenAbsent && after.TokenAbsent &&
		before.SnapshotValidUntil != "" && after.SnapshotValidUntil != ""
}

type pilotSnapshot struct {
	TaskID     int
	ProjectID  int
	Status     string
	Title      string
	ValidUntil string
}

func (s pilotSnapshot) matches(id, projectID int, status, title string) bool {
	return id == s.TaskID && projectID == s.ProjectID && status == s.Status && title == s.Title
}

func pilotTaskSnapshot(root int, path string, taskID int, now time.Time) (pilotSnapshot, error) {
	empty := pilotSnapshot{}
	fd, err := unix.Openat2(root, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return empty, errors.New("the pilot task snapshot is absent")
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 ||
		stat.Mode&0777 != 0644 || stat.Nlink != 1 || stat.Size < 1 || stat.Size > 4096 {
		return empty, errors.New("the pilot task snapshot custody differs")
	}
	raw := make([]byte, stat.Size+1)
	n, err := unix.Read(fd, raw)
	if err != nil || n != int(stat.Size) || uniqueJSON(raw[:n]) != nil {
		return empty, errors.New("the pilot task snapshot bytes differ")
	}
	var snapshot struct {
		Protocol string `json:"protocol"`
		Task     struct {
			ID        int    `json:"id"`
			ProjectID int    `json:"project_id"`
			Status    string `json:"status"`
			Title     string `json:"title"`
		} `json:"task"`
		ValidUntil string `json:"valid_until"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw[:n]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&snapshot) != nil || snapshot.Protocol != "agentgate.taskboard-read.v1" ||
		snapshot.Task.ID != taskID || snapshot.Task.ProjectID < 1 || snapshot.Task.Status == "" ||
		len(snapshot.Task.Status) > 64 || snapshot.Task.Title == "" || len(snapshot.Task.Title) > 512 {
		return empty, errors.New("the pilot task snapshot scope differs")
	}
	until, err := time.Parse(time.RFC3339Nano, snapshot.ValidUntil)
	if err != nil || !now.Before(until) || until.After(now.Add(16*time.Second)) {
		return empty, errors.New("the pilot task snapshot is stale or unbounded")
	}
	return pilotSnapshot{TaskID: snapshot.Task.ID, ProjectID: snapshot.Task.ProjectID,
		Status: snapshot.Task.Status, Title: snapshot.Task.Title, ValidUntil: snapshot.ValidUntil}, nil
}

func probePilotBridge(ctx context.Context, target dockerplacement.Target, handles *dockerplacement.Handles) (*pilotBridgeReadback, error) {
	if handles == nil || handles.Root == nil || target.BridgePath == "" || target.BridgeTaskID < 1 || handles.Measurement.BridgeTaskID != target.BridgeTaskID || handles.Measurement.BridgeInode == 0 {
		return nil, errors.New("the measured pilot bridge mount is absent")
	}
	source := filepath.Join(target.BridgeSource, "taskboard.sock")
	inside := filepath.Join(strings.TrimPrefix(target.BridgePath, "/"), "taskboard.sock")
	socket, err := pilotBridgeSocket(source, int(handles.Root.Fd()), inside)
	if err != nil {
		return nil, err
	}
	fd, err := openPilotTargetPath(int(handles.Root.Fd()), "run/secrets/taskboard-token")
	if err == nil {
		_ = unix.Close(fd)
	}
	if !errors.Is(err, unix.ENOENT) {
		return nil, errors.New("the pilot target exposes a taskboard token path")
	}
	snapshot, err := pilotTaskSnapshot(int(handles.Root.Fd()), filepath.Join(strings.TrimPrefix(target.BridgePath, "/"), "task.json"), target.BridgeTaskID, time.Now())
	if err != nil {
		return nil, err
	}
	client := pilotBridgeClient(source)
	defer client.CloseIdleConnections()
	task, err := pilotBridgeRequest(ctx, client, "/task")
	if err != nil || task.status != http.StatusOK {
		return nil, errors.New("the live pilot task read failed")
	}
	var body struct {
		ID        int    `json:"id"`
		ProjectID int    `json:"project_id"`
		Status    string `json:"status"`
		Title     string `json:"title"`
	}
	if json.Unmarshal(task.body, &body) != nil || body.ID != target.BridgeTaskID || body.ProjectID < 1 || body.Status == "" || len(body.Status) > 64 || body.Title == "" || len(body.Title) > 512 {
		return nil, errors.New("the live pilot task scope differs")
	}
	if !snapshot.matches(body.ID, body.ProjectID, body.Status, body.Title) {
		return nil, errors.New("the mounted task and authenticated live task differ")
	}
	foreign := 1
	if target.BridgeTaskID == foreign {
		foreign++
	}
	other, err := pilotBridgeRequest(ctx, client, "/api/tasks/"+strconv.Itoa(foreign))
	if err != nil || other.status != http.StatusForbidden {
		return nil, errors.New("the pilot bridge accepted a foreign task route")
	}
	probe, err := pilotBridgeRequest(ctx, client, "/auth-probe")
	var unauthenticated struct {
		TaskID         int `json:"task_id"`
		UpstreamStatus int `json:"upstream_status"`
	}
	if err != nil || probe.status != http.StatusOK || json.Unmarshal(probe.body, &unauthenticated) != nil ||
		unauthenticated.TaskID != target.BridgeTaskID ||
		(unauthenticated.UpstreamStatus != http.StatusUnauthorized && unauthenticated.UpstreamStatus != http.StatusForbidden) {
		return nil, errors.New("the exact upstream task is not credential-gated")
	}
	return &pilotBridgeReadback{TaskID: body.ID, ProjectID: body.ProjectID, Status: body.Status, SocketDevice: uint64(socket.Dev), SocketInode: socket.Ino, ForeignStatus: other.status, UpstreamNoTokenStatus: unauthenticated.UpstreamStatus, TokenAbsent: true, SnapshotValidUntil: snapshot.ValidUntil}, nil
}

// The retained root descriptor prevents a restarted container or reused PID
// from changing the filesystem while the bridge is being read back. Symlinks
// and magic links must not redirect either the socket or the token lookup.
func openPilotTargetPath(root int, relative string) (int, error) {
	return unix.Openat2(root, relative, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
}

func pilotBridgeSocket(source string, root int, inside string) (unix.Stat_t, error) {
	var a, b unix.Stat_t
	fd, err := openPilotTargetPath(root, inside)
	if err != nil {
		return a, errors.New("the pilot bridge socket is absent from the measured root")
	}
	defer unix.Close(fd)
	if unix.Lstat(source, &a) != nil || unix.Fstat(fd, &b) != nil ||
		a.Mode&unix.S_IFMT != unix.S_IFSOCK || b.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		a.Dev != b.Dev || a.Ino != b.Ino || a.Uid != 0 || a.Gid != 65534 || a.Mode&0777 != 0660 ||
		a.Mode != b.Mode {
		return a, errors.New("the pilot bridge socket mount or custody differs")
	}
	return a, nil
}

type pilotHTTPResponse struct {
	status int
	body   []byte
}

func pilotBridgeClient(path string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("the pilot bridge redirected a request")
	}, Transport: &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", path)
	}}}
}

func pilotBridgeRequest(ctx context.Context, client *http.Client, path string) (pilotHTTPResponse, error) {
	var out pilotHTTPResponse
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://pilot"+path, nil)
	if err != nil {
		return out, err
	}
	response, err := client.Do(request)
	if err != nil {
		return out, err
	}
	defer response.Body.Close()
	if response.ContentLength > 4096 {
		return out, errors.New("the pilot bridge response is oversized")
	}
	out.status = response.StatusCode
	out.body, err = io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(out.body) > 4096 {
		return pilotHTTPResponse{}, errors.New("the pilot bridge response exceeds its bound")
	}
	return out, nil
}
