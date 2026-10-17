// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodeapi"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/requestproof"
)

type enrollmentCall struct {
	Name       string             `json:"name"`
	Enrollment nodeapi.Enrollment `json:"enrollment"`
	Token      string             `json:"token"`
	Body       []byte             `json:"body"`
	Method     string             `json:"method"`
	Path       string             `json:"path"`
	Status     int                `json:"status"`
	Response   []byte             `json:"response"`
	MonoNS     uint64             `json:"mono_ns,string"`
}
type enrollmentReceipt struct {
	AgentKey             []byte           `json:"agent_key"`
	PeerUID              uint32           `json:"peer_uid"`
	PeerGID              uint32           `json:"peer_gid"`
	SocketMode           uint32           `json:"socket_mode"`
	SocketUID            uint32           `json:"socket_uid"`
	SocketGID            uint32           `json:"socket_gid"`
	Calls                []enrollmentCall `json:"calls"`
	RuntimeCalls         []enrollmentCall `json:"runtime_calls"`
	PersistedReplayError string           `json:"persisted_replay_error"`
	ServerError          string           `json:"server_error"`
	SocketRemoved        bool             `json:"socket_removed"`
}
type serviceEnrollments struct {
	mu      sync.RWMutex
	current nodeapi.Enrollment
}

func (r *serviceEnrollments) Resolve(_ context.Context, id string) (nodeapi.Enrollment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if id != r.current.AgentID {
		return nodeapi.Enrollment{}, errors.New("the subject is not enrolled")
	}
	return r.current, nil
}
func (r *serviceEnrollments) set(e nodeapi.Enrollment) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.current = e
}

// Every proof opens the real durable journal again. No in-memory nonce map can
// produce the replay witness.
type serviceProofJournal struct{ path string }

func (s serviceProofJournal) ConsumeProof(ctx context.Context, subject, nonce string, issued int64) error {
	journal, err := lifecycle.OpenJournal(s.path)
	if err != nil {
		return err
	}
	defer journal.Close()
	return journal.ConsumeProof(ctx, subject, nonce, issued)
}

// Generation uses the actual journal. Workload operations remain unavailable;
// this actor cannot release a process or substitute a qualification report.
type serviceAuthOperations struct{ path, node, boot string }

func (s serviceAuthOperations) GenerationFloor(ctx context.Context, agent string) (uint64, error) {
	journal, err := lifecycle.OpenJournal(s.path)
	if err != nil {
		return 0, err
	}
	defer journal.Close()
	return journal.GenerationFloor(ctx, agent, s.node, s.boot)
}
func (serviceAuthOperations) Target(context.Context) (policy.VerifiedTarget, error) {
	return policy.VerifiedTarget{}, errors.New("qualification is unavailable")
}
func (serviceAuthOperations) Prepare(context.Context, lifecycle.PrepareRequest) (lifecycle.PrepareResponse, error) {
	return lifecycle.PrepareResponse{}, errors.New("workload release is unavailable in the identity actor")
}
func (serviceAuthOperations) Run(context.Context, lifecycle.RunRequest) (lifecycle.Terminal, error) {
	return lifecycle.Terminal{}, errors.New("workload release is unavailable in the identity actor")
}
func (serviceAuthOperations) Stop(context.Context, lifecycle.StopRequest) (lifecycle.StopResponse, error) {
	return lifecycle.StopResponse{}, errors.New("the identity actor owns no workload")
}
func (serviceAuthOperations) Status(context.Context, string, string) (lifecycle.JobStatus, error) {
	return lifecycle.JobStatus{}, errors.New("the identity actor owns no workload")
}

func (a *serviceIdentity) runEnrollment(ctx context.Context, request qualification.Request, root string) (out enrollmentReceipt, err error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return out, err
	}
	defer clear(private)
	out.AgentKey, out.PeerUID, out.PeerGID = public, uint32(os.Getuid()), uint32(os.Getgid())
	baseline := nodeapi.Enrollment{AgentID: "qualification-agent", AgentKey: base64.RawURLEncoding.EncodeToString(public), PeerUID: out.PeerUID, PeerGID: out.PeerGID, Enabled: true, Runtimes: map[string]nodeapi.RuntimeArtifact{}}
	enrollments := &serviceEnrollments{current: baseline}
	journalPath := filepath.Join(root, "proofs.db")
	journal, err := lifecycle.OpenJournal(journalPath)
	if err != nil {
		return out, err
	}
	if err = journal.Close(); err != nil {
		return out, err
	}
	proofs := serviceProofJournal{path: journalPath}
	socket := filepath.Join(root, "node.sock")
	server, err := nodeapi.New(nodeapi.Config{Identity: lifecycle.Identity{NodeID: request.Binding.NodeID, BootID: request.Binding.BootID}, SocketPath: socket, SocketGID: out.PeerGID, ReadHeaderTimeout: time.Second, RequestTimeout: 2 * time.Second, ShutdownTimeout: time.Second, Clock: lifecycle.MonotonicClock{}}, enrollments, proofs, serviceAuthOperations{path: journalPath, node: request.Binding.NodeID, boot: request.Binding.BootID})
	if err != nil {
		return out, err
	}
	serverCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- server.Serve(serverCtx) }()
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	defer func() {
		transport.CloseIdleConnections()
		cancel()
		out.ServerError = serviceError(<-done)
		_, e := os.Lstat(socket)
		out.SocketRemoved = os.IsNotExist(e)
		if out.ServerError != "" || !out.SocketRemoved {
			err = errors.Join(err, errors.New("the private enrollment server cleanup is incomplete"))
		}
	}()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		info, e := os.Lstat(socket)
		if e == nil {
			out.SocketMode = uint32(info.Mode().Perm())
			var st syscallStat
			if e = readSocketStat(socket, &st); e != nil {
				return out, e
			}
			out.SocketUID, out.SocketGID = st.UID, st.GID
			break
		}
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case e := <-done:
			done <- e
			return out, errors.New("the private enrollment server did not start")
		case <-deadline.C:
			return out, errors.New("the private enrollment socket deadline expired")
		case <-ticker.C:
		}
	}
	path := "/v1/agents/" + baseline.AgentID + "/generation"
	sign := func(body []byte) string {
		return requestproof.Sign(baseline.AgentID, "GET", path, lifecycle.NodeAudience(request.Binding.NodeID), request.Binding.BootID, body, private)
	}
	token := sign(nil)
	for _, name := range []string{"enrolled-proof", "proof-replay", "wrong-peer-uid", "wrong-peer-gid", "unenrolled-subject", "disabled-enrollment", "wrong-key", "body-substitution"} {
		current := baseline
		c := enrollmentCall{Name: name, Enrollment: baseline, Token: sign(nil), Method: "GET", Path: path}
		switch name {
		case "enrolled-proof", "proof-replay":
			c.Token = token
		case "wrong-peer-uid":
			current.PeerUID++
		case "wrong-peer-gid":
			current.PeerGID++
		case "unenrolled-subject":
			current.AgentID += "-other"
		case "disabled-enrollment":
			current.Enabled = false
		case "wrong-key":
			other, otherPrivate, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				return out, e
			}
			clear(otherPrivate)
			current.AgentKey = base64.RawURLEncoding.EncodeToString(other)
		case "body-substitution":
			c.Body = []byte("substituted-body")
		}
		c.Enrollment = current
		enrollments.set(current)
		httpRequest, e := http.NewRequestWithContext(ctx, c.Method, "http://private-node"+c.Path, bytes.NewReader(c.Body))
		if e != nil {
			return out, e
		}
		httpRequest.Header.Set("Authorization", "Alloyium-Proof "+c.Token)
		response, e := client.Do(httpRequest)
		if e != nil {
			return out, e
		}
		c.Status = response.StatusCode
		c.Response, e = io.ReadAll(io.LimitReader(response.Body, 65537))
		response.Body.Close()
		c.MonoNS = serviceMono()
		if e != nil || len(c.Response) > 65536 {
			return out, errors.New("the enrollment response exceeds its bound")
		}
		out.Calls = append(out.Calls, c)
	}
	claims, e := requestproof.Parse(token)
	if e != nil {
		return out, e
	}
	out.PersistedReplayError = serviceError(proofs.ConsumeProof(ctx, claims.Subject, claims.Nonce, claims.Time))
	out.RuntimeCalls, err = runServiceRuntimes(ctx, request, root, baseline, private, enrollments, client)
	if err != nil {
		return out, err
	}
	return out, nil
}

type syscallStat struct{ UID, GID uint32 }
