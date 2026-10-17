// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodeapi

import (
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/requestproof"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type resolverFixture struct {
	enrollment Enrollment
	calls      atomic.Int64
}

func (r *resolverFixture) Resolve(context.Context, string) (Enrollment, error) {
	r.calls.Add(1)
	return r.enrollment, nil
}

type fixedClock struct{}

func (fixedClock) NowNS() (uint64, error) { return 1, nil }

type operationsFixture struct {
	inventoryError  atomic.Bool
	generationError atomic.Bool
	generationValue atomic.Uint64
	target          policy.VerifiedTarget
	targetMissing   atomic.Bool
	panicRun        atomic.Bool
	prepares        atomic.Int64
	runs            atomic.Int64
	stops           atomic.Int64
	binding         lifecycle.Binding
	required        []string
}

func (o *operationsFixture) Target(context.Context) (policy.VerifiedTarget, error) {
	if o.targetMissing.Load() {
		return policy.VerifiedTarget{}, errors.New("test-only target unavailable")
	}
	return o.target, nil
}
func (o *operationsFixture) evidence(binding lifecycle.Binding, phase string) lifecycle.Evidence {
	evidence := lifecycle.Evidence{Binding: binding, Phase: phase, Quarantined: true, MandatoryHooks: true, Empty: true, ReadbackDigest: strings.Repeat("f", 64), Capabilities: map[string]lifecycle.Capability{}}
	for _, id := range o.required {
		evidence.Capabilities[id] = lifecycle.Capability{State: "qualified", Mechanisms: []string{"unit-fixture-only"}, EvidenceDigest: strings.Repeat("e", 64)}
	}
	if phase == "stopped" {
		evidence.Quarantined = false
		evidence.Terminated = true
		evidence.RightsRemoved = true
	}
	evidence.Digest = lifecycle.EvidenceDigest(evidence)
	return evidence
}
func (o *operationsFixture) Prepare(_ context.Context, request lifecycle.PrepareRequest) (lifecycle.PrepareResponse, error) {
	o.prepares.Add(1)
	binding := request.Binding
	binding.CgroupID = 100
	streams := []jobaudit.Stream{}
	for _, name := range []string{"files", "peers", "sockets", "custody", "process"} {
		format := jobaudit.ResourceFormats()[name]
		streams = append(streams, jobaudit.Stream{Name: name, Kind: "resource", Version: format.Version, ArtifactDigest: binding.ArtifactDigests["node"]})
	}
	streams = append(streams, jobaudit.Stream{Name: "syscalls", Kind: "observation", Version: "syscalls104.v1", ArtifactDigest: binding.ArtifactDigests["node"]})
	header := jobaudit.Header{Protocol: jobaudit.HeaderProtocol, Binding: binding, DocumentDigest: binding.PolicyDigest, QualificationDigest: strings.Repeat("7", 64), RequiredCapabilities: o.required, RequiredStreams: streams, CreatedMonoNS: 1}
	raw, _ := jobaudit.HeaderBytes(header)
	digest, _ := jobaudit.HeaderDigest(header)
	return lifecycle.PrepareResponse{Protocol: lifecycle.PreparedProtocol, Binding: binding, ManifestDigest: binding.JobDigest, PreparationDeadlineNS: 500, Evidence: o.evidence(binding, "quarantined"), AuditHeader: raw, AuditHeaderDigest: digest}, nil
}
func (o *operationsFixture) Run(_ context.Context, request lifecycle.RunRequest) (lifecycle.Terminal, error) {
	o.runs.Add(1)
	if o.panicRun.Load() {
		panic("synthetic-private-runtime-detail")
	}
	return lifecycle.Terminal{Protocol: lifecycle.TerminalProtocol, Binding: request.Authorization.Binding, State: "completed", DomainEmpty: true, RightsRemoved: true, EvidenceDigest: strings.Repeat("d", 64), EvidenceVerdict: "VALID_COMPLETE"}, nil
}
func (o *operationsFixture) Status(_ context.Context, agent, run string) (lifecycle.JobStatus, error) {
	return lifecycle.JobStatus{Protocol: "agentgate.job.status.v1", Record: lifecycle.Record{Binding: o.binding, State: "stopped"}}, nil
}
func (o *operationsFixture) Stop(_ context.Context, request lifecycle.StopRequest) (lifecycle.StopResponse, error) {
	o.stops.Add(1)
	return lifecycle.StopResponse{Protocol: lifecycle.StoppedProtocol, Binding: request.Binding, Evidence: o.evidence(request.Binding, "stopped")}, nil
}

func schemaValue(schema, root map[string]any) any {
	if ref, ok := schema["$ref"].(string); ok {
		return schemaValue(root["$defs"].(map[string]any)[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any), root)
	}
	if value, ok := schema["const"]; ok {
		return value
	}
	if options, ok := schema["enum"].([]any); ok {
		for _, value := range options {
			if value == "deny" {
				return value
			}
		}
		return options[0]
	}
	switch schema["type"] {
	case "object":
		out := map[string]any{}
		properties, _ := schema["properties"].(map[string]any)
		required, _ := schema["required"].([]any)
		for _, name := range required {
			key := name.(string)
			out[key] = schemaValue(properties[key].(map[string]any), root)
		}
		return out
	case "array":
		return []any{}
	case "integer":
		if minimum, ok := schema["minimum"]; ok {
			return minimum
		}
		return 0
	case "boolean":
		return false
	default:
		return "node-unit-baseline"
	}
}
func fullDocument(t *testing.T) (json.RawMessage, []string) {
	t.Helper()
	var schema map[string]any
	if err := json.Unmarshal(policy.Schema(), &schema); err != nil {
		t.Fatal(err)
	}
	properties := schema["properties"].(map[string]any)
	out := map[string]any{}
	for _, name := range schema["required"].([]any) {
		key := name.(string)
		out[key] = schemaValue(properties[key].(map[string]any), schema)
	}
	for _, branch := range schema["oneOf"].([]any) {
		option := branch.(map[string]any)
		selector := option["properties"].(map[string]any)["profile"].(map[string]any)["const"]
		if selector == policy.KernelProfile {
			for _, name := range option["required"].([]any) {
				key := name.(string)
				out[key] = schemaValue(properties[key].(map[string]any), schema)
			}
		}
	}
	out["profile"] = policy.KernelProfile
	out["required_capabilities"] = []string{}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var document policy.Document
	if err = json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document.RequiredCapabilities, err = policy.Requirements(document)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = policy.Parse(raw, "json"); err != nil {
		t.Fatal(err)
	}
	return raw, document.RequiredCapabilities
}

type serverFixture struct {
	server     *Server
	operations *operationsFixture
	resolver   *resolverFixture
	journal    *lifecycle.SQLiteJournal
	key        ed25519.PrivateKey
	prepare    lifecycle.PrepareRequest
	document   json.RawMessage
	client     *http.Client
	root       string
	stop       context.CancelFunc
	done       chan error
}

func newFixture(t *testing.T) *serverFixture {
	t.Helper()
	scratch := os.Getenv("AGENTGATE_TEST_SCRATCH")
	if scratch == "" {
		scratch = os.Getenv("TMPDIR")
	}
	if scratch == "" || scratch == "/tmp" || strings.HasPrefix(scratch, "/tmp/") {
		t.Skip("set an owned private test scratch directory")
	}
	if os.Geteuid() != 0 {
		t.Skip("the actual Unix listener requires the node root identity")
	}
	root, err := os.MkdirTemp(scratch, "node-api-")
	if err != nil {
		t.Fatal(err)
	}
	journal, err := lifecycle.OpenJournal(filepath.Join(root, "journal.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	document, required := fullDocument(t)
	inputHash := sha256.Sum256([]byte("node API fixture input"))
	manifest := lifecycle.Manifest{Protocol: "agentgate.job.manifest.v1", AgentKind: "codex", RuntimeVersion: "unit-fixture-only", Executable: "/opt/agent/bin/codex", ExecutableDigest: strings.Repeat("a", 64), ImageDigest: "sha256:" + strings.Repeat("b", 64), Arguments: []string{"--unit-fixture"}, Workspace: "/work/node-job", Environment: map[string]string{}, InputDigest: hex.EncodeToString(inputHash[:])}
	jobDigest, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	binding := lifecycle.Binding{AgentID: "node-agent-one", AgentKey: base64.RawURLEncoding.EncodeToString(public), JobDigest: jobDigest, GrantID: "grant-one", RunID: "run-one", NodeID: "node-one", BootID: "boot-one", PolicyDigest: strings.Repeat("c", 64), SchemaDigest: policy.SchemaDigest(), CompilerDigest: strings.Repeat("d", 64), ArtifactDigests: map[string]string{"node": strings.Repeat("e", 64), "runtime.codex.files": emptyRuntimeFilesDigest()}, Generation: 1, DeadlineNS: 1000}
	registry := &resolverFixture{enrollment: Enrollment{AgentID: binding.AgentID, AgentKey: binding.AgentKey, PeerUID: uint32(os.Getuid()), PeerGID: uint32(os.Getgid()), Enabled: true, Runtimes: map[string]RuntimeArtifact{"codex": {Version: manifest.RuntimeVersion, Executable: manifest.Executable, ExecutableDigest: manifest.ExecutableDigest, ImageDigest: manifest.ImageDigest, Files: []runtimeclosure.File{}, FilesDigest: emptyRuntimeFilesDigest()}}}}
	report := policy.CapabilityReport{SchemaVersion: policy.CapabilityVersion, Node: binding.NodeID, Boot: binding.BootID, Challenge: "unit-challenge", Kernel: "unit-kernel", Architecture: "x86_64", SourceRevision: strings.Repeat("a", 40), ArtifactSHA256: binding.ArtifactDigests["node"], PolicySchemaDigest: policy.SchemaDigest(), InventorySHA256: strings.Repeat("1", 64), BTFSHA256: strings.Repeat("2", 64), KernelConfigSHA256: strings.Repeat("3", 64), IssuedAt: time.Now().Unix(), ValidUntil: time.Now().Unix() + 60, Capabilities: map[string]policy.Capability{}, Probes: []policy.HookProbe{}}
	for _, id := range required {
		report.Capabilities[id] = policy.Capability{State: "enforced", Mechanisms: []string{"unit-fixture-only"}, ReceiptSHA256: strings.Repeat("f", 64)}
	}
	envelope, err := policy.SignReport(report, key)
	if err != nil {
		t.Fatal(err)
	}
	target, err := policy.VerifyTarget(envelope, public, policy.TargetBinding{Node: binding.NodeID, Boot: binding.BootID, Challenge: report.Challenge}, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	operations := &operationsFixture{target: target, binding: binding, required: required}
	server, err := New(Config{Identity: lifecycle.Identity{NodeID: binding.NodeID, BootID: binding.BootID}, SocketPath: filepath.Join(root, "node.sock"), SocketGID: uint32(os.Getgid()), ReadHeaderTimeout: time.Second, RequestTimeout: time.Second, ShutdownTimeout: time.Second, Clock: fixedClock{}}, registry, journal, operations)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	// Wait for the actual listener without a fixed sleep.
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	ready := false
	for !ready {
		select {
		case err := <-done:
			t.Fatal("node listener failed", err)
		case <-deadline.C:
			t.Fatal("node listener did not start")
		case <-ticker.C:
			_, err := os.Stat(server.config.SocketPath)
			ready = err == nil
		}
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", server.config.SocketPath)
	}}
	fixture := &serverFixture{server: server, operations: operations, resolver: registry, journal: journal, key: key, prepare: lifecycle.PrepareRequest{Protocol: lifecycle.PrepareProtocol, Manifest: manifest, Binding: binding, RequiredCapabilities: required}, document: document, client: &http.Client{Transport: transport, Timeout: 2 * time.Second}, root: root, stop: cancel, done: done}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("node listener cleanup did not finish")
		}
		journal.Close()
		os.RemoveAll(root)
	})
	return fixture
}
func (f *serverFixture) call(t *testing.T, path string, body []byte, proof string) (int, []byte) {
	t.Helper()
	method := "POST"
	if strings.HasPrefix(path, "/v1/agents/") || path == "/v1/node/inventory" {
		method = "GET"
	}
	if proof == "" {
		proof = requestproof.Sign(f.prepare.Binding.AgentID, method, path, lifecycle.NodeAudience("node-one"), "boot-one", body, f.key)
	}
	request, err := http.NewRequest(method, "http://node"+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Alloyium-Proof "+proof)
	response, err := f.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, raw
}
func TestActualUnixPeerProofAndDurableReplayGuard(t *testing.T) {
	f := newFixture(t)
	body, _ := json.Marshal(f.prepare)
	proof := requestproof.Sign(f.prepare.Binding.AgentID, "POST", "/v1/jobs/prepare", lifecycle.NodeAudience("node-one"), "boot-one", body, f.key)
	if status, _ := f.call(t, "/v1/jobs/prepare", body, proof); status != 200 {
		t.Fatal("valid private prepare failed", status)
	}
	if status, _ := f.call(t, "/v1/jobs/prepare", body, proof); status != 401 {
		t.Fatal("proof replay accepted", status)
	}
	if f.operations.prepares.Load() != 1 {
		t.Fatal("replay repeated route effects")
	}
}
func TestHeaderCannotForgeUnixPeerCredentials(t *testing.T) {
	f := newFixture(t)
	body, _ := json.Marshal(f.prepare)
	request := httptest.NewRequest("POST", "http://node/v1/jobs/prepare", bytes.NewReader(body))
	request.Header.Set("X-Peer-Uid", "0")
	request.Header.Set("Authorization", "Alloyium-Proof "+requestproof.Sign(f.prepare.Binding.AgentID, "POST", "/v1/jobs/prepare", lifecycle.NodeAudience("node-one"), "boot-one", body, f.key))
	response := httptest.NewRecorder()
	f.server.ServeHTTP(response, request)
	if response.Code != 401 || f.operations.prepares.Load() != 0 {
		t.Fatal("unverified connection reached operations")
	}
}
func TestWrongBodyAndUnavailableRuntimeNeverPrepare(t *testing.T) {
	f := newFixture(t)
	body, _ := json.Marshal(f.prepare)
	wrong := requestproof.Sign(f.prepare.Binding.AgentID, "POST", "/v1/jobs/prepare", lifecycle.NodeAudience("node-one"), "boot-one", []byte("different body"), f.key)
	if status, _ := f.call(t, "/v1/jobs/prepare", body, wrong); status != 401 {
		t.Fatal("changed body accepted", status)
	}
	f.operations.targetMissing.Store(true)
	if status, _ := f.call(t, "/v1/jobs/prepare", body, ""); status != 503 {
		t.Fatal("unavailable runtime prepared", status)
	}
	if f.operations.prepares.Load() != 0 {
		t.Fatal("runtime failure caused route effects")
	}
}
func TestFullRunRequiresPreparedBindingAndDeclaredDocument(t *testing.T) {
	f := newFixture(t)
	body, _ := json.Marshal(f.prepare)
	status, raw := f.call(t, "/v1/jobs/prepare", body, "")
	if status != 200 {
		t.Fatal(status)
	}
	var prepared lifecycle.PrepareResponse
	if err := json.Unmarshal(raw, &prepared); err != nil {
		t.Fatal(err)
	}
	request := lifecycle.RunRequest{Protocol: lifecycle.RunProtocol, Manifest: f.prepare.Manifest, Authorization: lifecycle.Authorization{Binding: prepared.Binding, Grant: "test-only-authority-grant", Document: f.document, RequiredCapabilities: f.prepare.RequiredCapabilities}, Input: []byte("node API fixture input")}
	body, _ = json.Marshal(request)
	if status, _ = f.call(t, "/v1/jobs/run", body, ""); status != 200 {
		t.Fatal("qualified unit fixture did not reach runner", status)
	}
	if f.operations.runs.Load() != 1 {
		t.Fatal("runner call missing")
	}
	request.Authorization.RequiredCapabilities = []string{}
	body, _ = json.Marshal(request)
	if status, _ = f.call(t, "/v1/jobs/run", body, ""); status != 422 {
		t.Fatal("missing required controls accepted", status)
	}
	if f.operations.runs.Load() != 1 {
		t.Fatal("invalid document reached runner")
	}
}

func TestRunnerPanicStopsOwnedJobWithoutLeakingDetails(t *testing.T) {
	f := newFixture(t)
	f.operations.panicRun.Store(true)
	binding := f.prepare.Binding
	binding.CgroupID = 100
	request := lifecycle.RunRequest{Protocol: lifecycle.RunProtocol, Manifest: f.prepare.Manifest, Authorization: lifecycle.Authorization{Binding: binding, Grant: "test-only-authority-grant", Document: f.document, RequiredCapabilities: f.prepare.RequiredCapabilities}, Input: []byte("node API fixture input")}
	body, _ := json.Marshal(request)
	status, response := f.call(t, "/v1/jobs/run", body, "")
	if status != 500 || strings.Contains(string(response), "synthetic-private-runtime-detail") {
		t.Fatal("runner panic escaped its private boundary", status)
	}
	if f.operations.stops.Load() != 1 {
		t.Fatal("runner panic did not stop the owned job")
	}
	body, _ = json.Marshal(f.prepare)
	if status, _ = f.call(t, "/v1/jobs/prepare", body, ""); status != 503 {
		t.Fatal("runtime failure left preparation enabled", status)
	}
}

func TestStopResolutionPreservesAllOtherBindingFields(t *testing.T) {
	f := newFixture(t)
	request := lifecycle.StopRequest{Binding: f.prepare.Binding}
	actual := request.Binding
	actual.CgroupID = 100
	stopped := lifecycle.StopResponse{Protocol: lifecycle.StoppedProtocol, Binding: actual, Evidence: f.operations.evidence(actual, "stopped")}
	if !validStopped(request, stopped) {
		t.Fatal("resolved failure cleanup was rejected")
	}
	for _, change := range []func(*lifecycle.Binding){func(b *lifecycle.Binding) { b.GrantID = "other-grant" }, func(b *lifecycle.Binding) { b.AgentID = "other-agent" }, func(b *lifecycle.Binding) { b.Generation++ }, func(b *lifecycle.Binding) { b.BootID = "other-boot" }} {
		bad := stopped
		change(&bad.Binding)
		bad.Evidence = f.operations.evidence(bad.Binding, "stopped")
		if validStopped(request, bad) {
			t.Fatal("stop cleanup changed an immutable field")
		}
	}
	request.Binding.CgroupID = 101
	if validStopped(request, stopped) {
		t.Fatal("a resolved ID changed")
	}
}

func TestPreparedAuditHeaderRequiresExactCanonicalBinding(t *testing.T) {
	f := newFixture(t)
	prepared, err := f.operations.Prepare(context.Background(), f.prepare)
	if err != nil {
		t.Fatal(err)
	}
	if !validPrepared(f.prepare, prepared, f.server.config.Clock) {
		t.Fatal("the exact header failed")
	}
	for _, kind := range []string{"digest", "missing", "bytes", "binding"} {
		t.Run(kind, func(t *testing.T) {
			bad := prepared
			bad.AuditHeader = append([]byte{}, prepared.AuditHeader...)
			switch kind {
			case "digest":
				bad.AuditHeaderDigest = strings.Repeat("8", 64)
			case "missing":
				bad.AuditHeader = nil
			case "bytes":
				bad.AuditHeader = append(bad.AuditHeader, ' ')
			case "binding":
				var h jobaudit.Header
				_ = json.Unmarshal(bad.AuditHeader, &h)
				h.Binding.Generation++
				bad.AuditHeader, _ = jobaudit.HeaderBytes(h)
				bad.AuditHeaderDigest, _ = jobaudit.HeaderDigest(h)
			}
			if validPrepared(f.prepare, bad, f.server.config.Clock) {
				t.Fatal("changed prepared header passed")
			}
		})
	}
}

func (o *operationsFixture) GenerationFloor(context.Context, string) (uint64, error) {
	if o.generationError.Load() {
		return 0, errors.New("unit unavailable")
	}
	return o.generationValue.Load(), nil
}
func TestAuthenticatedGenerationFloorHasNoExecutionEffect(t *testing.T) {
	f := newFixture(t)
	f.operations.generationValue.Store(41)
	status, raw := f.call(t, "/v1/agents/"+f.prepare.Binding.AgentID+"/generation", nil, "")
	var result GenerationResponse
	if status != 200 || json.Unmarshal(raw, &result) != nil || result.Protocol != "agentgate.agent-generation.v1" || result.AgentID != f.prepare.Binding.AgentID || result.NodeID != f.prepare.Binding.NodeID || result.BootID != f.prepare.Binding.BootID || result.Generation != 41 || f.operations.prepares.Load() != 0 || f.operations.runs.Load() != 0 {
		t.Fatal("the generation read changed execution or identity", status, string(raw))
	}
	status, _ = f.call(t, "/v1/agents/another-agent/generation", nil, "")
	if status != 403 {
		t.Fatal("another subject read the floor", status)
	}
	f.operations.generationError.Store(true)
	status, _ = f.call(t, "/v1/agents/"+f.prepare.Binding.AgentID+"/generation", nil, "")
	if status != 503 {
		t.Fatal("an unavailable journal returned a floor", status)
	}
	f.operations.generationError.Store(false)
	f.operations.generationValue.Store(uint64(1<<63 - 1))
	status, _ = f.call(t, "/v1/agents/"+f.prepare.Binding.AgentID+"/generation", nil, "")
	if status != 503 {
		t.Fatal("an exhausted generation floor passed", status)
	}
}

func (o *operationsFixture) Inventory(ctx context.Context) (lifecycle.NodeInventory, error) {
	if o.inventoryError.Load() {
		return lifecycle.NodeInventory{}, errors.New("unit inventory unavailable")
	}
	target, err := o.Target(ctx)
	if err != nil {
		return lifecycle.NodeInventory{}, err
	}
	report := target.Report()
	inventory := lifecycle.NodeInventory{Protocol: lifecycle.NodeInventoryProtocol, NodeID: o.binding.NodeID, BootID: o.binding.BootID, SchemaDigest: o.binding.SchemaDigest, CompilerDigest: o.binding.CompilerDigest, ArtifactDigests: o.binding.ArtifactDigests, TargetReport: report, TargetDigest: target.Digest(), WallUnix: time.Now().Unix(), MonoNS: 1, KeyID: "node-key"}
	raw, err := lifecycle.NodeInventorySigningBytes(inventory)
	if err != nil {
		return inventory, err
	}
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("n", 32)))
	inventory.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))
	return inventory, nil
}
func TestAuthenticatedInventoryIsSignedAndReadOnly(t *testing.T) {
	f := newFixture(t)
	status, raw := f.call(t, "/v1/node/inventory", nil, "")
	var inventory lifecycle.NodeInventory
	if status != 200 || json.Unmarshal(raw, &inventory) != nil {
		t.Fatal("the inventory read failed", status, string(raw))
	}
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("n", 32))).Public().(ed25519.PublicKey)
	if _, err := lifecycle.VerifyNodeInventory(inventory, map[string]ed25519.PublicKey{"node-one/node-key": key}, lifecycle.Identity{"node-one", "boot-one"}, time.Now().Unix(), 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if f.operations.prepares.Load() != 0 || f.operations.runs.Load() != 0 {
		t.Fatal("an inventory read created execution rights")
	}
	f.operations.inventoryError.Store(true)
	status, _ = f.call(t, "/v1/node/inventory", nil, "")
	if status != 503 {
		t.Fatal("an unavailable inventory passed", status)
	}
}
