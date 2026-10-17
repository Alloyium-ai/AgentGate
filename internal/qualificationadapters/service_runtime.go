// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"time"

	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodeapi"
	"alloyium.local/kernel-poc/internal/nodebackend"
	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/requestproof"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"crypto/ed25519"
)

var serviceRuntimeNames = []string{"registered-runtime-unqualified", "unregistered-runtime", "wrong-runtime-version", "wrong-runtime-executable", "wrong-runtime-image", "wrong-runtime-files", "loader-environment"}

func serviceRuntimeInput(request qualification.Request, root string, public []byte) (lifecycle.PrepareRequest, nodeapi.RuntimeArtifact, error) {
	executable, err := os.Executable()
	if err != nil {
		return lifecycle.PrepareRequest{}, nodeapi.RuntimeArtifact{}, err
	}
	files, err := runtimeclosure.New([]runtimeclosure.File{})
	if err != nil {
		return lifecycle.PrepareRequest{}, nodeapi.RuntimeArtifact{}, err
	}
	if request.Binding.ArtifactDigests["runtime.codex.files"] != files.Digest() {
		return lifecycle.PrepareRequest{}, nodeapi.RuntimeArtifact{}, errors.New("the identity runtime fixture differs from the existing candidate closure")
	}
	artifact := nodeapi.RuntimeArtifact{Version: "qualification-identity-only", Executable: executable, ExecutableDigest: request.Binding.ArtifactDigests["qualification"], ImageDigest: "sha256:" + request.Binding.ArtifactDigests["qualification"], Files: files.Files(), FilesDigest: files.Digest()}
	manifest := lifecycle.Manifest{Protocol: "agentgate.job.manifest.v1", AgentKind: "codex", RuntimeVersion: artifact.Version, Executable: artifact.Executable, ExecutableDigest: artifact.ExecutableDigest, ImageDigest: artifact.ImageDigest, Arguments: []string{}, Workspace: root, Environment: map[string]string{}, InputDigest: requestproof.Digest(nil)}
	digest, err := manifest.Digest()
	if err != nil {
		return lifecycle.PrepareRequest{}, nodeapi.RuntimeArtifact{}, err
	}
	artifacts := map[string]string{}
	for name, value := range request.Binding.ArtifactDigests {
		artifacts[name] = value
	}
	binding := lifecycle.Binding{AgentID: "qualification-agent", AgentKey: base64.RawURLEncoding.EncodeToString(public), JobDigest: digest, GrantID: "qualification-runtime-grant", RunID: "qualification-runtime-run", NodeID: request.Binding.NodeID, BootID: request.Binding.BootID, PolicyDigest: request.Binding.PolicyDigest, SchemaDigest: request.Binding.SchemaDigest, CompilerDigest: nodebackend.CompilerDigest(request.Binding.ArtifactDigests["node"]), ArtifactDigests: artifacts, Generation: 2, DeadlineNS: serviceMono() + uint64(5*time.Second)}
	return lifecycle.PrepareRequest{Protocol: lifecycle.PrepareProtocol, Manifest: manifest, Binding: binding, RequiredCapabilities: request.Document.RequiredCapabilities}, artifact, nil
}
func changedServiceRuntime(base lifecycle.PrepareRequest, artifact nodeapi.RuntimeArtifact, name string) (lifecycle.PrepareRequest, map[string]nodeapi.RuntimeArtifact, error) {
	var request lifecycle.PrepareRequest
	if err := lifecycle.DecodeTransport(bytes.NewReader(serviceJSON(base)), &request); err != nil {
		return request, nil, err
	}
	runtimes := map[string]nodeapi.RuntimeArtifact{"codex": artifact}
	changed := artifact
	switch name {
	case "registered-runtime-unqualified":
	case "unregistered-runtime":
		runtimes = map[string]nodeapi.RuntimeArtifact{}
	case "wrong-runtime-version":
		changed.Version += "-other"
	case "wrong-runtime-executable":
		changed.Executable += "-other"
	case "wrong-runtime-image":
		changed.ImageDigest = "sha256:" + digestJSON(name)
	case "wrong-runtime-files":
		changed.FilesDigest = digestJSON(name)
	case "loader-environment":
		request.Manifest.Environment["LD_PRELOAD"] = "/untrusted/runtime.so"
	default:
		return request, nil, errors.New("the service runtime case is unknown")
	}
	if name != "unregistered-runtime" {
		runtimes["codex"] = changed
	}
	var err error
	request.Binding.JobDigest, err = request.Manifest.Digest()
	return request, runtimes, err
}
func runServiceRuntimes(ctx context.Context, request qualification.Request, root string, baseline nodeapi.Enrollment, private ed25519.PrivateKey, enrollments *serviceEnrollments, client *http.Client) ([]enrollmentCall, error) {
	base, artifact, err := serviceRuntimeInput(request, root, private.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	calls := []enrollmentCall{}
	for _, name := range serviceRuntimeNames {
		input, runtimes, err := changedServiceRuntime(base, artifact, name)
		if err != nil {
			return nil, err
		}
		enrollment := baseline
		enrollment.Runtimes = runtimes
		enrollments.set(enrollment)
		c := enrollmentCall{Name: name, Enrollment: enrollment, Method: "POST", Path: "/v1/jobs/prepare", Body: serviceJSON(input)}
		c.Token = requestproof.Sign(baseline.AgentID, c.Method, c.Path, lifecycle.NodeAudience(request.Binding.NodeID), request.Binding.BootID, c.Body, private)
		req, err := http.NewRequestWithContext(ctx, c.Method, "http://private-node"+c.Path, bytes.NewReader(c.Body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Alloyium-Proof "+c.Token)
		response, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		c.Status = response.StatusCode
		c.Response, err = io.ReadAll(io.LimitReader(response.Body, 65537))
		response.Body.Close()
		c.MonoNS = serviceMono()
		if err != nil || len(c.Response) > 65536 {
			return nil, errors.New("the service runtime response exceeds its bound")
		}
		calls = append(calls, c)
	}
	return calls, nil
}
func verifyServiceRuntimes(request qualification.Request, result qualification.Result, receipt enrollmentReceipt) error {
	if len(receipt.RuntimeCalls) != len(serviceRuntimeNames) {
		return errors.New("the service runtime calls are incomplete")
	}
	var base lifecycle.PrepareRequest
	first := receipt.RuntimeCalls[0]
	if err := lifecycle.DecodeTransport(bytes.NewReader(first.Body), &base); err != nil {
		return err
	}
	artifact, ok := first.Enrollment.Runtimes["codex"]
	files, _ := runtimeclosure.New([]runtimeclosure.File{})
	if !ok || base.Validate() != nil || !reflect.DeepEqual(base.Binding.ArtifactDigests, request.Binding.ArtifactDigests) || request.Binding.ArtifactDigests["runtime.codex.files"] != files.Digest() || base.Binding.NodeID != request.Binding.NodeID || base.Binding.BootID != request.Binding.BootID || base.Binding.PolicyDigest != request.Binding.PolicyDigest || base.Binding.SchemaDigest != request.Binding.SchemaDigest || base.Binding.AgentKey != base64.RawURLEncoding.EncodeToString(receipt.AgentKey) || base.Manifest.RuntimeVersion != "qualification-identity-only" || base.Manifest.ExecutableDigest != request.Binding.ArtifactDigests["qualification"] || base.Manifest.ImageDigest != "sha256:"+request.Binding.ArtifactDigests["qualification"] || artifact.FilesDigest != files.Digest() || !nodeapi.RuntimeFilesMatch(artifact, base.Manifest, base.Binding) {
		return errors.New("the registered identity-only runtime input differs")
	}
	baseline := receipt.Calls[0].Enrollment
	for index, name := range serviceRuntimeNames {
		c := receipt.RuntimeCalls[index]
		expected, runtimes, err := changedServiceRuntime(base, artifact, name)
		if err != nil {
			return err
		}
		var actual lifecycle.PrepareRequest
		if err = lifecycle.DecodeTransport(bytes.NewReader(c.Body), &actual); err != nil {
			return err
		}
		enrolled := baseline
		enrolled.Runtimes = runtimes
		if c.Name != name || c.Method != "POST" || c.Path != "/v1/jobs/prepare" || c.MonoNS < result.StartedMonoNS || c.MonoNS > result.FinishedMonoNS || !reflect.DeepEqual(actual, expected) || !reflect.DeepEqual(c.Enrollment, enrolled) {
			return errors.New("the runtime negative input or call order differs")
		}
		claims, err := verifyProofSignature(c, receipt.AgentKey)
		if err != nil || claims.Subject != baseline.AgentID || claims.Audience != lifecycle.NodeAudience(request.Binding.NodeID) || claims.Epoch != request.Binding.BootID || claims.Method != c.Method || claims.Path != c.Path || claims.BodyDigest != requestproof.Digest(c.Body) {
			return errors.New("the runtime request proof differs")
		}
		expectedStatus, code := 403, "node_job_enrollment_differs"
		if index == 0 {
			expectedStatus, code = 503, "node_required_capability_unavailable"
		}
		expectedBody := map[string]any{"error": map[string]string{"code": code, "message": code}}
		var body any
		if err = lifecycle.DecodeTransport(bytes.NewReader(c.Response), &body); err != nil || c.Status != expectedStatus || !bytes.Equal(serviceJSON(body), serviceJSON(expectedBody)) {
			return errors.New("the runtime enrollment outcome differs")
		}
	}
	return nil
}
