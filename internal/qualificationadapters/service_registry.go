// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"

	"alloyium.local/kernel-poc/internal/buildinfo"
	"alloyium.local/kernel-poc/internal/dnslease"
	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/noderuntime"
	"alloyium.local/kernel-poc/internal/qualification"
)

const serviceReceiptVersion = "agentgate.service-identity-receipt.v1"

// NewLifecycle supplies isolated service actors and, when configured, a
// measured Docker target custody actor. Lifecycle releases use only the fixed
// worker permit. Partial cases cannot satisfy a complete capability contract.
func NewLifecycle(config Config) ([]qualification.Adapter, error) {
	if err := protectedDirectory(config.ScratchRoot); err != nil {
		return nil, err
	}
	owned := Config{ScratchRoot: config.ScratchRoot, NodeConfigFile: config.NodeConfigFile, ServiceImage: config.ServiceImage, Artifacts: map[string]string{}}
	for name, path := range config.Artifacts {
		owned.Artifacts[name] = path
	}
	adapters := []qualification.Adapter{
		&serviceIdentity{config: owned},
		&serviceLifecycleAdapter{config: owned, mode: "stop"},
		&serviceLifecycleAdapter{config: owned, mode: "expiry"},
		&serviceLifecycleAdapter{config: owned, mode: "revoke"},
		&serviceLifecycleAdapter{config: owned, mode: "watchdog-loss"},
		&serviceLifecycleAdapter{config: owned, mode: "node-loss"},
		&serviceLifecycleAdapter{config: owned, mode: "prepare-reply-loss"},
	}
	if config.PilotTarget != nil {
		target := *config.PilotTarget
		if err := target.Validate(); err != nil {
			return nil, err
		}
		var resolver dnslease.Resolver
		if config.NodeConfigFile != "" {
			node, err := noderuntime.ReadConfig(config.NodeConfigFile)
			if err != nil {
				return nil, err
			}
			if node.PilotTarget == nil || !reflect.DeepEqual(*node.PilotTarget, target) {
				return nil, errors.New("the qualifier target differs from the protected node configuration")
			}
			resolver, err = noderuntime.ConfiguredResolver(node)
			if err != nil {
				return nil, err
			}
		}
		// The existing target-only diagnostic omits the node configuration. It
		// can retain partial custody cases but cannot gain trusted-host coverage.
		adapters = append(adapters, &pilotTargetAdapter{target: target, resolver: resolver})
	}
	return adapters, nil
}

type serviceIdentity struct{ config Config }

func (*serviceIdentity) ID() string { return "agentgate.service-identity-adapter.v1" }

type serviceCall struct {
	Name   string          `json:"name"`
	Input  json.RawMessage `json:"input,omitempty"`
	Error  string          `json:"error"`
	MonoNS uint64          `json:"mono_ns,string"`
}
type serviceReceipt struct {
	Protocol        string                `json:"protocol"`
	Binding         qualification.Binding `json:"binding"`
	AuthorityKey    []byte                `json:"authority_key"`
	NodeKey         []byte                `json:"node_key"`
	KeyRoles        []serviceCall         `json:"key_roles"`
	AgentKey        []byte                `json:"agent_key"`
	Grant           json.RawMessage       `json:"grant"`
	Authorization   json.RawMessage       `json:"authorization"`
	SignedClaims    json.RawMessage       `json:"signed_claims"`
	Calls           []serviceCall         `json:"calls"`
	JournalRecords  json.RawMessage       `json:"journal_records"`
	GenerationFloor uint64                `json:"generation_floor,string"`
	Enrollment      enrollmentReceipt     `json:"enrollment"`
	CleanupErrno    int                   `json:"cleanup_errno"`
}

func serviceError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
func serviceMono() uint64                   { value, _ := kernel.MonotonicNS(); return value }
func serviceJSON(value any) json.RawMessage { raw, _ := json.Marshal(value); return raw }

func (a *serviceIdentity) Run(ctx context.Context, request qualification.Request) (out qualification.Result, err error) {
	if err = validateRequest(request); err != nil {
		return out, err
	}
	if os.Geteuid() != 0 {
		return out, errors.New("the isolated service actor requires root")
	}
	if buildinfo.SourceRevision == "" || buildinfo.SourceRevision != request.Binding.SourceRevision {
		return out, errors.New("the service actor source differs")
	}
	if err = sourceBootMatches(request); err != nil {
		return out, err
	}
	if err = jobartifacts.VerifyRunningExecutable(request.Binding.ArtifactDigests["qualification"]); err != nil {
		return out, err
	}
	if err = protectedDirectory(a.config.ScratchRoot); err != nil {
		return out, err
	}
	root, err := os.MkdirTemp(a.config.ScratchRoot, "service-")
	if err != nil {
		return out, err
	}
	r := serviceReceipt{Protocol: serviceReceiptVersion, Binding: request.Binding}
	out.Binding, out.StartedMonoNS = request.Binding, serviceMono()
	defer func() {
		cleanupErr := os.RemoveAll(root)
		r.CleanupErrno = 0
		if cleanupErr != nil {
			r.CleanupErrno = 1
		}
		if _, e := os.Lstat(root); !os.IsNotExist(e) {
			r.CleanupErrno = 1
		}
		err = errors.Join(err, cleanupErr)
		out.FinishedMonoNS, out.Raw = serviceMono(), serviceJSON(r)
	}()
	if err = a.runIdentity(ctx, request, filepath.Join(root, "identity.db"), &r); err != nil {
		return out, err
	}
	r.Enrollment, err = a.runEnrollment(ctx, request, root)
	return out, err
}

func serviceResult(request qualification.Request, result qualification.Result) (serviceReceipt, error) {
	var r serviceReceipt
	if err := validateRequest(request); err != nil {
		return r, err
	}
	if len(result.Raw) == 0 || len(result.Raw) > 4<<20 || uniqueJSON(result.Raw) != nil {
		return r, errors.New("the service receipt encoding differs")
	}
	if err := lifecycle.DecodeTransport(bytes.NewReader(result.Raw), &r); err != nil {
		return r, err
	}
	if r.Protocol != serviceReceiptVersion || !reflect.DeepEqual(r.Binding, request.Binding) || !reflect.DeepEqual(result.Binding, request.Binding) || result.StartedMonoNS == 0 || result.FinishedMonoNS <= result.StartedMonoNS || r.CleanupErrno != 0 {
		return r, errors.New("the service receipt binding, time or cleanup differs")
	}
	for _, c := range append(append([]serviceCall{}, r.Calls...), r.KeyRoles...) {
		if c.MonoNS < result.StartedMonoNS || c.MonoNS > result.FinishedMonoNS {
			return r, errors.New("a service call time differs")
		}
	}
	return r, nil
}
