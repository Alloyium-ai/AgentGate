// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/jobauthority"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/noderuntime"
	"alloyium.local/kernel-poc/internal/qualification"
	"golang.org/x/sys/unix"
)

const serviceLifecycleReceiptVersion = "agentgate.fixed-lifecycle-scene-receipt.v2"

type serviceLifecycleReceipt struct {
	Protocol        string                  `json:"protocol"`
	AdapterID       string                  `json:"adapter_id"`
	Binding         qualification.Binding   `json:"binding"`
	TargetEnvelope  []byte                  `json:"target_envelope"`
	TargetPublicKey string                  `json:"target_public_key"`
	ServiceImage    string                  `json:"service_image"`
	Scenes          []serviceLifecycleScene `json:"scenes"`
}
type serviceLifecycleScene struct {
	Mode             string                            `json:"mode"`
	Recipe           serviceLifecycleRecipe            `json:"recipe"`
	Start            noderuntime.QualificationStart    `json:"start"`
	NodeConfig       noderuntime.Config                `json:"node_config"`
	NodeSnapshot     processSnapshot                   `json:"node_snapshot"`
	Prepared         noderuntime.QualificationPrepared `json:"prepared"`
	Active           noderuntime.QualificationStatus   `json:"active"`
	Stopped          noderuntime.QualificationStatus   `json:"stopped"`
	Repeat           noderuntime.QualificationStatus   `json:"repeat"`
	AuthorityPublic  []byte                            `json:"authority_public"`
	NodeKeys         map[string]ed25519.PublicKey      `json:"node_keys"`
	WatchdogPublic   []byte                            `json:"watchdog_public"`
	WatchdogState    *serviceLifecycleWatchdogReadback `json:"watchdog_state,omitempty"`
	Loss             *serviceLifecycleLoss             `json:"loss,omitempty"`
	NodeLoss         *serviceLifecycleNodeLoss         `json:"node_loss,omitempty"`
	PrepareReplyLoss *serviceLifecyclePrepareReplyLoss `json:"prepare_reply_loss,omitempty"`
	AuthorityCalls   []serviceLifecycleAuthorityCall   `json:"authority_calls"`
	Calls            []serviceLifecycleHTTPCall        `json:"calls"`
	Wire             []byte                            `json:"wire"`
	Actors           []processSnapshot                 `json:"actors"`
	After            []serviceLifecycleAfterProcess    `json:"after"`
	Audit            json.RawMessage                   `json:"audit"`
	AuditFile        *serviceLifecycleAuditFile        `json:"audit_file,omitempty"`
	Domain           string                            `json:"domain"`
	DomainInode      uint64                            `json:"domain_inode,string"`
	FinalDomainErrno int                               `json:"final_domain_errno"`
	FinalPins        []string                          `json:"final_pins"`
	NodeStderr       []byte                            `json:"node_stderr"`
	WatchdogStderr   []byte                            `json:"watchdog_stderr,omitempty"`
	Error            string                            `json:"error"`
	CleanupErrors    []string                          `json:"cleanup_errors"`
}
type serviceLifecycleAfterProcess struct {
	PID        int    `json:"pid"`
	StartTicks uint64 `json:"start_ticks,string"`
	Stat       []byte `json:"stat"`
	Status     string `json:"status"`
	Error      string `json:"error"`
	Errno      int    `json:"errno"`
}
type serviceLifecycleAdapter struct {
	config Config
	mode   string
}

func (a *serviceLifecycleAdapter) ID() string {
	switch a.mode {
	case "stop":
		return "agentgate.fixed-lifecycle-stop-adapter.v1"
	case "expiry":
		return "agentgate.fixed-lifecycle-expiry-adapter.v1"
	case "revoke":
		return "agentgate.fixed-lifecycle-revoke-adapter.v1"
	case "watchdog-loss":
		return "agentgate.fixed-lifecycle-watchdog-loss-adapter.v1"
	case "node-loss":
		return "agentgate.fixed-lifecycle-node-loss-adapter.v1"
	case "prepare-reply-loss":
		return "agentgate.fixed-lifecycle-prepare-reply-loss-adapter.v1"
	default:
		return ""
	}
}

func (a *serviceLifecycleAdapter) Run(ctx context.Context, request qualification.Request) (out qualification.Result, err error) {
	out.Binding = request.Binding
	out.StartedMonoNS = serviceMono()
	receipt := serviceLifecycleReceipt{Protocol: serviceLifecycleReceiptVersion, Binding: request.Binding, AdapterID: a.ID(), ServiceImage: a.config.ServiceImage, Scenes: []serviceLifecycleScene{}}
	defer func() { out.FinishedMonoNS = serviceMono(); out.Raw = serviceJSON(receipt) }()
	if a.ID() == "" {
		return out, errors.New("the fixed lifecycle adapter scene differs")
	}
	base, err := loadServiceLifecycleBase(ctx, request, a.config)
	if err != nil {
		return out, err
	}
	receipt.TargetEnvelope = base.report
	receipt.TargetPublicKey = base.config.Qualification.PublicKey
	scene, sceneErr := a.runScene(ctx, request, base, a.mode)
	if sceneErr != nil {
		scene.Error = sceneErr.Error()
	}
	receipt.Scenes = append(receipt.Scenes, scene)
	if len(scene.CleanupErrors) != 0 {
		return out, errors.New("the lifecycle fixture cleanup is incomplete")
	}
	return out, sceneErr
}
func (a *serviceLifecycleAdapter) sceneRecipe(request qualification.Request, base serviceLifecycleBase, mode string) (serviceLifecycleRecipe, error) {
	suffix := digestJSON(struct {
		Binding qualification.Binding
		Mode    string
		Mono    uint64
	}{request.Binding, mode, serviceMono()})[:16]
	root := filepath.Join("/var/lib", "kernel-poc-qualification-"+suffix)
	if err := os.Mkdir(root, 0755); err != nil {
		return serviceLifecycleRecipe{}, err
	}
	if err := os.Chmod(root, 0755); err != nil {
		return serviceLifecycleRecipe{}, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(root)
		}
	}()
	streams := filepath.Join(root, "streams")
	if err := os.Mkdir(streams, 0755); err != nil {
		return serviceLifecycleRecipe{}, err
	}
	if err := os.Chmod(streams, 0755); err != nil {
		return serviceLifecycleRecipe{}, err
	}
	prefix := "alloyium-poc-job-" + suffix + "-"
	proof, err := domainstore.MeasureRoot(prefix, base.root.QualificationReceiptDigest)
	if err != nil {
		return serviceLifecycleRecipe{}, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return serviceLifecycleRecipe{}, err
	}
	clear(private)
	image, err := serviceLifecycleImageDigest(a.config.ServiceImage)
	if err != nil {
		return serviceLifecycleRecipe{}, err
	}
	recipe, err := newServiceLifecycleRecipe(request, serviceLifecycleLayout{OwnedRoot: root, ArtifactRoot: streams, Worker: a.config.Artifacts["qualification-lifecycle-worker"], ImageDigest: image, TargetDigest: base.target.Digest(), AgentID: "qualification-agent-" + suffix, AgentKey: base64.RawURLEncoding.EncodeToString(public), RunID: "qualification-run-" + suffix, GrantID: "qualification-grant-" + suffix, Generation: 1, DeadlineNS: serviceMono() + uint64(25*time.Second), CandidateRootProof: base.root, RootProof: proof, Input: 'T'})
	if err == nil {
		keep = true
	}
	return recipe, err
}
func (a *serviceLifecycleAdapter) runScene(ctx context.Context, request qualification.Request, base serviceLifecycleBase, mode string) (scene serviceLifecycleScene, err error) {
	scene.Mode = mode
	scene.FinalPins = []string{}
	recipe, err := a.sceneRecipe(request, base, mode)
	scene.Recipe = recipe
	if err != nil {
		return scene, err
	}
	var node, watchdog *serviceLifecycleProcess
	var client *serviceLifecycleHTTPClient
	var server *serviceLifecycleAuthorityHTTP
	var authority *serviceLifecycleAuthority
	defer func() {
		if node != nil {
			if e := node.close(); e != nil {
				scene.CleanupErrors = append(scene.CleanupErrors, e.Error())
			}
		}
		if watchdog != nil {
			if e := watchdog.close(); e != nil {
				scene.CleanupErrors = append(scene.CleanupErrors, e.Error())
			}
		}
		if client != nil {
			client.close()
			client.mu.Lock()
			scene.Calls = append([]serviceLifecycleHTTPCall{}, client.calls...)
			client.mu.Unlock()
		}
		if server != nil {
			if e := server.close(); e != nil {
				scene.CleanupErrors = append(scene.CleanupErrors, e.Error())
			}
		}
		if authority != nil {
			scene.AuthorityCalls, _ = authority.observations()
			if e := authority.close(); e != nil {
				scene.CleanupErrors = append(scene.CleanupErrors, e.Error())
			}
		}
		if mode != "node-loss" && scene.AuditFile == nil && scene.Prepared.Record.Binding.RunID != "" {
			captureErr := captureServiceLifecycleAudit(&scene)
			err = errors.Join(err, captureErr)
			if captureErr != nil && len(scene.AuditFile.Raw) == 0 {
				scene.CleanupErrors = append(scene.CleanupErrors, "the unread audit remains in the owned fixture state")
			}
		}
		scene.After = serviceLifecycleAfter(scene.Actors)
		scene.Domain, scene.FinalDomainErrno, scene.FinalPins = serviceLifecycleFinalState(recipe)
		scene.NodeStderr, _ = os.ReadFile(filepath.Join(recipe.Spec.OwnedRoot, "private/node.stderr"))
		scene.WatchdogStderr, _ = os.ReadFile(filepath.Join(recipe.Spec.OwnedRoot, "private/watchdog.stderr"))
		if serviceLifecycleActorsTerminated(scene.Actors, scene.After) && scene.FinalDomainErrno == int(unix.ENOENT) && len(scene.FinalPins) == 0 && len(scene.CleanupErrors) == 0 {
			if e := os.RemoveAll(recipe.Spec.OwnedRoot); e != nil {
				scene.CleanupErrors = append(scene.CleanupErrors, e.Error())
			}
		} else {
			scene.CleanupErrors = append(scene.CleanupErrors, "the owned fixture state remains for recovery")
		}
	}()
	roles, err := stageServiceLifecycleKeys(recipe)
	if err != nil {
		return scene, err
	}
	authority, err = newServiceLifecycleAuthority(filepath.Join(recipe.Spec.OwnedRoot, "private/authority"), recipe, roles.nodeKeys)
	if err != nil {
		return scene, err
	}
	staged, err := stageServiceLifecycleNode(base, recipe, authority, roles)
	if err != nil {
		return scene, err
	}
	scene.NodeConfig = staged.node
	scene.NodeKeys = staged.nodeKeys
	scene.WatchdogPublic = staged.watchdogKey
	scene.AuthorityPublic = authority.public
	watchdog, err = startServiceLifecycleProcess(ctx, a.config.Artifacts["watchdog"], request.Binding.ArtifactDigests["watchdog"], recipe.Spec.OwnedRoot, "watchdog", []string{"-config", staged.watchdogPath}, nil)
	if err != nil {
		return scene, err
	}
	if err = waitServiceLifecycleSocket(ctx, staged.watchdog.SocketPath, watchdog); err != nil {
		return scene, err
	}
	parentTicks, err := lifecycle.ProcessStartTime(os.Getpid())
	if err != nil {
		return scene, err
	}
	scene.Start = noderuntime.QualificationStart{Protocol: noderuntime.QualificationStartProtocol, NodeConfigFile: staged.nodePath, Spec: recipe.Spec, Parent: lifecycle.DaemonIdentity{PID: os.Getpid(), StartTimeTicks: parentTicks, InstanceID: "qualification-parent-" + digestJSON(recipe.Spec)[:16]}}
	start, err := sealedServiceLifecycleStart(scene.Start)
	if err != nil {
		return scene, err
	}
	commands, childCommands, err := serviceLifecycleSocketpair()
	if err != nil {
		start.Close()
		return scene, err
	}
	callbacks, childCallbacks, err := serviceLifecycleSocketpair()
	if err != nil {
		start.Close()
		commands.Close()
		childCommands.Close()
		return scene, err
	}
	client, err = newServiceLifecycleHTTPClient(commands)
	if err != nil {
		start.Close()
		childCommands.Close()
		callbacks.Close()
		childCallbacks.Close()
		return scene, err
	}
	server, err = serveServiceLifecycleAuthority(callbacks, authority)
	if err != nil {
		start.Close()
		childCommands.Close()
		childCallbacks.Close()
		return scene, err
	}
	node, err = startServiceLifecycleProcess(ctx, a.config.Artifacts["node"], request.Binding.ArtifactDigests["node"], recipe.Spec.OwnedRoot, "node", []string{"qualification-fixture"}, []*os.File{start, childCommands, childCallbacks})
	if err != nil {
		return scene, err
	}
	scene.NodeSnapshot, err = inspectProcess(node.pid, a.config.Artifacts["node"], request.Binding.ArtifactDigests["node"])
	if err != nil {
		return scene, err
	}
	if mode == "prepare-reply-loss" {
		err = runServiceLifecyclePrepareReplyLoss(ctx, &scene, client)
		return scene, err
	}
	if err = client.request(ctx, "POST", "/fixture/prepare", struct{}{}, &scene.Prepared); err != nil {
		return scene, err
	}
	sample, err := noderuntime.VerifyQualificationPrepared(scene.Prepared, recipe.Spec, staged.nodeKeys, staged.watchdogKey, time.Now().Unix(), 2*time.Second)
	if err != nil {
		return scene, err
	}
	var header jobaudit.Header
	if err = lifecycle.DecodeTransport(bytes.NewReader(scene.Prepared.AuditHeader), &header); err != nil {
		return scene, err
	}
	authorization, err := authority.issue(ctx, scene.Prepared.Record.Binding, header, jobauthority.NodeTime{Wall: time.Unix(sample.Wall, 0), MonoNS: sample.MonoNS})
	if err != nil {
		return scene, err
	}
	if err = client.request(ctx, "POST", "/fixture/start", noderuntime.QualificationRunRequest{Protocol: noderuntime.QualificationRunProtocol, Authorization: authorization}, &scene.Active); err != nil {
		return scene, err
	}
	scene.Wire, scene.Actors, scene.DomainInode, err = readServiceLifecycleActors(ctx, recipe, scene.Active.Record.Binding, node.pid)
	if err != nil {
		return scene, err
	}
	watchdogReadback, readErr := readServiceLifecycleWatchdog(ctx, scene)
	scene.WatchdogState = &watchdogReadback
	if readErr != nil {
		return scene, readErr
	}
	if mode == "watchdog-loss" {
		err = runServiceLifecycleWatchdogLoss(ctx, &scene, node, watchdog, a.config.Artifacts["watchdog"], request.Binding.ArtifactDigests["watchdog"])
		return scene, err
	}
	if mode == "node-loss" {
		scene.Domain, _, _ = serviceLifecycleFinalState(recipe)
		err = runServiceLifecycleNodeLoss(ctx, &scene, node, watchdog, a.config.Artifacts["watchdog"], request.Binding.ArtifactDigests["watchdog"], a.config.Artifacts["node"], request.Binding.ArtifactDigests["node"], authority)
		return scene, err
	}
	if mode == "revoke" {
		if err = authority.revoke(ctx, authorization.Binding.GrantID); err != nil {
			return scene, err
		}
	}
	if mode == "stop" {
		err = client.request(ctx, "POST", "/fixture/stop", noderuntime.QualificationStopRequest{Protocol: noderuntime.QualificationStopProtocol, Reason: "client-stop"}, &scene.Stopped)
	} else {
		scene.Stopped, err = waitServiceLifecycleStopped(ctx, client)
	}
	if err != nil {
		return scene, err
	}
	if err = client.request(ctx, "POST", "/fixture/stop", noderuntime.QualificationStopRequest{Protocol: noderuntime.QualificationStopProtocol, Reason: "client-stop"}, &scene.Repeat); err != nil {
		return scene, err
	}
	if err = captureServiceLifecycleAudit(&scene); err != nil {
		return scene, err
	}
	return scene, nil
}
func waitServiceLifecycleSocket(ctx context.Context, path string, process *serviceLifecycleProcess) error {
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		var stat unix.Stat_t
		if unix.Lstat(path, &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFSOCK && stat.Uid == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-process.done:
			return errors.New("the fixed watchdog ended before its private socket")
		case <-timeout.C:
			return errors.New("the fixed watchdog socket deadline expired")
		case <-tick.C:
		}
	}
}
func waitServiceLifecycleStopped(ctx context.Context, client *serviceLifecycleHTTPClient) (noderuntime.QualificationStatus, error) {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	timeout := time.NewTimer(12 * time.Second)
	defer timeout.Stop()
	for {
		var status noderuntime.QualificationStatus
		if err := client.request(ctx, "GET", "/fixture/status", nil, &status); err != nil {
			return status, err
		}
		if status.Record.State == "stopped" {
			return status, nil
		}
		select {
		case <-ctx.Done():
			return status, ctx.Err()
		case <-timeout.C:
			return status, errors.New("the fixed lifecycle stop deadline expired")
		case <-tick.C:
		}
	}
}

func serviceLifecycleImageDigest(reference string) (string, error) {
	digest := reference
	if name, suffix, found := strings.Cut(reference, "@sha256:"); found {
		if name == "" || strings.ContainsAny(name, " @\t\n\r?#") {
			return "", errors.New("the lifecycle image reference differs")
		}
		digest = "sha256:" + suffix
	}
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 || strings.Trim(digest[7:], "0123456789abcdef") != "" {
		return "", errors.New("the lifecycle image digest differs")
	}
	return digest, nil
}
