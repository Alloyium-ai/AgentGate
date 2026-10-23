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
	"os"
	"path/filepath"
	"reflect"
	"time"

	"alloyium.local/kernel-poc/internal/buildinfo"
	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/nodeapi"
	"alloyium.local/kernel-poc/internal/nodebackend"
	"alloyium.local/kernel-poc/internal/noderuntime"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/qualification"
	"golang.org/x/sys/unix"
)

type serviceLifecycleBase struct {
	config noderuntime.Config
	report []byte
	target policy.VerifiedTarget
	root   domainstore.RootProof
}
type serviceLifecycleStaged struct {
	node                   noderuntime.Config
	watchdog               noderuntime.WatchdogConfig
	nodePath, watchdogPath string
	nodeKeys               map[string]ed25519.PublicKey
	watchdogKey            ed25519.PublicKey
}

func readServiceLifecycleOwned(path string, max int64) ([]byte, error) {
	if err := protectedDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Nlink != 1 || stat.Mode&022 != 0 || stat.Size <= 0 || stat.Size > max {
		return nil, errors.New("the lifecycle input custody differs")
	}
	raw, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || int64(len(raw)) != stat.Size {
		return nil, errors.New("the lifecycle input changed")
	}
	return raw, nil
}
func loadServiceLifecycleBase(ctx context.Context, request qualification.Request, config Config) (serviceLifecycleBase, error) {
	var base serviceLifecycleBase
	if buildinfo.SourceRevision == "" || buildinfo.SourceRevision != request.Binding.SourceRevision {
		return base, errors.New("the lifecycle parent source differs")
	}
	if err := validateRequest(request); err != nil {
		return base, err
	}
	if err := kernel.Preflight(); err != nil {
		return base, err
	}
	if err := sourceBootMatches(request); err != nil {
		return base, err
	}
	if err := jobartifacts.VerifyRunningExecutable(request.Binding.ArtifactDigests["qualification"]); err != nil {
		return base, err
	}
	var err error
	base.config, err = noderuntime.ReadConfig(config.NodeConfigFile)
	if err != nil {
		return base, err
	}
	if base.config.NodeID != request.Binding.NodeID || base.config.Qualification.SourceRevision != request.Binding.SourceRevision {
		return base, errors.New("the lifecycle node template source or target differs")
	}
	base.root, err = domainstore.MeasureRoot(base.config.OwnedPrefix, base.config.RootQualificationDigest)
	if err != nil {
		return base, err
	}
	expected := map[string]string{}
	for name, digest := range base.config.ArtifactDigests {
		expected[name] = digest
	}
	expected["domain-root"] = base.root.Digest()
	if !reflect.DeepEqual(expected, request.Binding.ArtifactDigests) {
		return base, errors.New("the lifecycle node template artifact set differs")
	}
	base.report, err = readServiceLifecycleOwned(base.config.Qualification.ReportFile, 2<<20)
	if err != nil {
		return base, err
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(base.config.Qualification.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return base, errors.New("the lifecycle target public key differs")
	}
	base.target, err = policy.VerifyTarget(base.report, ed25519.PublicKey(public), policy.TargetBinding{Node: request.Binding.NodeID, Boot: request.Binding.BootID, Challenge: base.config.Qualification.Challenge}, time.Now().Unix())
	if err != nil {
		return base, err
	}
	report := base.target.Report()
	if report.SourceRevision != request.Binding.SourceRevision || report.PolicySchemaDigest != request.Binding.SchemaDigest || report.Kernel != request.Binding.Kernel || report.Architecture != request.Binding.Architecture || report.InventorySHA256 != request.Binding.InventorySHA256 || report.BTFSHA256 != request.Binding.BTFSHA256 || report.KernelConfigSHA256 != request.Binding.KernelConfigSHA256 {
		return base, errors.New("the lifecycle target facts differ from the candidate request")
	}
	for _, capability := range report.Capabilities {
		if capability.State == "enforced" {
			return base, errors.New("the lifecycle fixture requires an unavailable target report")
		}
	}
	if err = ctx.Err(); err != nil {
		return base, err
	}
	return base, nil
}
func writeServiceLifecycleOwned(path string, raw []byte) error {
	if err := protectedDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	_, err = file.Write(raw)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func serviceLifecycleKey(path string) (ed25519.PublicKey, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	defer clear(private)
	if err = writeServiceLifecycleOwned(path, private); err != nil {
		return nil, err
	}
	return public, nil
}
func stageServiceLifecycleKeys(recipe serviceLifecycleRecipe) (serviceLifecycleStaged, error) {
	var staged serviceLifecycleStaged
	root := recipe.Spec.OwnedRoot
	for _, name := range []string{"private", "private/domains", "private/audit", "private/authority"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil && !os.IsExist(err) {
			return staged, err
		}
	}
	nodeKey, err := serviceLifecycleKey(filepath.Join(root, "private/node.key"))
	if err != nil {
		return staged, err
	}
	watchKey, err := serviceLifecycleKey(filepath.Join(root, "private/watchdog.key"))
	if err != nil {
		return staged, err
	}
	if bytes.Equal(nodeKey, watchKey) {
		return staged, errors.New("the fixture signing roles overlap")
	}
	return serviceLifecycleStaged{nodePath: filepath.Join(root, "private/node.json"), watchdogPath: filepath.Join(root, "private/watchdog.json"), nodeKeys: map[string]ed25519.PublicKey{recipe.Spec.Binding.NodeID + "/qualification-node-one": nodeKey}, watchdogKey: watchKey}, nil
}
func stageServiceLifecycleNode(base serviceLifecycleBase, recipe serviceLifecycleRecipe, authority *serviceLifecycleAuthority, keys serviceLifecycleStaged) (serviceLifecycleStaged, error) {
	staged := keys
	root := recipe.Spec.OwnedRoot
	nodePath := filepath.Join(root, "private/node.key")
	watchPath := filepath.Join(root, "private/watchdog.key")
	nodeKey := keys.nodeKeys[recipe.Spec.Binding.NodeID+"/qualification-node-one"]
	watchKey := keys.watchdogKey
	if len(nodeKey) != ed25519.PublicKeySize || len(watchKey) != ed25519.PublicKeySize || bytes.Equal(authority.public, watchKey) || !reflect.DeepEqual(authority.nodes, keys.nodeKeys) {
		return staged, errors.New("the staged node signing roles differ from authority custody")
	}
	var err error
	encode := base64.RawURLEncoding.EncodeToString
	config := base.config
	config.Protocol = noderuntime.ConfigProtocol
	config.InstanceID = "qualification-" + digestJSON(recipe.Spec)[:20]
	config.NodeKeyID = "qualification-node-one"
	config.NodeKeyFile = nodePath
	config.NodeKeys = map[string]string{config.NodeID + "/" + config.NodeKeyID: encode(nodeKey)}
	config.AuthorityKeys = map[string]string{serviceLifecycleAuthorityID + "/" + serviceLifecycleAuthorityKeyID: encode(authority.public)}
	config.SocketPath = filepath.Join(root, "private/unavailable-node.sock")
	config.SocketGID = 0
	config.WatchdogSocket = filepath.Join(root, "private/watchdog.sock")
	config.WatchdogPublicKey = encode(watchKey)
	config.WatchdogKeyFile = watchPath
	config.WatchdogStore = filepath.Join(root, "private/watchdog.db")
	config.OwnedPrefix = recipe.FixtureRoot.OwnedPrefix
	config.RootQualificationDigest = recipe.FixtureRoot.QualificationReceiptDigest
	config.DomainState = filepath.Join(root, "private/domains")
	config.Journal = filepath.Join(root, "private/node.db")
	config.AuditRoot = filepath.Join(root, "private/audit")
	config.ArtifactRoot = filepath.Join(root, "streams")
	// The lifecycle scene is a fixed host actor with its own measured domain.
	// It cannot borrow the candidate Docker placement: its streams and bridge
	// belong to the actual target and are verified by the target adapter.
	config.PilotTarget = nil
	config.ArtifactDigests = recipe.Spec.Binding.ArtifactDigests
	config.Limits = nodebackend.Limits{MemoryBytes: 256 << 20, PIDs: 16, CPUQuotaUS: 100000}
	config.OutputLimit = 1 << 20
	config.MaxRuns = 1
	config.PreparationLeaseMS = 15000
	// Actual target I spends more than five seconds on verified stop and teardown.
	// This fixture budget does not change its signed or kernel execution cutoff.
	config.StopTimeoutMS = 15000
	config.RequestTimeoutMS = 20000
	policyPath := filepath.Join(root, "private/policy.json")
	config.Documents = map[string]string{recipe.Spec.Binding.PolicyDigest: policyPath}
	config.Enrollments = []nodeapi.Enrollment{{AgentID: recipe.Spec.Binding.AgentID, AgentKey: recipe.Spec.Binding.AgentKey, PeerUID: 0, PeerGID: 0, Enabled: true, Runtimes: map[string]nodeapi.RuntimeArtifact{"codex": recipe.Runtime}}}
	config.Qualification.ReportFile = filepath.Join(root, "private/unavailable-target.json")
	config.Authority = noderuntime.AuthorityConfig{SocketPath: filepath.Join(root, "private/authority.sock"), AuthorityID: serviceLifecycleAuthorityID, Epoch: "qualification-" + authority.scope[:24], PeerUID: 0, TimeoutMS: 1000}
	// Preserve the candidate's measured resolver when its artifact is bound.
	// The fixture policy still grants no DNS or network operation to its worker.
	config.Credentials = nil
	watchdog := noderuntime.WatchdogConfig{Protocol: "agentgate.watchdog-config.v1", NodeID: config.NodeID, InstanceID: "watchdog-" + digestJSON(recipe.Spec)[:20], SocketPath: config.WatchdogSocket, StatePath: config.WatchdogStore, DomainState: config.DomainState, OwnedPrefix: config.OwnedPrefix, RootQualificationDigest: config.RootQualificationDigest, KeyFile: watchPath, PublicKey: config.WatchdogPublicKey, ArtifactDigest: config.ArtifactDigests["watchdog"], SourceRevision: recipe.Spec.SourceRevision, StopTimeoutMS: 5000, HeartbeatTimeoutMS: 1000}
	staged = serviceLifecycleStaged{node: config, watchdog: watchdog, nodePath: filepath.Join(root, "private/node.json"), watchdogPath: filepath.Join(root, "private/watchdog.json"), nodeKeys: map[string]ed25519.PublicKey{config.NodeID + "/" + config.NodeKeyID: nodeKey}, watchdogKey: watchKey}
	for _, item := range []struct {
		path string
		raw  []byte
	}{{policyPath, recipe.Spec.Document}, {config.Qualification.ReportFile, base.report}, {staged.nodePath, serviceJSON(config)}, {staged.watchdogPath, serviceJSON(watchdog)}} {
		if err = writeServiceLifecycleOwned(item.path, item.raw); err != nil {
			return staged, err
		}
	}
	return staged, nil
}
