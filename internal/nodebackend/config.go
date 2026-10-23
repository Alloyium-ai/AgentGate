// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
)

var errUnknownRun = errors.New("the concrete backend run is unknown")

func CompilerDigest(nodeDigest string) string {
	if !validDigest(nodeDigest) {
		return ""
	}
	sum := sha256.Sum256([]byte("agentgate.full-compiler.v1\n" + policy.CompilerVersion + "\n" + policy.SchemaDigest() + "\n" + nodeDigest))
	return hex.EncodeToString(sum[:])
}

func cloneJSON[T any](value T) T {
	raw, _ := json.Marshal(value)
	var out T
	_ = json.Unmarshal(raw, &out)
	return out
}
func digest(value any) string {
	raw, _ := json.Marshal(value)
	s := sha256.Sum256(raw)
	return hex.EncodeToString(s[:])
}
func validDigest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}
func protectedRoot(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || path == "/tmp" || strings.HasPrefix(path, "/tmp/") {
		return errors.New("a canonical protected backend directory is required")
	}
	for {
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&022 != 0 {
			return errors.New("the backend directory custody differs")
		}
		if path == "/" {
			return nil
		}
		path = filepath.Dir(path)
	}
}
func validateConfig(c Config) error {
	if c.Domain.NodeID == "" || c.Documents == nil || c.Qualification == nil || c.Verifier == nil || c.Clock == nil || c.Signer == nil || c.Authority == nil || len(c.NodeKeys) == 0 || len(c.AuthorityKeys) == 0 || !validDigest(c.CompilerDigest) || c.OutputLimit <= 0 || c.OutputLimit > lifecycle.MaxInputBytes || c.MaxRuns < 1 || c.MaxRuns > 64 {
		return errors.New("the concrete backend requires current trust, signatures, documents and bounded output")
	}
	if err := c.Limits.validate(); err != nil {
		return err
	}
	if c.Credentials != nil {
		if err := c.Credentials.validate(c.ArtifactDigests); err != nil {
			return err
		}
	}
	if c.PilotTarget != nil {
		if c.MaxRuns != 1 {
			return errors.New("the dedicated SSH Docker target requires one active job")
		}
		if err := c.PilotTarget.Validate(); err != nil {
			return err
		}
		if c.PilotTarget.ArtifactSource != c.ArtifactRoot || c.PilotTarget.ArtifactPath == "" || c.PilotTarget.BridgePath == "" {
			return errors.New("the Docker target stream or scoped bridge mount is absent")
		}
	}
	if c.ArtifactDigests["domain-root"] != c.Domain.Proof.Digest() {
		return errors.New("the backend root proof digest differs")
	}
	if c.CompilerDigest != CompilerDigest(c.ArtifactDigests["node"]) {
		return errors.New("the compiler digest differs from the measured node artifact")
	}
	if !strings.HasPrefix(c.Domain.Proof.OwnedPrefix, "alloyium-poc-job-") {
		return errors.New("the measured exec broker requires the qualified domain prefix")
	}
	if err := jobartifacts.VerifyRunningExecutable(c.ArtifactDigests["node"]); err != nil {
		return err
	}
	for _, name := range []string{"node", "watchdog", "held-helper", "exec-broker", "files", "peers", "sockets", "custody", "process", "syscalls"} {
		if !validDigest(c.ArtifactDigests[name]) {
			return errors.New("a mandatory backend artifact digest is absent")
		}
	}
	if c.Artifacts.Anonymous != "" {
		if !validDigest(c.ArtifactDigests["anonymous"]) {
			return errors.New("the anonymous guard artifact digest is absent")
		}
		if err := jobartifacts.VerifyDataFile(c.Artifacts.Anonymous, c.ArtifactDigests["anonymous"], 64<<20); err != nil {
			return err
		}
	} else if c.ArtifactDigests["anonymous"] != "" {
		return errors.New("the measured anonymous guard artifact is absent")
	}
	p := c.ObservationProfile
	if p.Initialize == nil || p.EventsMap != "audit_events" || p.CountersMap != "audit_stats" || len(p.LSMPrograms) != 0 || len(p.CgroupPrograms) != 0 || len(p.TracepointPrograms) != len(syscallrules.Programs()) {
		return errors.New("the backend requires the complete syscall observation profile")
	}
	want := map[string]string{}
	for _, hook := range syscallrules.Programs() {
		want[hook.Program] = hook.Group + "/" + hook.Name
	}
	for _, hook := range p.TracepointPrograms {
		if want[hook.Name] != hook.Group+"/"+hook.Event {
			return errors.New("the syscall observation attachment differs")
		}
		delete(want, hook.Name)
	}
	if len(want) != 0 {
		return errors.New("a syscall observation attachment is missing")
	}
	for name, format := range jobaudit.ResourceFormats() {
		if c.Registry[name+"/"+format.Version] == nil {
			return errors.New("a resource audit decoder is absent")
		}
	}
	for name, format := range jobaudit.ObservationFormats() {
		if c.Registry[name+"/"+format.Version] == nil {
			return errors.New("a syscall observation decoder is absent")
		}
	}
	for _, path := range []string{c.AuditRoot, c.ArtifactRoot} {
		if err := protectedRoot(path); err != nil {
			return err
		}
	}
	if err := jobartifacts.ValidateRuntimeTraversal(c.ArtifactRoot); err != nil {
		return err
	}
	for _, item := range []struct{ name, path string }{{"held-helper", c.Helper}, {"exec-broker", c.Broker}} {
		if err := jobartifacts.VerifyExecutable(item.path, c.ArtifactDigests[item.name]); err != nil {
			return err
		}
	}
	for _, item := range []struct{ name, path string }{{"files", c.Artifacts.Files}, {"peers", c.Artifacts.Peers}, {"sockets", c.Artifacts.Sockets}, {"custody", c.Artifacts.Custody}, {"process", c.Artifacts.Process}, {"syscalls", c.ObservationObject}} {
		if err := jobartifacts.VerifyDataFile(item.path, c.ArtifactDigests[item.name], 64<<20); err != nil {
			return err
		}
	}
	return nil
}
func New(c Config) (out *Backend, err error) {
	if err = validateConfig(c); err != nil {
		return nil, err
	}
	if err = kernel.Preflight(); err != nil {
		return nil, err
	}
	b := &Backend{config: c, runs: map[string]*run{}}
	b.config.Credentials = copyValue(c.Credentials)
	b.config.PilotTarget = copyValue(c.PilotTarget)
	b.config.ArtifactDigests = cloneJSON(c.ArtifactDigests)
	b.config.NodeKeys = copyValue(c.NodeKeys)
	b.config.AuthorityKeys = copyValue(c.AuthorityKeys)
	b.config.Registry = jobaudit.Registry{}
	for name, decode := range c.Registry {
		b.config.Registry[name] = decode
	}
	if b.pins, err = NewPinReader(c.Domain.NodeID, c.Domain.Proof); err != nil {
		return nil, err
	}
	if b.artifacts, err = jobartifacts.New(c.ArtifactRoot, c.Domain.NodeID, c.OutputLimit); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = b.artifacts.Close()
		}
	}()
	domain := c.Domain
	domain.BarrierVerifier = b
	domain.CounterReader = b.pins
	domain.RightsVerifier = b.pins
	b.domains, err = domainstore.New(domain)
	if err != nil {
		return nil, err
	}
	return b, nil
}
func privateLog(root, name string) (*os.File, error) {
	if err := protectedRoot(root); err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(root, name), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
}
