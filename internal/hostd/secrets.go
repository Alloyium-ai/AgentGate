// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"alloyium.local/kernel-poc/internal/broker"
	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/secretseal"
)

// Seal key timing: a record is valid for sealKeyLifetime and is re-signed
// once less than sealKeyRenew of it remains, so a client never sees one that
// is about to expire.
const (
	sealKeyLifetime = 30 * 24 * time.Hour
	sealKeyRenew    = 7 * 24 * time.Hour
	bindingsName    = "secret-bindings.json"
	maxBindings     = 256
)

// currentSealKey returns this host's seal key: the enrollment X25519 key in a
// record signed by the enrolled Ed25519 key (secretseal.HostKeyFromECDH). The
// key id depends only on the public key, so re-signing never invalidates an
// envelope sealed to it.
func (d *Daemon) currentSealKey() (*secretseal.HostKey, error) {
	d.sealMu.Lock()
	defer d.sealMu.Unlock()
	now := d.Now()
	if d.sealKey != nil {
		notAfter, err := time.Parse(time.RFC3339, d.sealKey.Record().NotAfter)
		if err == nil && now.Before(notAfter.Add(-sealKeyRenew)) {
			return d.sealKey, nil
		}
	}
	key, err := secretseal.HostKeyFromECDH(d.Identity.TargetID, d.Keys.Encryption, d.Keys.Signing, now, sealKeyLifetime)
	if err != nil {
		return nil, err
	}
	d.sealKey = key
	return key, nil
}

// sealKeyRecord is the published record for the heartbeat.
func (d *Daemon) sealKeyRecord() json.RawMessage {
	key, err := d.currentSealKey()
	if err != nil {
		d.logf("seal key unavailable: %v", err)
		return nil
	}
	raw, err := json.Marshal(key.Published())
	if err != nil || len(raw) > hostproto.MaxSealKeyRecordBytes {
		return nil
	}
	return raw
}

// secretDir is this target's store: SecretRoot/TARGET, root-owned and 0700.
func (d *Daemon) secretDir() string {
	return filepath.Join(d.Config.secretRoot(), d.Identity.TargetID)
}

// secretStore opens (creating it the first time) the target's store. Every
// stored value must be one the broker can inject.
func (d *Daemon) secretStore() (*secretseal.Store, error) {
	if err := ensurePrivateDir(d.Config.secretRoot()); err != nil {
		return nil, err
	}
	if err := ensurePrivateDir(d.secretDir()); err != nil {
		return nil, err
	}
	store, err := secretseal.OpenStore(d.secretDir())
	if err != nil {
		return nil, err
	}
	store.Validate = broker.ValidSecret
	return store, nil
}

// secretBinding ties a stored name to the service's secret id, so a launch
// can only use the value the service relayed for exactly that secret, and to
// the injection policy the client sealed with the value (its digest is in the
// HPKE associated data the host opened it with). Every broker for the secret
// is built from Policy, never from a launch job's copy of the settings.
type secretBinding struct {
	SecretID     string                  `json:"secret_id"`
	Version      uint64                  `json:"version"`
	Fingerprint  string                  `json:"fingerprint"`
	PolicyDigest string                  `json:"policy_digest,omitempty"`
	Policy       *hostproto.SecretPolicy `json:"policy,omitempty"`
}

func (d *Daemon) loadBindings() (map[string]secretBinding, error) {
	out := map[string]secretBinding{}
	raw, err := readPrivateFile(filepath.Join(d.StateDir, bindingsName), 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&out); err != nil || len(out) > maxBindings {
		return nil, errors.New("hostd: the secret binding file is damaged")
	}
	return out, nil
}

func (d *Daemon) saveBindings(bindings map[string]secretBinding) error {
	if len(bindings) > maxBindings {
		return errors.New("hostd: too many stored secrets")
	}
	raw, err := json.Marshal(bindings)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(d.StateDir, bindingsName), raw, 0o600)
}

// secretErrorCode maps a store refusal to a result. A refusal never names
// the value; every one leaves the stored secret as it was.
func secretErrorCode(err error) (string, string) {
	switch {
	case errors.Is(err, secretseal.ErrReplay):
		return hostproto.ResultRejected, "replayed_or_rolled_back"
	case errors.Is(err, secretseal.ErrStale):
		return hostproto.ResultRejected, "envelope_stale"
	case errors.Is(err, secretseal.ErrContext):
		return hostproto.ResultRejected, "envelope_wrong_context"
	case errors.Is(err, secretseal.ErrOpen):
		return hostproto.ResultRejected, "envelope_unauthenticated"
	case errors.Is(err, secretseal.ErrValue):
		return hostproto.ResultRejected, "value_refused"
	case errors.Is(err, secretseal.ErrEnvelope):
		return hostproto.ResultRejected, "envelope_malformed"
	}
	return hostproto.ResultFailed, "store_unavailable"
}

// secretPutJob opens a sealed envelope into the target's store and answers
// with the receipt only the sealing client can verify.
func (d *Daemon) secretPutJob(job hostproto.Job, p hostproto.SecretPutPayload) {
	d.secretMu.Lock()
	defer d.secretMu.Unlock()
	env, err := secretseal.DecodeEnvelope(p.Ciphertext)
	if err != nil {
		d.finish(job.ID, hostproto.ResultRejected, "envelope_malformed", "the secret-put ciphertext is not a secretseal envelope; nothing was stored", nil, "")
		return
	}
	if env.TargetID != d.Identity.TargetID || env.Name != p.Name {
		d.finish(job.ID, hostproto.ResultRejected, "envelope_wrong_context", "the envelope is sealed for another target or name; nothing was stored", nil, "")
		return
	}
	// The relayed settings must be exactly the policy the client sealed: their
	// digest equals the envelope's policy_digest, which the AEAD below
	// authenticates. A service that changed the upstream, header, scheme,
	// rules or any other setting gets nothing stored.
	policy, err := p.Policy()
	if err != nil || policy.Digest() != p.PolicyDigest || policy.Digest() != env.PolicyDigest {
		d.finish(job.ID, hostproto.ResultRejected, "policy_mismatch", "the relayed broker settings differ from the policy sealed with the value; nothing was stored", nil, "")
		return
	}
	key, err := d.currentSealKey()
	if err != nil {
		d.finish(job.ID, hostproto.ResultFailed, "seal_key_unavailable", "this host has no seal key; nothing was stored", nil, "")
		return
	}
	store, err := d.secretStore()
	if errors.Is(err, secretseal.ErrLegacyStore) {
		d.logf("secret store %s: %v", d.secretDir(), err)
		d.finish(job.ID, hostproto.ResultFailed, "store_legacy_format", "the secret store on this host holds the earlier two-file format; the host operator must remove it and every secret must be sealed again; nothing was stored", nil, "")
		return
	}
	if err != nil {
		d.finish(job.ID, hostproto.ResultFailed, "store_unavailable", "the secret store is unavailable; nothing was stored", nil, "")
		return
	}
	bindings, err := d.loadBindings()
	if err != nil {
		d.finish(job.ID, hostproto.ResultFailed, "store_unavailable", err.Error(), nil, "")
		return
	}
	receipt, err := store.Accept(key, env, d.Now())
	if err != nil {
		status, code := secretErrorCode(err)
		d.finish(job.ID, status, code, "the host refused the sealed secret: "+code+"; the stored secret is unchanged", nil, "")
		return
	}
	bindings[p.Name] = secretBinding{SecretID: p.SecretID, Version: receipt.Version, Fingerprint: receipt.Fingerprint, PolicyDigest: receipt.PolicyDigest, Policy: &policy}
	if err = d.saveBindings(bindings); err != nil {
		// The value is stored but not bound: every launch refuses it.
		d.finish(job.ID, hostproto.ResultFailed, "binding_unsaved", "the secret was stored but could not be bound to its id: "+err.Error(), nil, "")
		return
	}
	answer := hostproto.SecretReceipt(*receipt)
	d.finishResult(job.ID, hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "stored", SecretReceipt: &answer},
		fmt.Sprintf("stored secret %s version %d (fingerprint %s, policy %s)", p.Name, receipt.Version, receipt.Fingerprint, receipt.PolicyDigest))
}

// secretDeleteJob zeroes and removes one value, keeping a tombstone so the
// envelope that set it cannot set it again. A secret a running launch uses is
// refused; a name bound to another secret id is left alone.
func (d *Daemon) secretDeleteJob(job hostproto.Job, p hostproto.SecretDeletePayload) {
	d.secretMu.Lock()
	defer d.secretMu.Unlock()
	if d.secretInUse(p.Name) {
		d.finish(job.ID, hostproto.ResultRejected, "secret_in_use", "a running launch uses this secret; stop it first", nil, "")
		return
	}
	bindings, err := d.loadBindings()
	if err != nil {
		d.finish(job.ID, hostproto.ResultFailed, "store_unavailable", err.Error(), nil, "")
		return
	}
	if b, ok := bindings[p.Name]; ok && b.SecretID != p.SecretID {
		d.finish(job.ID, hostproto.ResultSucceeded, "not_held", "this host holds a different secret under that name; nothing was removed", nil, "")
		return
	}
	store, err := d.secretStore()
	if err == nil {
		err = store.Delete(p.Name, d.Now())
	}
	if err != nil {
		d.finish(job.ID, hostproto.ResultFailed, "store_unavailable", "the secret could not be removed", nil, "")
		return
	}
	delete(bindings, p.Name)
	if err = d.saveBindings(bindings); err != nil {
		d.finish(job.ID, hostproto.ResultFailed, "binding_unsaved", err.Error(), nil, "")
		return
	}
	d.finish(job.ID, hostproto.ResultSucceeded, "deleted", "the secret value was overwritten and removed", nil, "")
}

func (d *Daemon) secretInUse(name string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, launch := range d.active {
		for _, ref := range launch.secrets {
			if ref == name {
				return true
			}
		}
	}
	return false
}

// boundSecret checks that the store holds exactly the value the service
// relayed for secretID under name, and returns that value and the policy
// stored with it. The value is read from the store's one committed record;
// its fingerprint is recomputed here and must equal both the record's and
// the binding's, as must the version, so a value that differs from what the
// sealing client was given a receipt for is never used. The binding's policy
// must reproduce the digest both the binding and the record hold (the store
// recorded the digest the envelope sealed), so a damaged or edited binding is
// refused too. The caller wipes the value.
func (d *Daemon) boundSecret(store *secretseal.Store, bindings map[string]secretBinding, name, secretID string) ([]byte, *hostproto.SecretPolicy, error) {
	b, ok := bindings[name]
	if !ok || b.SecretID != secretID {
		return nil, nil, fmt.Errorf("secret %s is not stored on this host for secret id %s", name, secretID)
	}
	held, ok, err := store.Load(name)
	if err != nil || !ok {
		return nil, nil, fmt.Errorf("secret %s on this host differs from its binding", name)
	}
	fp := store.Fingerprint(d.Identity.TargetID, name, held.Value)
	if held.Version != b.Version || fp != held.Fingerprint || fp != b.Fingerprint {
		held.Wipe()
		return nil, nil, fmt.Errorf("secret %s on this host differs from its binding", name)
	}
	if b.Policy == nil || b.PolicyDigest == "" || b.Policy.Digest() != b.PolicyDigest || held.PolicyDigest != b.PolicyDigest {
		held.Wipe()
		return nil, nil, fmt.Errorf("secret %s on this host has no sealed broker policy that matches its value; store it again", name)
	}
	return held.Value, b.Policy, nil
}
