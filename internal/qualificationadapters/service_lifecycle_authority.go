// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/jobauthority"
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodeaudit"
	"alloyium.local/kernel-poc/internal/nodecontrol"
)

const serviceLifecycleAuthorityID = "qualification-lifecycle-authority"
const serviceLifecycleAuthorityKeyID = "one"

type serviceLifecycleAuthorityCall struct {
	Operation     string                     `json:"operation"`
	GrantID       string                     `json:"grant_id"`
	Known         bool                       `json:"known"`
	Revoked       bool                       `json:"revoked"`
	Authorization *lifecycle.Authorization   `json:"authorization,omitempty"`
	Receipt       *jobaudit.AuthorityReceipt `json:"receipt,omitempty"`
	MonoNS        uint64                     `json:"mono_ns,string"`
}
type serviceLifecycleAuthority struct {
	callMu sync.Mutex
	recipe serviceLifecycleRecipe
	scope  string
	key    ed25519.PrivateKey
	public ed25519.PublicKey
	nodes  map[string]ed25519.PublicKey
	store  *jobauthority.Store
	calls  []serviceLifecycleAuthorityCall
}

func newServiceLifecycleAuthority(root string, recipe serviceLifecycleRecipe, nodes map[string]ed25519.PublicKey) (*serviceLifecycleAuthority, error) {
	if err := protectedDirectory(root); err != nil {
		return nil, err
	}
	scope, err := lifecycle.QualificationFixtureScopeDigest(recipe.Spec)
	if err != nil {
		return nil, err
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	owned := map[string]ed25519.PublicKey{}
	for id, pinned := range nodes {
		if len(pinned) != ed25519.PublicKeySize || bytes.Equal(pinned, public) {
			clear(key)
			return nil, errors.New("the lifecycle authority signing roles differ")
		}
		owned[id] = append(ed25519.PublicKey{}, pinned...)
	}
	if len(owned) == 0 {
		clear(key)
		return nil, errors.New("the lifecycle authority requires pinned node keys")
	}
	store, err := jobauthority.OpenStore(filepath.Join(root, "authority.db"), "qualification-"+scope[:24])
	if err != nil {
		clear(key)
		return nil, err
	}
	return &serviceLifecycleAuthority{recipe: recipe, scope: scope, key: key, public: public, nodes: owned, store: store}, nil
}
func (a *serviceLifecycleAuthority) close() error {
	clear(a.key)
	if a.store == nil {
		return nil
	}
	err := a.store.Close()
	a.store = nil
	return err
}
func (a *serviceLifecycleAuthority) keys() map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{serviceLifecycleAuthorityID + "/" + serviceLifecycleAuthorityKeyID: append(ed25519.PublicKey{}, a.public...)}
}
func (a *serviceLifecycleAuthority) checkBinding(binding lifecycle.Binding) error {
	expected := a.recipe.Spec.Binding
	expected.CgroupID = binding.CgroupID
	if binding.CgroupID == 0 || !reflect.DeepEqual(binding, expected) {
		return errors.New("the lifecycle authority binding differs")
	}
	return nil
}
func (a *serviceLifecycleAuthority) state(ctx context.Context, id string) (jobauthority.StateResponse, error) {
	authorization, revoked, err := a.store.Grant(ctx, id)
	if errors.Is(err, jobauthority.ErrUnknown) {
		a.record(serviceLifecycleAuthorityCall{Operation: "state", GrantID: id, MonoNS: serviceMono()})
		return jobauthority.StateResponse{Protocol: jobauthority.StateProtocol, GrantID: id}, nil
	}
	if err != nil {
		return jobauthority.StateResponse{}, err
	}
	if id != a.recipe.Spec.Binding.GrantID || a.checkBinding(authorization.Binding) != nil {
		return jobauthority.StateResponse{}, errors.New("the lifecycle authority grant owner differs")
	}
	a.record(serviceLifecycleAuthorityCall{Operation: "state", GrantID: id, Known: true, Revoked: revoked, MonoNS: serviceMono()})
	return jobauthority.StateResponse{Protocol: jobauthority.StateProtocol, GrantID: id, Known: true, Revoked: revoked}, nil
}
func (a *serviceLifecycleAuthority) revoke(ctx context.Context, id string) error {
	if id != a.recipe.Spec.Binding.GrantID {
		return errors.New("the lifecycle revoke grant differs")
	}
	if err := a.store.Revoke(ctx, id); err != nil {
		return err
	}
	a.record(serviceLifecycleAuthorityCall{Operation: "revoke", GrantID: id, Known: true, Revoked: true, MonoNS: serviceMono()})
	state, err := a.state(ctx, id)
	if err != nil {
		return err
	}
	if !state.Known || !state.Revoked {
		return errors.New("the durable lifecycle revoke readback differs")
	}
	return nil
}
func (a *serviceLifecycleAuthority) trust(binding lifecycle.Binding) jobaudit.Trust {
	return jobaudit.Trust{NodeKeys: a.nodes, AuthorityKeys: a.keys(), Registry: nodecontrol.Registry(nodeaudit.Registry(), binding), Document: a.recipe.Document}
}
func (a *serviceLifecycleAuthority) countersign(ctx context.Context, bundle jobaudit.Bundle) (jobaudit.AuthorityReceipt, error) {
	if a.checkBinding(bundle.Header.Binding) != nil || bundle.Header.FixturePurpose != lifecycle.QualificationFixturePurpose || bundle.Header.QualificationDigest != a.scope || bundle.Grant == nil || bundle.Seal == nil || bundle.Authority != nil {
		return jobaudit.AuthorityReceipt{}, errors.New("the lifecycle fixture audit scope differs")
	}
	stored, revoked, err := a.store.Grant(ctx, bundle.Header.Binding.GrantID)
	if err != nil {
		return jobaudit.AuthorityReceipt{}, err
	}
	grant, err := jobgrant.Decode(stored.Grant)
	if err != nil || jobgrant.Digest(grant) != jobgrant.Digest(*bundle.Grant) || !reflect.DeepEqual(stored.Binding, bundle.Header.Binding) {
		return jobaudit.AuthorityReceipt{}, errors.New("the lifecycle audit grant differs from durable custody")
	}
	if revoked && bundle.Seal.Terminal.State == "completed" {
		return jobaudit.AuthorityReceipt{}, errors.New("the revoked lifecycle fixture cannot complete")
	}
	receipt, err := jobaudit.SignReceipt(serviceLifecycleAuthorityID, serviceLifecycleAuthorityKeyID, a.key, bundle, a.trust(stored.Binding), time.Now().Unix())
	if err != nil {
		return jobaudit.AuthorityReceipt{}, err
	}
	if err = a.store.SaveReceipt(ctx, stored.Binding.GrantID, jobaudit.SealDigest(*bundle.Seal), revoked, receipt); err != nil {
		return jobaudit.AuthorityReceipt{}, err
	}
	verified := bundle
	verified.Authority = &receipt
	verdict := jobaudit.VerifyOffline(verified, a.trust(stored.Binding))
	if verdict.State != "VALID_COMPLETE" {
		return jobaudit.AuthorityReceipt{}, errors.New("the lifecycle authority receipt fails offline verification")
	}
	a.record(serviceLifecycleAuthorityCall{Operation: "countersign", GrantID: stored.Binding.GrantID, Known: true, Revoked: revoked, Receipt: &receipt, MonoNS: serviceMono()})
	return receipt, nil
}

func (a *serviceLifecycleAuthority) record(call serviceLifecycleAuthorityCall) {
	a.callMu.Lock()
	defer a.callMu.Unlock()
	call.MonoNS = serviceMono()
	a.calls = append(a.calls, call)
}
func (a *serviceLifecycleAuthority) observations() ([]serviceLifecycleAuthorityCall, error) {
	a.callMu.Lock()
	defer a.callMu.Unlock()
	var calls []serviceLifecycleAuthorityCall
	err := lifecycle.DecodeTransport(bytes.NewReader(serviceJSON(a.calls)), &calls)
	return calls, err
}
