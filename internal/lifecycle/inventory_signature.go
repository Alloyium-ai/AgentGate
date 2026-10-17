// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"alloyium.local/kernel-poc/internal/policy"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

const NodeInventoryProtocol = "agentgate.node.inventory.v1"
const NodeInventorySigningDomain = "AGENTGATE_NODE_INVENTORY_V1\n"

type NodeInventory struct {
	Protocol        string                  `json:"protocol"`
	NodeID          string                  `json:"node_id"`
	BootID          string                  `json:"boot_id"`
	SchemaDigest    string                  `json:"schema_digest"`
	CompilerDigest  string                  `json:"compiler_digest"`
	ArtifactDigests map[string]string       `json:"artifact_digests"`
	TargetReport    policy.CapabilityReport `json:"target_report"`
	TargetDigest    string                  `json:"target_digest"`
	WallUnix        int64                   `json:"wall_unix"`
	MonoNS          uint64                  `json:"mono_ns,string"`
	KeyID           string                  `json:"key_id"`
	Signature       string                  `json:"signature"`
}

func inventoryContent(i NodeInventory) error {
	if i.Protocol != NodeInventoryProtocol || !identifier.MatchString(i.NodeID) || !identifier.MatchString(i.BootID) || !identifier.MatchString(i.KeyID) || i.SchemaDigest != policy.SchemaDigest() || !validDigest(i.CompilerDigest) || !validDigest(i.TargetDigest) || i.WallUnix <= 0 || i.MonoNS == 0 || len(i.ArtifactDigests) == 0 || len(i.ArtifactDigests) > 64 {
		return errors.New("the signed node inventory content is invalid")
	}
	bound := false
	for name, digest := range i.ArtifactDigests {
		if !identifier.MatchString(name) || !validDigest(digest) {
			return errors.New("the signed node artifact registry is invalid")
		}
		bound = bound || digest == i.TargetReport.ArtifactSHA256
	}
	r := i.TargetReport
	if !bound || r.SchemaVersion != policy.CapabilityVersion || r.Node != i.NodeID || r.Boot != i.BootID || r.PolicySchemaDigest != i.SchemaDigest || r.Architecture != "x86_64" || r.Kernel == "" || r.IssuedAt < 0 || r.ValidUntil <= r.IssuedAt || r.ValidUntil-r.IssuedAt > 300 || i.WallUnix < r.IssuedAt || i.WallUnix >= r.ValidUntil || len(r.Capabilities) > 64 || len(r.Probes) > 64 {
		return errors.New("the signed inventory target report binding differs")
	}
	for _, digest := range []string{r.ArtifactSHA256, r.InventorySHA256, r.BTFSHA256, r.KernelConfigSHA256} {
		if !validDigest(digest) {
			return errors.New("the signed inventory target measurements are incomplete")
		}
	}
	raw, _ := json.Marshal(r)
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != i.TargetDigest {
		return errors.New("the signed inventory target report digest differs")
	}
	return nil
}
func NodeInventorySigningBytes(i NodeInventory) ([]byte, error) {
	if err := inventoryContent(i); err != nil {
		return nil, err
	}
	i.Signature = ""
	raw, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}
	return append([]byte(NodeInventorySigningDomain), raw...), nil
}
func VerifyNodeInventory(i NodeInventory, pinned map[string]ed25519.PublicKey, expected Identity, nowWall int64, maxAge time.Duration) (PreparedNodeTime, error) {
	if !identifier.MatchString(expected.NodeID) || !identifier.MatchString(expected.BootID) || i.NodeID != expected.NodeID || i.BootID != expected.BootID || nowWall <= 0 || maxAge < time.Second || maxAge > 30*time.Second || maxAge%time.Second != 0 || i.WallUnix > nowWall+1 || nowWall-i.WallUnix > int64(maxAge/time.Second) || nowWall >= i.TargetReport.ValidUntil {
		return PreparedNodeTime{}, errors.New("the node inventory identity or freshness differs")
	}
	raw, err := NodeInventorySigningBytes(i)
	if err != nil {
		return PreparedNodeTime{}, err
	}
	key := pinned[i.NodeID+"/"+i.KeyID]
	signature, err := base64.RawURLEncoding.DecodeString(i.Signature)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != i.Signature || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, raw, signature) {
		return PreparedNodeTime{}, errors.New("the inventory signature differs from pinned node trust")
	}
	return PreparedNodeTime{i.WallUnix, i.MonoNS}, nil
}
