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
	"strings"
	"testing"
	"time"
)

func inventoryFixture(t *testing.T) (NodeInventory, map[string]ed25519.PublicKey) {
	t.Helper()
	r := policy.CapabilityReport{SchemaVersion: policy.CapabilityVersion, Node: "node-one", Boot: "boot-one", Challenge: "challenge-one", Kernel: "6.8.0-142-generic", Architecture: "x86_64", SourceRevision: strings.Repeat("a", 40), ArtifactSHA256: strings.Repeat("b", 64), PolicySchemaDigest: policy.SchemaDigest(), InventorySHA256: strings.Repeat("c", 64), BTFSHA256: strings.Repeat("d", 64), KernelConfigSHA256: strings.Repeat("e", 64), IssuedAt: 100, ValidUntil: 200, Capabilities: map[string]policy.Capability{"fs.rules.v1": {State: "probe-only", Mechanisms: []string{}}}, Probes: []policy.HookProbe{}}
	raw, _ := json.Marshal(r)
	sum := sha256.Sum256(raw)
	i := NodeInventory{Protocol: NodeInventoryProtocol, NodeID: r.Node, BootID: r.Boot, SchemaDigest: r.PolicySchemaDigest, CompilerDigest: strings.Repeat("f", 64), ArtifactDigests: map[string]string{"kernel": r.ArtifactSHA256}, TargetReport: r, TargetDigest: hex.EncodeToString(sum[:]), WallUnix: 150, MonoNS: 500, KeyID: "node-key"}
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("n", 32)))
	signed, err := NodeInventorySigningBytes(i)
	if err != nil {
		t.Fatal(err)
	}
	i.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, signed))
	return i, map[string]ed25519.PublicKey{"node-one/node-key": key.Public().(ed25519.PublicKey)}
}
func TestSignedNodeInventoryBindsBootArtifactsAndNodeTime(t *testing.T) {
	i, keys := inventoryFixture(t)
	point, err := VerifyNodeInventory(i, keys, Identity{"node-one", "boot-one"}, 151, 30*time.Second)
	if err != nil || point.Wall != 150 || point.MonoNS != 500 {
		t.Fatal("the node inventory signature or time differs", err)
	}
	if i.TargetReport.Capabilities["fs.rules.v1"].State != "probe-only" {
		t.Fatal("an inventory read invented qualification")
	}
}
func TestNodeInventoryRejectsChangedProofAndStaleOrDifferentBoot(t *testing.T) {
	for _, name := range []string{"unsigned", "key", "boot", "node", "compiler", "artifact", "report", "digest", "stale", "future", "report-expired", "time"} {
		t.Run(name, func(t *testing.T) {
			i, keys := inventoryFixture(t)
			identity := Identity{"node-one", "boot-one"}
			now := int64(151)
			switch name {
			case "unsigned":
				i.Signature = ""
			case "key":
				keys = map[string]ed25519.PublicKey{}
			case "boot":
				identity.BootID = "other-boot"
			case "node":
				identity.NodeID = "other-node"
			case "compiler":
				i.CompilerDigest = strings.Repeat("1", 64)
			case "artifact":
				i.ArtifactDigests["kernel"] = strings.Repeat("2", 64)
			case "report":
				i.TargetReport.Kernel = "different-kernel"
			case "digest":
				i.TargetDigest = strings.Repeat("3", 64)
			case "stale":
				now = 181
			case "future":
				now = 148
			case "report-expired":
				now = 200
			case "time":
				i.MonoNS++
			}
			if _, err := VerifyNodeInventory(i, keys, identity, now, 30*time.Second); err == nil {
				t.Fatal("an untrusted inventory passed")
			}
		})
	}
}
