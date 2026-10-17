// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodeapi

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"encoding/base64"
	"net/http"
)

type InventoryProvider interface {
	Inventory(context.Context) (lifecycle.NodeInventory, error)
}

func (s *Server) inventory(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != "GET" || r.URL.Path != "/v1/node/inventory" {
		return false
	}
	provider, ok := s.operations.(InventoryProvider)
	if !ok {
		problem(w, 503, "node_inventory_unavailable")
		return true
	}
	inventory, err := provider.Inventory(r.Context())
	if err != nil || inventory.NodeID != s.config.Identity.NodeID || inventory.BootID != s.config.Identity.BootID {
		problem(w, 503, "node_inventory_unavailable")
		return true
	}
	if _, err = lifecycle.NodeInventorySigningBytes(inventory); err != nil {
		problem(w, 503, "node_inventory_invalid")
		return true
	}
	signature, err := base64.RawURLEncoding.DecodeString(inventory.Signature)
	if err != nil || len(signature) != 64 || base64.RawURLEncoding.EncodeToString(signature) != inventory.Signature {
		problem(w, 503, "node_inventory_unsigned")
		return true
	}
	response(w, inventory)
	return true
}
