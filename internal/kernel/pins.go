// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package kernel

import (
	"encoding/hex"
	"errors"
	"strings"
)

// mapPinNames preserves existing names and encodes ELF global-data names.
// Linux bpffs reserves dots. Collisions reject before any attachment starts.
func mapPinNames(names []string) (map[string]string, error) {
	result := map[string]string{}
	used := map[string]bool{}
	for _, name := range names {
		if name == "" {
			return nil, errors.New("a fixture map name is empty")
		}
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
				return nil, errors.New("a fixture map name contains an unsupported character")
			}
		}
		pin := name
		if strings.ContainsRune(name, '.') {
			pin = "map-" + hex.EncodeToString([]byte(name))
		}
		if len(pin) > 255 || used[pin] {
			return nil, errors.New("fixture map pin names collide or exceed the filesystem limit")
		}
		used[pin] = true
		result[name] = pin
	}
	return result, nil
}
