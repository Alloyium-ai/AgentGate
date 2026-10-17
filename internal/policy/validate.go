// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
)

func (d Document) Validate() error {
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	value, err := parseValue(raw, "json")
	if err != nil {
		return err
	}
	if err = validateSchema(value); err != nil {
		return err
	}
	if d.Profile == SelectedProfile {
		return validateSelected(*d.Selected)
	}
	ids := map[string]bool{}
	if err = validateFiles(*d.Files, ids); err != nil {
		return err
	}
	if err = validatePrograms(*d.Programs, ids); err != nil {
		return err
	}
	if err = validateNetwork(*d.Network, ids); err != nil {
		return err
	}
	return validateSockets(*d.Sockets, ids)
}
func validateSelected(selected Selected) error {
	address, err := netip.ParseAddr(selected.TCPAddress)
	if err != nil || !unicast(address) || !address.Is4() || address.String() != selected.TCPAddress {
		return errors.New("selected target must be one canonical unicast IPv4 address")
	}
	return nil
}
func unicast(address netip.Addr) bool {
	return address.IsValid() && !address.IsUnspecified() && !address.IsMulticast() && !address.Is4In6() && address != netip.MustParseAddr("255.255.255.255")
}
func validateSelector(selector Selector) error {
	if !filepath.IsAbs(selector.Path) || filepath.Clean(selector.Path) != selector.Path || strings.ContainsRune(selector.Path, 0) {
		return errors.New("file selector must use a canonical absolute path")
	}
	return nil
}
func uniqueRule(id string, ids map[string]bool) error {
	if ids[id] {
		return fmt.Errorf("duplicate rule id %q", id)
	}
	ids[id] = true
	return nil
}
func validateFiles(files Files, ids map[string]bool) error {
	for _, rule := range files.Rules {
		if err := uniqueRule(rule.ID, ids); err != nil {
			return err
		}
		if err := validateSelector(rule.Selector); err != nil {
			return fmt.Errorf("file rule %s: %w", rule.ID, err)
		}
	}
	return nil
}
func validatePrograms(programs Programs, ids map[string]bool) error {
	for _, rule := range programs.Rules {
		if err := uniqueRule(rule.ID, ids); err != nil {
			return err
		}
		if err := validateSelector(rule.Selector); err != nil {
			return fmt.Errorf("program rule %s: %w", rule.ID, err)
		}
		if rule.Approval != nil && (rule.Effect != "allow" || rule.Selector.Kind != "exact") {
			return errors.New("an approval requires an exact executable allow rule")
		}
	}
	return nil
}
func validateNetwork(network Network, ids map[string]bool) error {
	for _, rule := range network.Rules {
		if err := uniqueRule(rule.ID, ids); err != nil {
			return err
		}
		if rule.PortFrom > rule.PortTo {
			return fmt.Errorf("network rule %s: port range is reversed", rule.ID)
		}
		if err := validateDestination(rule); err != nil {
			return fmt.Errorf("network rule %s: %w", rule.ID, err)
		}
	}
	return nil
}
func validateDestination(rule NetworkRule) error {
	destination := rule.Destination
	if destination.Kind == "hostname" {
		if !validHostname(destination.Value) {
			return errors.New("hostname must use canonical lower-case DNS labels")
		}
		return nil
	}
	var address netip.Addr
	if destination.Kind == "ip" {
		parsed, err := netip.ParseAddr(destination.Value)
		if err != nil || parsed.String() != destination.Value {
			return errors.New("address must use canonical IP notation")
		}
		address = parsed
	} else {
		prefix, err := netip.ParsePrefix(destination.Value)
		if err != nil || prefix.Masked().String() != destination.Value {
			return errors.New("prefix must use canonical masked CIDR notation")
		}
		address = prefix.Addr()
	}
	if !address.IsValid() || address.Is4In6() || address.Is4() != (rule.Family == "ipv4") {
		return errors.New("destination and address family must match")
	}
	if destination.Kind == "ip" && !unicast(address) {
		return errors.New("literal destination must be unicast")
	}
	if destination.Kind == "prefix" && (address.IsMulticast() || address == netip.MustParseAddr("255.255.255.255")) {
		return errors.New("multicast and limited-broadcast prefixes are unsupported")
	}
	return nil
}
func validHostname(value string) bool {
	if value != strings.ToLower(value) || len(value) > 253 || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	_, err := netip.ParseAddr(value)
	return err != nil
}

// FileEffect defines compiler precedence. It does not claim a loaded kernel hook.
func FileEffect(files Files, path, operation string) string {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		return "deny"
	}
	if !registeredFileOperation(operation) {
		return "deny"
	}
	effect := "deny"
	specificity := -1
	for _, rule := range files.Rules {
		if !selectorMatches(rule.Selector, path) || !hasOperation(rule.Operations, operation) {
			continue
		}
		size := len(rule.Selector.Path)
		if size > specificity || (size == specificity && rule.Effect == "deny") {
			effect = rule.Effect
			specificity = size
		}
	}
	return effect
}
func registeredFileOperation(operation string) bool {
	var root map[string]any
	if json.Unmarshal(schemaBytes, &root) != nil {
		return false
	}
	definition, err := schemaReference(root, "#/$defs/file_operation")
	if err != nil {
		return false
	}
	values, _ := definition["enum"].([]any)
	for _, value := range values {
		if value == operation {
			return true
		}
	}
	return false
}
func selectorMatches(selector Selector, path string) bool {
	if path == selector.Path {
		return true
	}
	return selector.Kind == "subtree" && (selector.Path == "/" || strings.HasPrefix(path, selector.Path+"/"))
}
func hasOperation(operations []string, expected string) bool {
	for _, operation := range operations {
		if operation == expected {
			return true
		}
	}
	return false
}
