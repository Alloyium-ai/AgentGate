// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Requirements derives capabilities from the same schema that the API and UI use.
func Requirements(document Document) ([]string, error) {
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	var value any
	var schema map[string]any
	if err = json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(schemaBytes, &schema); err != nil {
		return nil, err
	}
	required := map[string]bool{}
	if err = collectRequirements(schema, value, schema, required); err != nil {
		return nil, err
	}
	result := []string{}
	for capability := range required {
		result = append(result, capability)
	}
	sort.Strings(result)
	return result, nil
}
func collectRequirements(node map[string]any, value any, root map[string]any, result map[string]bool) error {
	if capability, ok := node["x-capability"].(string); ok {
		result[capability] = true
	}
	if options, ok := node["x-value-capabilities"].(map[string]any); ok {
		name, ok := value.(string)
		if !ok {
			return errors.New("capability selector must be a string")
		}
		capability, ok := options[name].(string)
		if !ok {
			return fmt.Errorf("unregistered capability selector %q", name)
		}
		result[capability] = true
	}
	if reference, ok := node["$ref"].(string); ok {
		target, err := schemaReference(root, reference)
		if err != nil {
			return err
		}
		return collectRequirements(target, value, root, result)
	}
	switch input := value.(type) {
	case map[string]any:
		properties, _ := node["properties"].(map[string]any)
		for name, item := range input {
			if property, ok := properties[name].(map[string]any); ok {
				if err := collectRequirements(property, item, root, result); err != nil {
					return err
				}
			}
		}
	case []any:
		if items, ok := node["items"].(map[string]any); ok {
			for _, item := range input {
				if err := collectRequirements(items, item, root, result); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func schemaReference(root map[string]any, reference string) (map[string]any, error) {
	if !strings.HasPrefix(reference, "#/$defs/") {
		return nil, errors.New("policy schema contains an external reference")
	}
	definitions, _ := root["$defs"].(map[string]any)
	result, ok := definitions[strings.TrimPrefix(reference, "#/$defs/")].(map[string]any)
	if !ok {
		return nil, errors.New("policy schema reference is unavailable")
	}
	return result, nil
}
func (document Document) CheckDeclaredRequirements() error {
	required, err := Requirements(document)
	if err != nil {
		return err
	}
	declared := append([]string{}, document.RequiredCapabilities...)
	sort.Strings(declared)
	if len(required) != len(declared) {
		return errors.New("required_capabilities must equal the capabilities derived from this policy")
	}
	for i, capability := range required {
		if declared[i] != capability {
			return fmt.Errorf("required capability %s differs from the declared set", capability)
		}
	}
	return nil
}
func NewSelected(rights Selected) Document {
	document := Document{SchemaVersion: Version, Profile: SelectedProfile, Selected: &rights, RequiredCapabilities: []string{}}
	document.RequiredCapabilities, _ = Requirements(document)
	return document
}

func CapabilityIDs() ([]string, error) {
	var schema any
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		return nil, err
	}
	result := map[string]bool{}
	collectCatalog(schema, result)
	ids := []string{}
	for id := range result {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}
func collectCatalog(value any, result map[string]bool) {
	switch node := value.(type) {
	case map[string]any:
		if id, ok := node["x-capability"].(string); ok {
			result[id] = true
		}
		if options, ok := node["x-value-capabilities"].(map[string]any); ok {
			for _, value := range options {
				if id, ok := value.(string); ok {
					result[id] = true
				}
			}
		}
		for _, child := range node {
			collectCatalog(child, result)
		}
	case []any:
		for _, child := range node {
			collectCatalog(child, result)
		}
	}
}
