// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"go.yaml.in/yaml/v3"
)

const MaxBytes = 65536
const maxDepth = 24
const maxNodes = 4096

var jsonNumber = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,18})$`)

type inputBudget struct{ nodes int }

func ReadJSON(data []byte) (any, error) {
	if len(data) == 0 || len(data) > MaxBytes {
		return nil, errors.New("JSON policy request exceeds its input limit")
	}
	return parseValue(data, "json")
}

func (b *inputBudget) visit(depth int) error {
	b.nodes++
	if depth > maxDepth || b.nodes > maxNodes {
		return errors.New("policy nesting or element limit exceeded")
	}
	return nil
}

// Parse accepts one bounded document. It rejects duplicate keys before decoding.
// YAML uses JSON scalar semantics and rejects tags, anchors, and aliases.
func Parse(data []byte, format string) (Document, error) {
	var document Document
	if len(data) == 0 || len(data) > MaxBytes {
		return document, errors.New("policy size must be between1 and65536 bytes")
	}
	value, err := parseValue(data, format)
	if err != nil {
		return document, err
	}
	if err = validateSchema(value); err != nil {
		return document, err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return document, err
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&document); err != nil {
		return document, err
	}
	return document, document.Validate()
}
func parseValue(data []byte, format string) (any, error) {
	budget := &inputBudget{}
	switch format {
	case "json":
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		value, err := readJSON(decoder, budget, 0)
		if err != nil {
			return nil, err
		}
		if _, err = decoder.Token(); err != io.EOF {
			return nil, errors.New("one JSON policy document required")
		}
		return value, nil
	case "yaml":
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		var node yaml.Node
		if err := decoder.Decode(&node); err != nil {
			return nil, err
		}
		var extra yaml.Node
		if err := decoder.Decode(&extra); err != io.EOF {
			return nil, errors.New("one YAML policy document required")
		}
		return readYAML(&node, budget, 0)
	default:
		return nil, errors.New("policy format must be json or yaml")
	}
}
func readJSON(decoder *json.Decoder, budget *inputBudget, depth int) (any, error) {
	if err := budget.visit(depth); err != nil {
		return nil, err
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		if number, numeric := token.(json.Number); numeric && !jsonNumber.MatchString(string(number)) {
			return nil, errors.New("policy numbers require bounded decimal integer literals")
		}
		return token, nil
	}
	switch delimiter {
	case '{':
		return readJSONObject(decoder, budget, depth)
	case '[':
		result := []any{}
		for decoder.More() {
			value, err := readJSON(decoder, budget, depth+1)
			if err != nil {
				return nil, err
			}
			result = append(result, value)
		}
		_, err = decoder.Token()
		return result, err
	default:
		return nil, errors.New("unexpected JSON delimiter")
	}
}
func readJSONObject(decoder *json.Decoder, budget *inputBudget, depth int) (any, error) {
	result := map[string]any{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := token.(string)
		if !ok {
			return nil, errors.New("JSON object key must be a string")
		}
		if _, exists := result[name]; exists {
			return nil, fmt.Errorf("duplicate policy key %q", name)
		}
		value, err := readJSON(decoder, budget, depth+1)
		if err != nil {
			return nil, err
		}
		result[name] = value
	}
	_, err := decoder.Token()
	return result, err
}
func readYAML(node *yaml.Node, budget *inputBudget, depth int) (any, error) {
	if err := budget.visit(depth); err != nil {
		return nil, err
	}
	if node.Anchor != "" || node.Kind == yaml.AliasNode || node.Style&yaml.TaggedStyle != 0 {
		return nil, errors.New("YAML tags, anchors, and aliases are unsupported")
	}
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) != 1 {
			return nil, errors.New("one YAML policy object required")
		}
		return readYAML(node.Content[0], budget, depth+1)
	case yaml.MappingNode:
		return readYAMLMap(node, budget, depth)
	case yaml.SequenceNode:
		result := []any{}
		for _, child := range node.Content {
			value, err := readYAML(child, budget, depth+1)
			if err != nil {
				return nil, err
			}
			result = append(result, value)
		}
		return result, nil
	case yaml.ScalarNode:
		return yamlScalar(node)
	default:
		return nil, errors.New("unsupported YAML element")
	}
}
func readYAMLMap(node *yaml.Node, budget *inputBudget, depth int) (any, error) {
	result := map[string]any{}
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Anchor != "" || key.Style&yaml.TaggedStyle != 0 || key.Value == "<<" {
			return nil, errors.New("YAML object keys must be plain strings")
		}
		if _, exists := result[key.Value]; exists {
			return nil, fmt.Errorf("duplicate policy key %q", key.Value)
		}
		value, err := readYAML(node.Content[i+1], budget, depth+1)
		if err != nil {
			return nil, err
		}
		result[key.Value] = value
	}
	return result, nil
}
func yamlScalar(node *yaml.Node) (any, error) {
	switch node.Tag {
	case "!!str":
		return node.Value, nil
	case "!!bool":
		if node.Value == "true" {
			return true, nil
		}
		if node.Value == "false" {
			return false, nil
		}
	case "!!int", "!!float":
		if jsonNumber.MatchString(node.Value) {
			return json.Number(node.Value), nil
		}
	case "!!null":
		if node.Value == "null" {
			return nil, nil
		}
	}
	return nil, errors.New("YAML scalar must use an explicit JSON-compatible type and value")
}
