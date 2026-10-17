// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"encoding/json"
	"math"
	"reflect"
	"regexp"
	"unicode/utf8"
)

func schemaInvalid() error {
	return fail(422, "schema_constraint", "A request value does not match the API contract.")
}

func validateSchemaValue(value any, schema, schemas map[string]any, depth int) error {
	if depth > 64 {
		return schemaInvalid()
	}
	resolved, err := schemaReference(schema, schemas)
	if err != nil {
		return err
	}
	schema = resolved
	if !schemaTypeMatches(value, schema["type"], schema["nullable"] == true) {
		return schemaInvalid()
	}
	if options, ok := schema["enum"].([]any); ok {
		matched := false
		for _, option := range options {
			if schemaEqual(value, option) {
				matched = true
				break
			}
		}
		if !matched {
			return schemaInvalid()
		}
	}
	switch v := value.(type) {
	case map[string]any:
		return validateSchemaObject(v, schema, schemas, depth)
	case []any:
		return validateSchemaArray(v, schema, schemas, depth)
	case string:
		if !schemaLength(utf8.RuneCountInString(v), schema, "minLength", "maxLength") {
			return schemaInvalid()
		}
		if pattern, ok := schema["pattern"].(string); ok {
			rule, err := regexp.Compile(pattern)
			if err != nil {
				return fail(503, "schema_unavailable", "The API schema is unavailable.")
			}
			if !rule.MatchString(v) {
				return schemaInvalid()
			}
		}
	case json.Number:
		return validateSchemaNumber(v, schema)
	}
	return nil
}

func schemaTypeMatches(value, kind any, nullable bool) bool {
	if value == nil && nullable {
		return true
	}
	if kinds, ok := kind.([]any); ok {
		for _, item := range kinds {
			if schemaTypeMatches(value, item, false) {
				return true
			}
		}
		return false
	}
	if kind == nil {
		return true
	}
	switch kind {
	case "null":
		return value == nil
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "number", "integer":
		n, ok := value.(json.Number)
		if !ok {
			return false
		}
		f, err := n.Float64()
		return err == nil && !math.IsInf(f, 0) && (kind == "number" || math.Trunc(f) == f)
	}
	return false
}

func schemaLength(length int, schema map[string]any, min, max string) bool {
	if n, ok := schema[min].(json.Number); ok {
		value, err := n.Int64()
		if err != nil || int64(length) < value {
			return false
		}
	}
	if n, ok := schema[max].(json.Number); ok {
		value, err := n.Int64()
		if err != nil || int64(length) > value {
			return false
		}
	}
	return true
}

func schemaEqual(a, b any) bool {
	left, lok := a.(json.Number)
	right, rok := b.(json.Number)
	if lok && rok {
		x, e := left.Float64()
		y, f := right.Float64()
		return e == nil && f == nil && x == y
	}
	return reflect.DeepEqual(a, b)
}

func validateSchemaObject(value map[string]any, schema, schemas map[string]any, depth int) error {
	if !schemaLength(len(value), schema, "minProperties", "maxProperties") {
		return schemaInvalid()
	}
	if required, ok := schema["required"].([]any); ok {
		for _, name := range required {
			if _, exists := value[name.(string)]; !exists {
				return fail(422, "required_field", "The request omits a required field.")
			}
		}
	}
	properties, _ := schema["properties"].(map[string]any)
	for name, item := range value {
		property, known := properties[name].(map[string]any)
		if !known {
			if schema["additionalProperties"] == false {
				return schemaInvalid()
			}
			property, _ = schema["additionalProperties"].(map[string]any)
		}
		if property != nil {
			if err := validateSchemaValue(item, property, schemas, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateSchemaArray(value []any, schema, schemas map[string]any, depth int) error {
	if !schemaLength(len(value), schema, "minItems", "maxItems") {
		return schemaInvalid()
	}
	items, _ := schema["items"].(map[string]any)
	for i, item := range value {
		if items != nil {
			if err := validateSchemaValue(item, items, schemas, depth+1); err != nil {
				return err
			}
		}
		if schema["uniqueItems"] == true {
			for _, previous := range value[:i] {
				if schemaEqual(item, previous) {
					return schemaInvalid()
				}
			}
		}
	}
	return nil
}

func validateSchemaNumber(value json.Number, schema map[string]any) error {
	n, err := value.Float64()
	if err != nil || math.IsInf(n, 0) {
		return schemaInvalid()
	}
	for _, bound := range []struct {
		key              string
		lower, exclusive bool
	}{{"minimum", true, false}, {"maximum", false, false}, {"exclusiveMinimum", true, true}, {"exclusiveMaximum", false, true}} {
		if limit, ok := schema[bound.key].(json.Number); ok {
			f, err := limit.Float64()
			if err != nil {
				return schemaInvalid()
			}
			if bound.lower && (n < f || bound.exclusive && n == f) || !bound.lower && (n > f || bound.exclusive && n == f) {
				return schemaInvalid()
			}
		}
	}
	return nil
}
