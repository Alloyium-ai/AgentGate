// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
)

var schemaOnce sync.Once
var bodySchemas map[string]any

func requestSchemas() map[string]any {
	schemaOnce.Do(func() {
		data, _ := json.Marshal(apiSchemas())
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		if err := decoder.Decode(&bodySchemas); err != nil {
			panic(err)
		}
	})
	return bodySchemas
}

func validateRequiredBody(data []byte, dst any) error {
	name := reflect.TypeOf(dst).Elem().Name()
	aliases := map[string]string{"RequestPolicy": "PolicyRequest", "AdmitInput": "Admission", "ActivateInput": "Activation", "IngestInput": "Ingest"}
	if alias := aliases[name]; alias != "" {
		name = alias
	}
	schemas := requestSchemas()
	schema, ok := schemas[name].(map[string]any)
	if !ok {
		return nil
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return fail(422, "invalid_json", "Supply JSON that matches the API contract.")
	}
	return validateSchemaValue(value, schema, schemas, 0)
}

func schemaReference(schema, schemas map[string]any) (map[string]any, error) {
	if ref, ok := schema["$ref"].(string); ok {
		if !strings.HasPrefix(ref, "#/components/schemas/") {
			return nil, fail(503, "schema_unavailable", "The API schema is unavailable.")
		}
		resolved, ok := schemas[strings.TrimPrefix(ref, "#/components/schemas/")].(map[string]any)
		if !ok {
			return nil, fail(503, "schema_unavailable", "The API schema is unavailable.")
		}
		return resolved, nil
	}
	return schema, nil
}
