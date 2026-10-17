// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
)

var rawMessageType = reflect.TypeFor[json.RawMessage]()

// exactFields runs before encoding/json can match case-folded struct aliases.
// Map keys and opaque RawMessage values retain their declared validation scope.
func exactFields(raw []byte, t reflect.Type) error {
	if t == nil {
		return errors.New("the transport destination type is required")
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == rawMessageType || t.Kind() == reflect.Interface || string(raw) == "null" {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		fields := map[string]reflect.Type{}
		jsonFields(t, fields)
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			return errors.New("the transport object shape is invalid")
		}
		for name, value := range object {
			field, ok := fields[name]
			if !ok {
				return errors.New("the transport field name does not exactly match its JSON contract")
			}
			if err := exactFields(value, field); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8 {
			return nil
		}
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return errors.New("the transport array shape is invalid")
		}
		for _, value := range items {
			if err := exactFields(value, t.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			return errors.New("the transport map shape is invalid")
		}
		for _, value := range object {
			if err := exactFields(value, t.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
func jsonFields(t reflect.Type, out map[string]reflect.Type) {
	for n := 0; n < t.NumField(); n++ {
		f := t.Field(n)
		if f.PkgPath != "" {
			continue
		}
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		nested := f.Type
		for nested.Kind() == reflect.Pointer {
			nested = nested.Elem()
		}
		if f.Anonymous && name == "" && nested.Kind() == reflect.Struct {
			jsonFields(nested, out)
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
}
