// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"alloyium.local/kernel-poc/internal/control"
)

// fill sets every exported field of v to a non-zero value, so that a JSON
// encoding carries every field, including omitempty ones.
func fill(v reflect.Value, depth int) {
	if depth > 6 {
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		fill(v.Elem(), depth+1)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				fill(v.Field(i), depth+1)
			}
		}
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64, reflect.Int32, reflect.Uint32, reflect.Uint64:
		if v.CanInt() {
			v.SetInt(1)
		} else {
			v.SetUint(1)
		}
	case reflect.Slice:
		if v.Type() == reflect.TypeOf(json.RawMessage{}) {
			v.SetBytes([]byte(`{}`))
			return
		}
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fill(s.Index(0), depth+1)
		v.Set(s)
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		k, e := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
		fill(k, depth+1)
		if e.Kind() == reflect.Interface {
			e.Set(reflect.ValueOf("x"))
		} else {
			fill(e, depth+1)
		}
		m.SetMapIndex(k, e)
		v.Set(m)
	}
}

// TestAPITypesCover decodes every service response type into the CLI's type
// with unknown fields disallowed: a field the service adds or renames fails
// here until the CLI handles it, so --json and human output keep the API's
// field names.
func TestAPITypesCover(t *testing.T) {
	pairs := []struct {
		name    string
		service any
		cli     any
	}{
		{"Target", &control.Target{}, &Target{}},
		{"Profile", &control.Profile{}, &Profile{}},
		{"ProfileVersion", &control.ProfileVersion{}, &ProfileVersion{}},
		{"LaunchPlan", &control.LaunchPlan{}, &LaunchPlan{}},
		{"Permissions", &control.Permissions{}, &Permissions{}},
		{"PlanSecret", &control.PlanSecret{}, &PlanSecret{}},
		{"Launch", &control.Launch{}, &Launch{}},
		{"JobRecord", &control.JobRecord{}, &Job{}},
		{"LaunchEvent", &control.LaunchEvent{}, &LaunchEvent{}},
		{"LogLine", &control.LogLine{}, &LogLine{}},
		{"Secret", &control.Secret{}, &Secret{}},
		{"APIToken", &control.APIToken{}, &APIToken{}},
		{"AuditEntry", &control.AuditEntry{}, &AuditEntry{}},
	}
	for _, p := range pairs {
		fill(reflect.ValueOf(p.service), 0)
		raw, err := json.Marshal(p.service)
		if err != nil {
			t.Fatalf("%s: %v", p.name, err)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(p.cli); err != nil {
			t.Errorf("%s: the CLI type does not cover the service's fields: %v\n%s", p.name, err, raw)
		}
		back, _ := json.Marshal(p.cli)
		var a, b map[string]any
		json.Unmarshal(raw, &a)
		json.Unmarshal(back, &b)
		for k := range a {
			if _, ok := b[k]; !ok {
				t.Errorf("%s: field %q is lost when the CLI re-encodes it", p.name, k)
			}
		}
	}
}
