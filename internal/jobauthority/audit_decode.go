// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/jobaudit"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
)

const MaxAuditBytes = 256 << 20
const MaxAuditRecords = 100000

// decodeAudit has its own bound. Lifecycle transport retains its smaller bound.
// A token pass rejects duplicate/unknown keys and excessive depth/nodes before decoding.
func decodeAudit(raw []byte, b *jobaudit.Bundle) error {
	if len(raw) == 0 || len(raw) > MaxAuditBytes {
		return errors.New("authority_audit_byte_bound")
	}
	check := json.NewDecoder(bytes.NewReader(raw))
	check.UseNumber()
	nodes := 0
	if e := auditValue(check, reflect.TypeOf(*b), 0, &nodes); e != nil {
		return e
	}
	if _, e := check.Token(); e != io.EOF {
		return errors.New("authority_audit_trailing_data")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(b); e != nil {
		return e
	}
	if len(b.Events) > MaxAuditRecords {
		return errors.New("authority_audit_record_bound")
	}
	for _, event := range b.Events {
		if len(event.Raw) == 0 || len(event.Raw) > 65536 {
			return errors.New("authority_audit_raw_bound")
		}
	}
	return nil
}
func auditValue(d *json.Decoder, t reflect.Type, depth int, nodes *int) error {
	*nodes++
	if depth > 32 || *nodes > 4000000 {
		return errors.New("authority_audit_structure_bound")
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	token, e := d.Token()
	if e != nil {
		return e
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return nil
	}
	switch delimiter {
	case '{':
		if t.Kind() != reflect.Struct && t.Kind() != reflect.Map {
			return errors.New("authority_audit_shape_invalid")
		}
		fields := map[string]reflect.Type{}
		if t.Kind() == reflect.Struct {
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				name := strings.Split(f.Tag.Get("json"), ",")[0]
				if name == "" {
					name = f.Name
				}
				if name != "-" {
					fields[name] = f.Type
				}
			}
		}
		seen := map[string]bool{}
		for d.More() {
			keyToken, e := d.Token()
			if e != nil {
				return e
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return errors.New("authority_audit_duplicate_key")
			}
			seen[key] = true
			var child reflect.Type
			if t.Kind() == reflect.Map {
				child = t.Elem()
			} else {
				child = fields[key]
				if child == nil {
					return errors.New("authority_audit_unknown_field")
				}
			}
			if e = auditValue(d, child, depth+1, nodes); e != nil {
				return e
			}
		}
	case '[':
		if t.Kind() != reflect.Slice && t.Kind() != reflect.Array || t.Elem().Kind() == reflect.Uint8 {
			return errors.New("authority_audit_shape_invalid")
		}
		count := 0
		for d.More() {
			count++
			if count > MaxAuditRecords {
				return errors.New("authority_audit_record_bound")
			}
			if e = auditValue(d, t.Elem(), depth+1, nodes); e != nil {
				return e
			}
		}
	default:
		return errors.New("authority_audit_delimiter_invalid")
	}
	_, e = d.Token()
	return e
}

// DecodeAuditBundle applies the same strict bounds as the authority receipt route.
func DecodeAuditBundle(raw []byte) (jobaudit.Bundle, error) {
 var bundle jobaudit.Bundle
 err := decodeAudit(raw, &bundle)
 return bundle, err
}
