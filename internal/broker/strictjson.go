// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// decodeStrict decodes exactly one JSON object into v. It rejects documents
// over limit bytes, duplicate keys, keys that are not lowercase ASCII (encoding/json
// matches field names case-insensitively, so "Version" and "version" would
// otherwise alias one field), null anywhere, unknown fields and trailing data.
func decodeStrict(raw []byte, limit int, v any) error {
	if len(raw) == 0 || len(raw) > limit {
		return errors.New("document is empty or exceeds its size bound")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	first, err := dec.Token()
	if err != nil {
		return errors.New("document is not valid JSON")
	}
	if d, ok := first.(json.Delim); !ok || d != '{' {
		return errors.New("document must be one JSON object")
	}
	if err := walkStrict(dec, '{', 1); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("document has trailing data")
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("document does not match the schema")
	}
	return nil
}

func walkStrict(dec *json.Decoder, delim json.Delim, depth int) error {
	if depth > 16 {
		return errors.New("document nests too deeply")
	}
	keys := map[string]bool{}
	for dec.More() {
		if delim == '{' {
			token, err := dec.Token()
			if err != nil {
				return errors.New("document is not valid JSON")
			}
			key, ok := token.(string)
			if !ok || !lowerKey(key) {
				return errors.New("object keys must be lowercase ASCII names")
			}
			if keys[key] {
				return errors.New("document has a duplicate key")
			}
			keys[key] = true
		}
		token, err := dec.Token()
		if err != nil {
			return errors.New("document is not valid JSON")
		}
		switch t := token.(type) {
		case nil:
			return errors.New("null is not allowed")
		case json.Delim:
			if t != '{' && t != '[' {
				return errors.New("document is not valid JSON")
			}
			if err := walkStrict(dec, t, depth+1); err != nil {
				return err
			}
		}
	}
	end, err := dec.Token()
	if err != nil {
		return errors.New("document is not valid JSON")
	}
	if d, ok := end.(json.Delim); !ok || (delim == '{' && d != '}') || (delim == '[' && d != ']') {
		return errors.New("document is not valid JSON")
	}
	return nil
}

func lowerKey(key string) bool {
	if key == "" || len(key) > 64 {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
