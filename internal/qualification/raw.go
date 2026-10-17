// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualification

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Raw schemas belong to the fixed adapter. This common guard rejects ambiguous
// JSON keys and bounds parser work before the adapter sees the evidence.
func checkRaw(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	if err := rawValue(d, 0, &nodes); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("qualification evidence requires one JSON value")
	}
	return nil
}
func rawValue(d *json.Decoder, depth int, nodes *int) error {
	*nodes++
	if depth > 32 || *nodes > 200000 {
		return errors.New("qualification raw evidence structure exceeds the bound")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim == '{' {
		keys := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || keys[name] {
				return errors.New("qualification raw evidence repeats a key")
			}
			keys[name] = true
			if err = rawValue(d, depth+1, nodes); err != nil {
				return err
			}
		}
	} else if delim == '[' {
		for d.More() {
			if err = rawValue(d, depth+1, nodes); err != nil {
				return err
			}
		}
	} else {
		return errors.New("qualification raw evidence has an invalid delimiter")
	}
	_, err = d.Token()
	return err
}
