// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
)

// DecodeTransport rejects duplicate and unknown fields before typed decoding.
// Its larger bound permits the separately hashed agent input in a run request.
func DecodeTransport(reader io.Reader, destination any) error {
	raw, err := io.ReadAll(io.LimitReader(reader, (2<<20)+1))
	if err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > 2<<20 {
		return errors.New("the lifecycle request exceeds its byte bound")
	}
	check := json.NewDecoder(bytes.NewReader(raw))
	check.UseNumber()
	nodes := 0
	if err = uniqueValue(check, 0, &nodes); err != nil {
		return err
	}
	if _, err = check.Token(); err != io.EOF {
		return errors.New("one lifecycle request is required")
	}
	if err = exactFields(raw, reflect.TypeOf(destination)); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination)
}
func uniqueValue(decoder *json.Decoder, depth int, nodes *int) error {
	*nodes++
	if depth > 32 || *nodes > 16384 {
		return errors.New("the lifecycle request exceeds its structural bound")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]bool{}
		for decoder.More() {
			token, err = decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || keys[key] {
				return errors.New("the lifecycle request contains a duplicate key")
			}
			keys[key] = true
			if err = uniqueValue(decoder, depth+1, nodes); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err = uniqueValue(decoder, depth+1, nodes); err != nil {
				return err
			}
		}
	default:
		return errors.New("the lifecycle request contains an unexpected delimiter")
	}
	_, err = decoder.Token()
	return err
}
