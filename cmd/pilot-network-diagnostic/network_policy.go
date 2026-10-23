// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"alloyium.local/kernel-poc/internal/pocpolicy"
)

func networkPolicyCommand(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: pilot-network-diagnostic network-info FILE")
	}
	raw, err := os.ReadFile(args[1])
	if err != nil {
		return err
	}
	d, err := pocpolicy.Parse(raw)
	if err != nil {
		return err
	}
	data := struct {
		Digest   string             `json:"digest"`
		Document pocpolicy.Document `json:"document"`
	}{d.Digest(), d}
	encoded, err := json.Marshal(data)
	if err == nil {
		fmt.Println(string(encoded))
	}
	return err
}
