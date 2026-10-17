// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"alloyium.local/kernel-poc/internal/controlclient"
	"alloyium.local/kernel-poc/internal/grant"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

func nodeKeys(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errors.New("keys require a fresh absolute private directory")
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	public := map[string]string{}
	for _, name := range []string{"node", "agent"} {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		file, err := os.OpenFile(filepath.Join(dir, name+".key"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if _, err = file.Write(key); err == nil {
			err = file.Sync()
		}
		file.Close()
		if err != nil {
			return err
		}
		public[name] = controlclient.EncodeKey(pub)
	}
	data, err := json.Marshal(public)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "public-keys.json"), data, 0600); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func requestWorkload(args []string) error {
	if len(args) != 3 {
		return errors.New("request requires a private agent configuration, published version id and reason")
	}
	var cfg controlclient.Config
	if err := privateDeclaration(args[0], &cfg); err != nil {
		return err
	}
	client, err := controlclient.New(cfg)
	if err != nil {
		return err
	}
	key, err := grant.Nonce()
	if err != nil {
		return err
	}
	var response json.RawMessage
	if err = client.Call("requests", "POST", key, map[string]string{"version_id": args[1], "reason": args[2]}, &response); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(response)
}
