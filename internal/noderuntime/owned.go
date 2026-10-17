// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func canonical(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && path != "/tmp" && !strings.HasPrefix(path, "/tmp/")
}
func parents(path string) error {
	if !canonical(path) {
		return errors.New("a canonical protected node path is required")
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		var st unix.Stat_t
		if err := unix.Lstat(dir, &st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&022 != 0 {
			return errors.New("the node path parent custody differs")
		}
		if dir == "/" {
			return nil
		}
	}
}
func readOwned(path string, max int64, private bool) ([]byte, error) {
	if max <= 0 || max > 2<<20 {
		return nil, errors.New("the node file bound is invalid")
	}
	if err := parents(path); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&022 != 0 || (private && st.Mode&077 != 0) || st.Size <= 0 || st.Size > max {
		return nil, errors.New("the node file custody or size differs")
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != st.Size || int64(len(raw)) > max {
		return nil, errors.New("the node file size changed")
	}
	return raw, nil
}
func publicKey(raw string) (ed25519.PublicKey, error) {
	key, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(key) != raw {
		return nil, errors.New("a canonical pinned Ed25519 public key is required")
	}
	return ed25519.PublicKey(key), nil
}
func privateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := readOwned(path, ed25519.PrivateKeySize, true)
	if err != nil {
		return nil, err
	}
	if len(raw) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(raw), nil
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("the node private key size differs")
	}
	key := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
	if subtle.ConstantTimeCompare(key, raw) != 1 {
		return nil, errors.New("the node private key is inconsistent")
	}
	return key, nil
}
func pinnedKeys(raw map[string]string) (map[string]ed25519.PublicKey, error) {
	if len(raw) == 0 || len(raw) > 64 {
		return nil, errors.New("the node signing registry is absent or excessive")
	}
	out := map[string]ed25519.PublicKey{}
	for id, value := range raw {
		if len(id) > 257 || strings.Count(id, "/") != 1 {
			return nil, errors.New("the signing registry identity differs")
		}
		key, err := publicKey(value)
		if err != nil {
			return nil, err
		}
		out[id] = key
	}
	return out, nil
}
