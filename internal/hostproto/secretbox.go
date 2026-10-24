// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// Secret sealing: a client encrypts a secret value to the target host's X25519
// key, so the service relays ciphertext it cannot read.
//
//	sealed = 0x01 || ephemeral_public(32) || nonce(12) || AES-256-GCM(value, aad)
//	key    = HKDF-SHA256(X25519(ephemeral, host), salt = ephemeral_public || host_public, info = "agentgate-secret-v1")
//	aad    = "agentgate-secret-v1" 0x00 target_id 0x00 secret_name
const (
	secretInfo   = "agentgate-secret-v1"
	sealVersion  = 1
	sealOverhead = 1 + 32 + 12 + 16
)

// SecretAAD binds a sealed secret to one target and name.
func SecretAAD(targetID, name string) []byte {
	return []byte(secretInfo + "\x00" + targetID + "\x00" + name)
}

func secretKey(shared, ephemeral, host []byte) ([]byte, error) {
	salt := append(append([]byte{}, ephemeral...), host...)
	return hkdf.Key(sha256.New, shared, salt, secretInfo, 32)
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// SealSecret encrypts value to hostPublic (a raw X25519 public key). It returns
// raw bytes; the wire form is unpadded base64url (EncodeSealed).
func SealSecret(hostPublic []byte, value, aad []byte, random io.Reader) ([]byte, error) {
	if len(value) == 0 || len(value) > MaxSecretBytes {
		return nil, errors.New("hostproto: a secret value is 1 to 8192 bytes")
	}
	if random == nil {
		random = rand.Reader
	}
	host, err := ecdh.X25519().NewPublicKey(hostPublic)
	if err != nil {
		return nil, errors.New("hostproto: invalid host encryption key")
	}
	seed := make([]byte, 32)
	if _, err = io.ReadFull(random, seed); err != nil {
		return nil, err
	}
	ephemeral, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, err
	}
	shared, err := ephemeral.ECDH(host)
	if err != nil {
		return nil, err
	}
	key, err := secretKey(shared, ephemeral.PublicKey().Bytes(), hostPublic)
	if err != nil {
		return nil, err
	}
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err = io.ReadFull(random, nonce); err != nil {
		return nil, err
	}
	out := append([]byte{sealVersion}, ephemeral.PublicKey().Bytes()...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, value, aad), nil
}

// OpenSecret decrypts a SealSecret output with the host's X25519 private key.
func OpenSecret(hostPrivate *ecdh.PrivateKey, sealed, aad []byte) ([]byte, error) {
	if hostPrivate == nil || len(sealed) < sealOverhead || len(sealed) > MaxSecretBytes+sealOverhead || sealed[0] != sealVersion {
		return nil, errors.New("hostproto: sealed secret framing invalid")
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(sealed[1:33])
	if err != nil {
		return nil, errors.New("hostproto: sealed secret key invalid")
	}
	shared, err := hostPrivate.ECDH(ephemeral)
	if err != nil {
		return nil, errors.New("hostproto: sealed secret key invalid")
	}
	key, err := secretKey(shared, sealed[1:33], hostPrivate.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	value, err := aead.Open(nil, sealed[33:45], sealed[45:], aad)
	if err != nil {
		return nil, errors.New("hostproto: sealed secret does not open")
	}
	return value, nil
}

// CheckSealed validates the framing of a sealed secret without opening it.
func CheckSealed(sealed []byte) error {
	if len(sealed) < sealOverhead || len(sealed) > MaxSecretBytes+sealOverhead || sealed[0] != sealVersion {
		return errors.New("hostproto: sealed secret framing invalid")
	}
	if _, err := ecdh.X25519().NewPublicKey(sealed[1:33]); err != nil {
		return errors.New("hostproto: sealed secret key invalid")
	}
	return nil
}

// EncodeSealed and DecodeSealed move a sealed secret as unpadded base64url.
func EncodeSealed(sealed []byte) string { return b64.EncodeToString(sealed) }

// DecodeSealed decodes and frames a sealed secret.
func DecodeSealed(value string) ([]byte, error) {
	if len(value) > (MaxSecretBytes+sealOverhead)*4/3+4 {
		return nil, errors.New("hostproto: sealed secret too large")
	}
	raw, err := b64.DecodeString(value)
	if err != nil {
		return nil, errors.New("hostproto: sealed secret encoding invalid")
	}
	return raw, CheckSealed(raw)
}
