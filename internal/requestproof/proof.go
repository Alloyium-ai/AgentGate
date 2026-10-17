// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package requestproof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const Header = `{"alg":"EdDSA","typ":"alloyium-request-proof-v1"}`

var encoding = base64.RawURLEncoding.Strict()

type Claims struct {
	Audience   string `json:"aud"`
	Epoch      string `json:"epoch"`
	Subject    string `json:"sub"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	BodyDigest string `json:"body_sha256"`
	Time       int64  `json:"iat"`
	Nonce      string `json:"nonce"`
}

func Digest(body []byte) string { v := sha256.Sum256(body); return hex.EncodeToString(v[:]) }
func Sign(subject, method, path, audience, epoch string, body []byte, key ed25519.PrivateKey) string {
	v := make([]byte, 32)
	rand.Read(v)
	c := Claims{audience, epoch, subject, method, path, Digest(body), time.Now().Unix(), encoding.EncodeToString(v)}
	data, _ := json.Marshal(c)
	unsigned := encoding.EncodeToString([]byte(Header)) + "." + encoding.EncodeToString(data)
	return unsigned + "." + encoding.EncodeToString(ed25519.Sign(key, []byte(unsigned)))
}
func Parse(token string) (Claims, error) {
	var c Claims
	if len(token) > 4096 {
		return c, errors.New("proof exceeds limit")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, errors.New("invalid proof framing")
	}
	header, err := encoding.DecodeString(parts[0])
	if err != nil || string(header) != Header {
		return c, errors.New("invalid proof algorithm")
	}
	data, err := encoding.DecodeString(parts[1])
	if err != nil {
		return c, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	return c, nil
}
func Verify(token string, key ed25519.PublicKey, audience, epoch, method, path string, body []byte) (Claims, error) {
	c, err := Parse(token)
	if err != nil {
		return c, err
	}
	parts := strings.Split(token, ".")
	sig, err := encoding.DecodeString(parts[2])
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return c, errors.New("invalid proof signature")
	}
	now := time.Now().Unix()
	if c.Audience != audience || c.Epoch != epoch || c.Method != method || c.Path != path || c.BodyDigest != Digest(body) || c.Time > now+5 || c.Time < now-60 || len(c.Nonce) < 32 || len(c.Nonce) > 100 {
		return c, errors.New("proof recipient, epoch, request binding or validity differs")
	}
	return c, nil
}
