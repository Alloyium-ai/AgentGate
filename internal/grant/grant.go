// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// The trusted local manager issues a grant. Workers cannot reach this signer.
package grant

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const Issuer = "alloyium-local-poc-authority-v1"
const Audience = "alloyium-kernel-poc-v1"
const header = `{"alg":"EdDSA","typ":"JWT","kid":"poc-authority-v1"}`

var encoding = base64.RawURLEncoding

type Claims struct {
	Issuer        string `json:"iss"`
	Audience      string `json:"aud"`
	Deployment    string `json:"deployment"`
	Node          string `json:"node"`
	Boot          string `json:"boot"`
	Run           string `json:"run"`
	Domain        string `json:"cgroup"`
	Agent         string `json:"agent"`
	AgentKey      string `json:"agent_key"`
	JobDigest     string `json:"job_digest"`
	Generation    string `json:"generation"`
	Workspace     string `json:"workspace"`
	Endpoint      string `json:"endpoint"`
	DeadlineNS    string `json:"deadline_ns"`
	Issued        int64  `json:"iat"`
	Expires       int64  `json:"exp"`
	Nonce         string `json:"jti"`
	PolicyVersion string `json:"policy_version,omitempty"`
	PolicyDigest  string `json:"policy_digest,omitempty"`
	ReadOnly      bool   `json:"read_only,omitempty"`
}

type Trust struct {
	Authority string `json:"authority"`
	Node      string `json:"node"`
	Agent     string `json:"agent"`
}

type Keys struct {
	Authority, Node ed25519.PrivateKey
	Trust           Trust
}

func Digest(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }

func Init(dir string) error {
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	keys := Keys{}
	agent, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	keys.Trust.Agent = encoding.EncodeToString(agent)
	for _, item := range []struct {
		name string
		dest *ed25519.PrivateKey
	}{{"authority.key", &keys.Authority}, {"node.key", &keys.Node}} {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(dir, item.name), key, 0600); err != nil {
			return err
		}
		*item.dest = key
		if item.name == "authority.key" {
			keys.Trust.Authority = encoding.EncodeToString(pub)
		} else {
			keys.Trust.Node = encoding.EncodeToString(pub)
		}
	}
	data, err := json.Marshal(keys.Trust)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "trust.json"), data, 0644)
}

func Load(dir string) (Keys, error) {
	var k Keys
	for _, item := range []struct {
		name string
		dest *ed25519.PrivateKey
	}{{"authority.key", &k.Authority}, {"node.key", &k.Node}} {
		name := filepath.Join(dir, item.name)
		info, err := os.Stat(name)
		if err != nil {
			return k, err
		}
		if info.Mode().Perm() != 0600 {
			return k, errors.New("private key mode must be 0600")
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return k, err
		}
		if len(data) != ed25519.PrivateKeySize {
			return k, errors.New("invalid private key length")
		}
		*item.dest = data
	}
	data, err := os.ReadFile(filepath.Join(dir, "trust.json"))
	if err != nil {
		return k, err
	}
	if err = json.Unmarshal(data, &k.Trust); err != nil {
		return k, err
	}
	if k.Trust.Authority != encoding.EncodeToString(k.Authority.Public().(ed25519.PublicKey)) || k.Trust.Node != encoding.EncodeToString(k.Node.Public().(ed25519.PublicKey)) {
		return k, errors.New("key differs from pinned trust")
	}
	return k, nil
}

func Public(value string) (ed25519.PublicKey, error) {
	key, err := encoding.DecodeString(value)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid pinned public key")
	}
	return key, nil
}

func Sign(c Claims, key ed25519.PrivateKey) (string, error) {
	if err := Validate(c, time.Now().Unix()); err != nil {
		return "", err
	}
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	unsigned := encoding.EncodeToString([]byte(header)) + "." + encoding.EncodeToString(body)
	return unsigned + "." + encoding.EncodeToString(ed25519.Sign(key, []byte(unsigned))), nil
}

func Verify(token string, key ed25519.PublicKey, expected Claims, now int64) (Claims, error) {
	var c Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(token) > 4096 {
		return c, errors.New("invalid compact grant")
	}
	h, err := encoding.DecodeString(parts[0])
	if err != nil || string(h) != header {
		return c, errors.New("untrusted grant header")
	}
	signature, err := encoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
		return c, errors.New("grant signature failed")
	}
	body, err := encoding.DecodeString(parts[1])
	if err != nil {
		return c, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&c); err != nil {
		return c, err
	}
	canonical, err := json.Marshal(c)
	if err != nil || string(canonical) != string(body) {
		return c, errors.New("noncanonical grant body")
	}
	if err = Validate(c, now); err != nil {
		return c, err
	}
	if c != expected {
		return c, errors.New("grant differs from trusted manager enrollment")
	}
	return c, nil
}

func Validate(c Claims, now int64) error {
	if c.Issuer != Issuer || c.Audience != Audience || (c.Deployment != "disposable-dev-poc" && c.Deployment != "agentgate-community-v1") {
		return errors.New("grant trust boundary differs")
	}
	if c.Issued > now+2 || c.Expires <= now || c.Expires-c.Issued > 60 || c.Expires <= c.Issued {
		return errors.New("grant validity failed")
	}
	if c.Node == "" || c.Boot == "" || c.Run == "" || c.Domain == "" || c.Agent == "" || len(c.Nonce) != 32 || len(c.JobDigest) != 64 {
		return errors.New("grant identity incomplete")
	}
	if _, err := hex.DecodeString(c.Nonce); err != nil {
		return err
	}
	if _, err := Public(c.AgentKey); err != nil {
		return err
	}
	if !filepath.IsAbs(c.Workspace) || !strings.HasSuffix(c.Workspace, "/") || strings.ContainsRune(c.Workspace, 0) || filepath.Clean(c.Workspace)+"/" != c.Workspace || len(c.Workspace) >= 128 {
		return errors.New("unsupported workspace")
	}
	if c.Generation != "1" || c.DeadlineNS == "" {
		return errors.New("unsupported policy")
	}
	if c.Deployment == "disposable-dev-poc" && c.Endpoint != "127.0.0.1:18081" && c.Endpoint != "127.0.0.1:18082" {
		return errors.New("unsupported fixture endpoint")
	}
	if c.Deployment == "agentgate-community-v1" {
		host, port, err := net.SplitHostPort(c.Endpoint)
		ip := net.ParseIP(host)
		number, portErr := strconv.Atoi(port)
		if err != nil || portErr != nil || ip == nil || ip.To4() == nil || ip.String() != host || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) || number < 1 || number > 65535 || strconv.Itoa(number) != port {
			return errors.New("unsupported customer IPv4 TCP endpoint")
		}
	}
	if _, err := strconv.ParseUint(c.DeadlineNS, 10, 64); err != nil {
		return errors.New("invalid monotonic deadline")
	}
	if _, err := strconv.ParseUint(c.Domain, 10, 64); err != nil {
		return errors.New("invalid execution domain")
	}
	if _, err := hex.DecodeString(c.JobDigest); err != nil {
		return errors.New("invalid job digest")
	}
	if c.PolicyVersion != "" || c.PolicyDigest != "" {
		if len(c.PolicyVersion) != 32 || len(c.PolicyDigest) != 64 {
			return errors.New("invalid control-plane policy binding")
		}
		if _, err := hex.DecodeString(c.PolicyVersion); err != nil {
			return err
		}
		if _, err := hex.DecodeString(c.PolicyDigest); err != nil {
			return err
		}
	}
	return nil
}

func Nonce() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(data[:]), nil
}

func Consume(dir string, c Claims, token string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, c.Nonce)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("grant admission replay or storage failure: %w", err)
	}
	defer f.Close()
	if _, err = f.WriteString(Digest([]byte(token)) + " consumed\n"); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
