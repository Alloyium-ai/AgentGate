// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package controlclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/requestproof"
)

type Config struct {
	URL            string `json:"url"`
	Audience       string `json:"audience"`
	Subject        string `json:"subject"`
	PrivateKeyFile string `json:"private_key_file"`
	CAFile         string `json:"ca_file"`
	Authority      string `json:"authority"`
	Agent          string `json:"agent"`
	AgentKey       string `json:"agent_key"`
	RequestID      string `json:"request_id"`
}
type Client struct {
	Config Config
	HTTP   *http.Client
	Key    ed25519.PrivateKey
}

func EncodeKey(key ed25519.PublicKey) string { return base64.RawURLEncoding.EncodeToString(key) }
func Decode(value string) ([]byte, error)    { return base64.RawURLEncoding.DecodeString(value) }
func New(c Config) (*Client, error) {
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("control plane requires a pinned HTTPS URL")
	}
	st, err := os.Stat(c.PrivateKeyFile)
	if err != nil || st.Mode().Perm() != 0600 {
		return nil, errors.New("node private key must use mode 0600")
	}
	key, err := os.ReadFile(c.PrivateKeyFile)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("node private key invalid")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if c.CAFile != "" {
		data, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("control-plane CA invalid")
		}
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, MaxIdleConnsPerHost: 2, ResponseHeaderTimeout: 8 * time.Second}
	return &Client{Config: c, HTTP: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("control-plane redirect rejected") }}, Key: key}, nil
}
func (c *Client) Call(path, method, key string, input, out any) error {
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			return err
		}
	}
	var challenge struct {
		Audience string `json:"audience"`
		Epoch    string `json:"epoch"`
	}
	response, err := c.HTTP.Get(strings.TrimRight(c.Config.URL, "/") + "/api/v1/machine-challenge")
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if err != nil || response.StatusCode != 200 {
		return errors.New("machine challenge unavailable")
	}
	if err = json.Unmarshal(data, &challenge); err != nil {
		return err
	}
	if challenge.Audience != c.Config.Audience || challenge.Epoch == "" {
		return errors.New("control-plane audience differs from the trusted configuration")
	}
	uri := "/api/v1/" + path
	request, err := http.NewRequest(method, strings.TrimRight(c.Config.URL, "/")+uri, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Alloyium-Proof "+requestproof.Sign(c.Config.Subject, method, uri, c.Config.Audience, challenge.Epoch, body, c.Key))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", key)
	request.Header.Set("X-Correlation-ID", c.Config.RequestID)
	request.Header.Set("Idempotency-Key", key)
	response, err = c.HTTP.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err = io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil {
		return err
	}
	if response.StatusCode != 200 {
		var problem struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		json.Unmarshal(data, &problem)
		return fmt.Errorf("control-plane HTTP %d: %s", response.StatusCode, problem.Error.Code)
	}
	if len(data) > 4<<20 {
		return errors.New("control-plane response exceeds limit")
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}
