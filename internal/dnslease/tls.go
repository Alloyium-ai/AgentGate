// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dnslease

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"time"
)

type TLSConfig struct {
	Address    netip.AddrPort
	ServerName string
	RootPEM    []byte
	Timeout    time.Duration
}

// TLSResolver uses one verified TLS connection per query. Its literal target
// avoids a bootstrap DNS lookup and its private roots avoid mutable trust.
type TLSResolver struct {
	evidence ResolverEvidence
	roots    *x509.CertPool
	timeout  time.Duration
}

func NewTLSResolver(config TLSConfig) (*TLSResolver, error) {
	roots, digest, err := pinnedRoots(config.RootPEM)
	if err != nil {
		return nil, err
	}
	e := ResolverEvidence{Transport: "tls1.3", Address: config.Address.String(), ServerName: config.ServerName, RootsSHA256: digest, TimeoutMS: config.Timeout.Milliseconds()}
	if err = validateResolverEvidence(e); err != nil {
		return nil, err
	}
	return &TLSResolver{evidence: e, roots: roots, timeout: config.Timeout}, nil
}

func (r *TLSResolver) Evidence() ResolverEvidence { return r.evidence }

func (r *TLSResolver) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("a DNS query context is required")
	}
	if _, err := parseQuery(query); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	dialer := net.Dialer{Timeout: r.timeout}
	connection, err := dialer.DialContext(ctx, "tcp", r.evidence.Address)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err = connection.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	secured := tls.Client(connection, &tls.Config{ServerName: r.evidence.ServerName, RootCAs: r.roots, MinVersion: tls.VersionTLS13})
	if err = secured.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	frame := make([]byte, len(query)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if _, err = io.Copy(secured, bytes.NewReader(frame)); err != nil {
		return nil, err
	}
	var header [2]byte
	if _, err = io.ReadFull(secured, header[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[:]))
	if length < 12 || length > MaxWire {
		return nil, fmt.Errorf("TLS DNS reply exceeds the target frame limit")
	}
	reply := make([]byte, length)
	if _, err = io.ReadFull(secured, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func pinnedRoots(raw []byte) (*x509.CertPool, string, error) {
	if len(raw) > 128*1024 {
		return nil, "", fmt.Errorf("pinned CA input exceeds the target limit")
	}
	roots := x509.NewCertPool()
	certificates := [][]byte{}
	for len(bytes.TrimSpace(raw)) != 0 {
		if len(certificates) == 16 {
			return nil, "", fmt.Errorf("pinned CA count exceeds the target limit")
		}
		block, remaining := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, "", fmt.Errorf("only explicit CA certificate PEM blocks are supported")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid {
			return nil, "", fmt.Errorf("a valid pinned CA certificate is required")
		}
		roots.AddCert(certificate)
		certificates = append(certificates, append([]byte(nil), certificate.Raw...))
		raw = remaining
	}
	if len(certificates) == 0 || len(certificates) > 16 {
		return nil, "", fmt.Errorf("one to sixteen pinned CA certificates are required")
	}
	sort.Slice(certificates, func(i, j int) bool { return bytes.Compare(certificates[i], certificates[j]) < 0 })
	hash := sha256.New()
	for _, certificate := range certificates {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(certificate)))
		hash.Write(length[:])
		hash.Write(certificate)
	}
	return roots, hex.EncodeToString(hash.Sum(nil)), nil
}
