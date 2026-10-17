// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodeapi

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/requestproof"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"golang.org/x/sys/unix"
	"net"
	"net/http"
	"regexp"
	"strings"
)

var identityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type peerKey struct{}
type peer struct {
	uid, gid uint32
	pid      int32
	verified bool
}

func connectionContext(ctx context.Context, connection net.Conn) context.Context {
	caller := peer{}
	if socket, ok := connection.(*net.UnixConn); ok {
		raw, err := socket.SyscallConn()
		if err == nil {
			_ = raw.Control(func(fd uintptr) {
				credentials, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
				if err == nil && credentials.Pid > 0 {
					caller = peer{credentials.Uid, credentials.Gid, credentials.Pid, true}
				}
			})
		}
	}
	return context.WithValue(ctx, peerKey{}, caller)
}
func (s *Server) authenticate(r *http.Request, body []byte) (Enrollment, error) {
	caller, ok := r.Context().Value(peerKey{}).(peer)
	if !ok || !caller.verified {
		return Enrollment{}, errors.New("node_peer_unverified")
	}
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 || !strings.HasPrefix(headers[0], "Alloyium-Proof ") {
		return Enrollment{}, errors.New("node_proof_required")
	}
	token := strings.TrimPrefix(headers[0], "Alloyium-Proof ")
	claims, err := requestproof.Parse(token)
	if err != nil || !identityPattern.MatchString(claims.Subject) {
		return Enrollment{}, errors.New("node_proof_invalid")
	}
	enrollment, err := s.resolver.Resolve(r.Context(), claims.Subject)
	if err != nil || !enrollment.Enabled || enrollment.AgentID != claims.Subject || enrollment.PeerUID != caller.uid || enrollment.PeerGID != caller.gid {
		return Enrollment{}, errors.New("node_enrollment_denied")
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(enrollment.AgentKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return Enrollment{}, errors.New("node_enrollment_invalid")
	}
	verified, err := requestproof.Verify(token, ed25519.PublicKey(public), lifecycle.NodeAudience(s.config.Identity.NodeID), s.config.Identity.BootID, r.Method, r.URL.EscapedPath(), body)
	if err != nil || verified.Subject != enrollment.AgentID {
		return Enrollment{}, errors.New("node_proof_invalid")
	}
	if err = s.proofs.ConsumeProof(r.Context(), verified.Subject, verified.Nonce, verified.Time); err != nil {
		return Enrollment{}, errors.New("node_proof_rejected")
	}
	return enrollment, nil
}
