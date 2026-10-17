// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"alloyium.local/kernel-poc/internal/lifecycle"
)

func (s *qualificationSession) purpose() string {
	if s.version != nil {
		return lifecycle.QualificationVersionPurpose
	}
	return lifecycle.QualificationFixturePurpose
}
func (s *qualificationSession) preparedProtocol() string {
	if s.version != nil {
		return QualificationVersionPreparedProtocol
	}
	return QualificationPreparedProtocol
}
func (s *qualificationSession) runProtocol() string {
	if s.version != nil {
		return QualificationVersionRunProtocol
	}
	return QualificationRunProtocol
}
func (s *qualificationSession) statusProtocol() string {
	if s.version != nil {
		return QualificationVersionStatusProtocol
	}
	return QualificationStatusProtocol
}
func (s *qualificationSession) stopProtocol() string {
	if s.version != nil {
		return QualificationVersionStopProtocol
	}
	return QualificationStopProtocol
}
func (s *qualificationSession) preparedSigningBytes(r QualificationPrepared) ([]byte, error) {
	if s.version != nil {
		return QualificationVersionPreparedSigningBytes(QualificationVersionPrepared(r))
	}
	return QualificationPreparedSigningBytes(r)
}
func (s *qualificationSession) input() ([]byte, error) {
	if s.version == nil {
		return qualificationInput(s.spec.Manifest)
	}
	sum := sha256.Sum256(nil)
	if s.spec.Manifest.InputDigest != hex.EncodeToString(sum[:]) {
		return nil, errors.New("the native version fixture input is not empty")
	}
	return []byte{}, nil
}
