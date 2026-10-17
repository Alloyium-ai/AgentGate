// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodecontrol

import (
	"alloyium.local/kernel-poc/internal/childwire"
	"alloyium.local/kernel-poc/internal/heldprocess"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/unix"
)

type ChildFrames struct {
	Process               lifecycle.HeldProcess `json:"process"`
	HelperDigest          string                `json:"helper_digest"`
	ManifestDigest        string                `json:"manifest_digest"`
	JobDigest             string                `json:"job_digest"`
	FilterDigest          string                `json:"filter_digest"`
	JobBytes              uint32                `json:"job_bytes"`
	FilterBytes           uint32                `json:"filter_bytes"`
	JobSeals              int                   `json:"job_seals"`
	FilterSeals           int                   `json:"filter_seals"`
	FilterAcknowledgement []byte                `json:"filter_acknowledgement"`
}
type ChildFrameChunk struct {
	Kind   string `json:"kind"`
	Offset uint32 `json:"offset"`
	Total  uint32 `json:"total"`
	Digest string `json:"digest"`
	Bytes  []byte `json:"bytes"`
}

func childFrameHash(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == s
}
func (p ChildFrames) Validate(b lifecycle.Binding) error {
	if _, err := heldprocess.DecodeFilterAcknowledgement(p.FilterAcknowledgement); err != nil {
		return err
	}
	want := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if p.Process.PID <= 1 || p.Process.StartTimeTicks == 0 || p.Process.BarrierID == "" || !childFrameHash(p.HelperDigest) || p.HelperDigest != b.ArtifactDigests["held-helper"] || p.ManifestDigest != b.JobDigest || !childFrameHash(p.JobDigest) || !childFrameHash(p.FilterDigest) || p.JobBytes == 0 || p.JobBytes > childwire.MaxFrame || p.FilterBytes == 0 || p.FilterBytes > childwire.MaxFrame || p.JobSeals&want != want || p.FilterSeals&want != want {
		return errors.New("the measured child frame custody differs")
	}
	return nil
}
func (p ChildFrameChunk) Validate() error {
	if p.Kind != "job" && p.Kind != "filters" || !childFrameHash(p.Digest) || p.Total == 0 || p.Total > childwire.MaxFrame || len(p.Bytes) == 0 || len(p.Bytes) > 4096 || uint64(p.Offset)+uint64(len(p.Bytes)) > uint64(p.Total) {
		return errors.New("the child frame chunk exceeds its fixed scope")
	}
	return nil
}
