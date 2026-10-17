// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package runtimeclosure measures an explicitly configured immutable file set.
// It grants no file permission and supplies no runtime qualification.
package runtimeclosure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const Version = "agentgate.runtime-closure.v1"
const DigestDomain = "AGENTGATE_RUNTIME_CLOSURE_V1\n"
const MaxFiles = 128
const MaxFileBytes = int64(256 << 20)
const MaxTotalBytes = int64(1 << 30)

var ErrConfiguration = errors.New("the explicit runtime closure configuration is invalid")
var ErrCustody = errors.New("the runtime closure file custody differs")
var ErrChanged = errors.New("the runtime closure file changed during measurement")
var ErrDigest = errors.New("the runtime closure file digest differs")

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes,string"`
	Mode   uint32 `json:"mode"`
	GID    uint32 `json:"gid"`
}

type Set struct {
	files  []File
	digest string
	total  int64
}

type Measurement struct {
	Protocol   string `json:"protocol"`
	Digest     string `json:"digest"`
	Files      []File `json:"files"`
	TotalBytes int64  `json:"total_bytes,string"`
}

func canonical(path string) bool {
	for _, value := range path {
		if value < 0x20 || value == 0x7f {
			return false
		}
	}
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && path != "/tmp" && !strings.HasPrefix(path, "/tmp/") && !strings.ContainsAny(path, "\x00\n\r") && utf8.ValidString(path) && len(path) <= 4096
}
func validFile(f File) bool {
	raw, err := hex.DecodeString(f.SHA256)
	return canonical(f.Path) && err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == f.SHA256 && f.Bytes >= 0 && f.Bytes <= MaxFileBytes && f.Mode&^uint32(0777) == 0 && f.Mode&0022 == 0 && f.GID != ^uint32(0)
}

// New distinguishes an omitted set from an explicit empty static closure.
// The digest binds the exact sorted configuration, independently of file I/O.
func New(files []File) (Set, error) {
	if files == nil || len(files) > MaxFiles {
		return Set{}, ErrConfiguration
	}
	owned := append([]File{}, files...)
	sort.Slice(owned, func(i, j int) bool { return owned[i].Path < owned[j].Path })
	var total int64
	for i, f := range owned {
		if !validFile(f) || (i > 0 && owned[i-1].Path == f.Path) || f.Bytes > MaxTotalBytes-total {
			return Set{}, ErrConfiguration
		}
		total += f.Bytes
	}
	raw, err := json.Marshal(owned)
	if err != nil {
		return Set{}, ErrConfiguration
	}
	sum := sha256.Sum256(append([]byte(DigestDomain), raw...))
	return Set{files: owned, digest: hex.EncodeToString(sum[:]), total: total}, nil
}
func (s Set) Digest() string { return s.digest }
func (s Set) Files() []File  { return append([]File{}, s.files...) }
