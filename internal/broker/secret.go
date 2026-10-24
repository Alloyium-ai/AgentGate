// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Secret value bounds. The value is placed in an HTTP header, so it must be
// visible ASCII; a short value would also make response redaction noisy.
const (
	MinSecretBytes = 8
	MaxSecretBytes = 8192
)

// ErrSecretCustody never carries a path's contents or the value.
var ErrSecretCustody = errors.New("broker secret custody is invalid")

// errSecretCustody is the internal alias.
var errSecretCustody = ErrSecretCustody

// ValidSecret reports whether v can be injected as a credential: 8 to 8192
// bytes of visible ASCII. The host agent can check a value at secret-put time.
func ValidSecret(v []byte) bool { return validSecret(v) }

// CheckSecrets loads and immediately wipes every file-backed secret of cfg
// with the same custody checks as run. Descriptor-backed secrets belong to a
// run invocation and are reported as unchecked.
func CheckSecrets(cfg *Config) (unchecked []string, err error) {
	for _, r := range cfg.Routes {
		if r.Credential.SecretFile == "" {
			unchecked = append(unchecked, r.Name)
			continue
		}
		cred, err := loadCredential(r.Name, r.Credential, fileSource(r.Credential.SecretFile))
		if err != nil {
			return unchecked, err
		}
		cred.destroy()
		cred.arena.release()
	}
	return unchecked, nil
}

// credential is one route's injection rule with its secret held in an arena.
type credential struct {
	header      string
	value       string // header value, backed by the arena, never logged
	extra       http.Header
	strip       map[string]bool
	patterns    []pattern
	arena       *secretArena
	memoryLocks bool
}

func (c *credential) destroy() {
	if c == nil {
		return
	}
	wipePatterns(c.patterns)
	c.value = ""
	if c.arena != nil {
		c.arena.destroy()
	}
}

// secretSource reads a raw secret into dst and returns the length read.
type secretSource func(dst []byte) (int, error)

func fileSource(path string) secretSource {
	return func(dst []byte) (int, error) {
		fd, err := openNoSymlinks(path)
		if err != nil {
			return 0, errSecretCustody
		}
		defer unix.Close(fd)
		var before, after unix.Stat_t
		if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 ||
			(before.Uid != 0 && int(before.Uid) != os.Geteuid()) || before.Mode&0o077 != 0 ||
			before.Size < MinSecretBytes || before.Size > int64(len(dst)-1) {
			return 0, errSecretCustody
		}
		n, err := readFull(fd, dst)
		if err != nil || int64(n) != before.Size {
			return 0, errSecretCustody
		}
		if unix.Fstat(fd, &after) != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size ||
			after.Mtim != before.Mtim || after.Ctim != before.Ctim || after.Mode != before.Mode || after.Uid != before.Uid {
			return 0, errSecretCustody
		}
		return n, nil
	}
}

// fdSource reads an inherited descriptor: a regular file or memfd owned by
// root or the broker with no group or other access, or a pipe.
func fdSource(fd int) secretSource {
	return func(dst []byte) (int, error) {
		defer unix.Close(fd)
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil {
			return 0, errSecretCustody
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			if st.Nlink > 1 || (st.Uid != 0 && int(st.Uid) != os.Geteuid()) || st.Mode&0o077 != 0 {
				return 0, errSecretCustody
			}
		case unix.S_IFIFO:
		default:
			return 0, errSecretCustody
		}
		n, err := readFull(fd, dst)
		if err != nil {
			return 0, errSecretCustody
		}
		return n, nil
	}
}

func openNoSymlinks(path string) (int, error) {
	how := &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, how)
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
		// Kernels before 5.6 or seccomp profiles without openat2: the final
		// component is still refused if it is a symlink.
		fd, err = unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	}
	return fd, err
}

// readFull reads until EOF; it fails if dst fills before EOF.
func readFull(fd int, dst []byte) (int, error) {
	n := 0
	for {
		if n == len(dst) {
			return 0, errSecretCustody
		}
		m, err := unix.Read(fd, dst[n:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) {
			// A pipe opened non-blocking by its writer: wait for data.
			var fds = []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if _, perr := unix.Poll(fds, 5000); perr != nil && !errors.Is(perr, unix.EINTR) {
				return 0, errSecretCustody
			}
			if fds[0].Revents == 0 {
				return 0, errSecretCustody
			}
			continue
		}
		if err != nil {
			return 0, errSecretCustody
		}
		if m == 0 {
			return n, nil
		}
		n += m
	}
}

// validSecret reports whether v is 8..8192 bytes of visible ASCII.
func validSecret(v []byte) bool {
	if len(v) < MinSecretBytes || len(v) > MaxSecretBytes {
		return false
	}
	for _, c := range v {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// loadCredential reads one secret into a locked scratch mapping, then derives
// the injected header value and the redaction forms into an exactly sized arena.
// This code makes no heap copy of the value.
func loadCredential(route string, c Credential, src secretSource) (*credential, error) {
	failed := fmt.Errorf("broker route %s: %w", route, errSecretCustody)
	scratch, err := newSecretArena(MaxSecretBytes + 2)
	if err != nil {
		return nil, fmt.Errorf("broker route %s: secret memory is unavailable", route)
	}
	defer scratch.release()
	buf := scratch.alloc(MaxSecretBytes + 2)
	n, err := src(buf)
	if err != nil {
		return nil, failed
	}
	read := buf[:n]
	if len(read) > 0 && read[len(read)-1] == '\n' {
		read = read[:len(read)-1]
	}
	if !validSecret(read) {
		return nil, failed
	}
	std, url := base64.RawStdEncoding, base64.RawURLEncoding
	pairLen := 0
	if c.Scheme == "Basic" {
		pairLen = len(c.Username) + 1 + len(read)
	}
	need := len(read) + len("Bearer ") + len(read) + len("Basic ") + base64.StdEncoding.EncodedLen(pairLen) +
		pairLen + 2*std.EncodedLen(len(read)) + 2*std.EncodedLen(pairLen)
	arena, err := newSecretArena(need)
	if err != nil {
		return nil, fmt.Errorf("broker route %s: secret memory is unavailable", route)
	}
	value := arena.alloc(len(read))
	copy(value, read)
	var header []byte
	switch c.Scheme {
	case "":
		header = value
	case "Bearer":
		header = arena.alloc(len("Bearer ") + len(value))
		copy(header, "Bearer ")
		copy(header[len("Bearer "):], value)
	case "Basic":
		header = arena.alloc(len("Basic ") + base64.StdEncoding.EncodedLen(pairLen))
		copy(header, "Basic ")
	}
	var pair []byte
	if c.Scheme == "Basic" {
		pair = arena.alloc(pairLen)
		copy(pair, c.Username)
		pair[len(c.Username)] = ':'
		copy(pair[len(c.Username)+1:], value)
		base64.StdEncoding.Encode(header[len("Basic "):], pair)
	}
	forms := [][]byte{value}
	addForm := func(src []byte, enc *base64.Encoding) {
		dst := arena.alloc(enc.EncodedLen(len(src)))
		enc.Encode(dst, src)
		for _, f := range forms {
			if string(f) == string(dst) {
				return
			}
		}
		forms = append(forms, dst)
	}
	for _, enc := range []*base64.Encoding{std, url} {
		addForm(value, enc)
		if pair != nil {
			addForm(pair, enc)
		}
	}
	if header == nil || len(forms) == 0 {
		arena.destroy()
		return nil, failed
	}
	cred := &credential{
		header: http.CanonicalHeaderKey(c.Header),
		value:  unsafe.String(unsafe.SliceData(header), len(header)),
		extra:  http.Header{},
		strip:  map[string]bool{http.CanonicalHeaderKey(c.Header): true},
		// The patterns alias arena memory; only their KMP tables are on the
		// heap, and destroy wipes them.
		patterns:    newPatterns(forms),
		arena:       arena,
		memoryLocks: arena.locked,
	}
	for k, v := range c.ExtraHeaders {
		ck := http.CanonicalHeaderKey(k)
		cred.extra[ck] = []string{v}
		cred.strip[ck] = true
	}
	return cred, nil
}
