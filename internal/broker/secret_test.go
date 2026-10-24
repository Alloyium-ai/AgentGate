// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func load(t *testing.T, c Credential, src secretSource) (*credential, error) {
	t.Helper()
	cred, err := loadCredential("anthropic", c, src)
	if err != nil {
		if strings.Contains(err.Error(), testSecret[:12]) {
			t.Fatal("error carries secret content")
		}
		return nil, err
	}
	t.Cleanup(cred.destroy)
	return cred, nil
}

func TestSecretFileCustody(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, mode)
		return p
	}
	header := Credential{Header: "x-api-key"}
	good := write("good", testSecret+"\n", 0o600)
	cred, err := load(t, header, fileSource(good))
	if err != nil {
		t.Fatal(err)
	}
	if cred.value != testSecret || cred.header != "X-Api-Key" {
		t.Fatal("value not loaded exactly")
	}
	bad := map[string]string{
		"group readable": write("g", testSecret, 0o640),
		"world readable": write("w", testSecret, 0o604),
		"too short":      write("short", "abc", 0o600),
		"inner space":    write("space", "sk-test FAKE 0123456789", 0o600),
		"crlf":           write("crlf", testSecret+"\r\n", 0o600),
		"two lines":      write("lines", testSecret+"\n"+testSecret+"\n", 0o600),
		"nul":            write("nul", testSecret+"\x00x", 0o600),
		"non-ascii":      write("utf8", testSecret+"é", 0o600),
		"too long":       write("long", strings.Repeat("a", MaxSecretBytes+1), 0o600),
		"empty":          write("empty", "", 0o600),
		"missing":        filepath.Join(dir, "absent"),
		"directory":      dir,
	}
	link := filepath.Join(dir, "symlink")
	os.Symlink(good, link)
	bad["symlink"] = link
	sub := filepath.Join(dir, "sub")
	os.Mkdir(sub, 0o700)
	os.Symlink(sub, filepath.Join(dir, "sublink"))
	write("sub/inner", testSecret, 0o600)
	bad["symlinked parent"] = filepath.Join(dir, "sublink", "inner")
	hard := write("hard-src", testSecret, 0o600)
	os.Link(hard, filepath.Join(dir, "hard"))
	bad["hard link"] = filepath.Join(dir, "hard")
	if os.Geteuid() == 0 {
		other := write("other-owner", testSecret, 0o600)
		os.Chown(other, 12345, 12345)
		bad["other owner"] = other
	}
	fifo := filepath.Join(dir, "fifo")
	if err := mkfifo(fifo); err == nil {
		bad["fifo path"] = fifo
	}
	for name, path := range bad {
		if _, err := load(t, header, fileSource(path)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSecretFromDescriptor(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() { w.WriteString(testSecret); w.Close() }()
	fd, err := dupFD(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	cred, err := load(t, Credential{Header: "authorization", Scheme: "Bearer"}, fdSource(fd))
	if err != nil {
		t.Fatal(err)
	}
	if cred.value != "Bearer "+testSecret {
		t.Fatal("pipe value")
	}
	f, err := os.CreateTemp(t.TempDir(), "fd")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(testSecret)
	f.Chmod(0o644)
	f.Seek(0, 0)
	fd, _ = dupFD(f)
	f.Close()
	if _, err := load(t, Credential{Header: "x-api-key"}, fdSource(fd)); err == nil {
		t.Fatal("world-readable descriptor accepted")
	}
}

func TestCredentialFormsLiveOutsideTheHeapAndAreWiped(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s")
	os.WriteFile(p, []byte(testSecret), 0o600)
	cred, err := loadCredential("gh", Credential{Header: "authorization", Scheme: "Basic", Username: "x-access-token"}, fileSource(p))
	if err != nil {
		t.Fatal(err)
	}
	if len(cred.patterns) < 3 {
		t.Fatal(len(cred.patterns))
	}
	arena := cred.arena.mem
	if !strings.Contains(string(arena), testSecret) {
		t.Fatal("secret not in the arena")
	}
	cred.destroy()
	for _, b := range arena {
		if b != 0 {
			t.Fatal("arena not zeroed")
		}
	}
	if cred.value != "" {
		t.Fatal("value reference kept")
	}
}

func TestListenInterfaceCheck(t *testing.T) {
	l := Listen{Network: "tcp", Address: "10.99.0.2", Port: 8443, Subnet: "10.99.0.0/29"}
	list := func(addrs ...InterfaceAddr) InterfaceAddrs {
		return func() ([]InterfaceAddr, error) { return addrs, nil }
	}
	good := InterfaceAddr{Interface: "eth1", Up: true, Prefix: netip.MustParsePrefix("10.99.0.2/29")}
	if err := checkListenInterface(l, list(good, InterfaceAddr{Interface: "lo", Loopback: true, Up: true,
		Prefix: netip.MustParsePrefix("127.0.0.1/8")})); err != nil {
		t.Fatal(err)
	}
	cases := map[string]InterfaceAddrs{
		"absent":       list(InterfaceAddr{Interface: "eth0", Up: true, Prefix: netip.MustParsePrefix("172.17.0.2/16")}),
		"loopback":     list(InterfaceAddr{Interface: "lo", Loopback: true, Up: true, Prefix: netip.MustParsePrefix("10.99.0.2/29")}),
		"down":         list(InterfaceAddr{Interface: "eth1", Up: false, Prefix: netip.MustParsePrefix("10.99.0.2/29")}),
		"wrong subnet": list(InterfaceAddr{Interface: "eth1", Up: true, Prefix: netip.MustParsePrefix("10.99.0.2/16")}),
		"duplicated":   list(good, InterfaceAddr{Interface: "eth2", Up: true, Prefix: netip.MustParsePrefix("10.99.0.2/29")}),
	}
	for name, l2 := range cases {
		if err := checkListenInterface(l, l2); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The real host has no such interface, so the production check refuses.
	if err := checkListenInterface(l, systemInterfaces); err == nil {
		t.Fatal("system interfaces unexpectedly hold the test address")
	}
	// listenTCP binds exactly the address it is given.
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	ln, err := listenTCP(Listen{Address: "127.0.0.1", Port: port})
	if err != nil {
		t.Fatal(err)
	}
	if ln.Addr().String() != net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) {
		t.Fatal(ln.Addr())
	}
	ln.Close()
}

func TestUnixListener(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o750)
	gid := os.Getgid()
	l := Listen{Network: "unix", Path: filepath.Join(dir, "broker.sock"), SocketGID: &gid}
	ln, err := listenUnix(l)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(l.Path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o660 {
		t.Fatal(fi.Mode(), err)
	}
	if _, err := listenUnix(l); err == nil {
		t.Fatal("existing socket path reused")
	}
	ln.Close()
	if _, err := os.Lstat(l.Path); err == nil {
		t.Fatal("socket not removed on close")
	}
	os.Chmod(dir, 0o770)
	if _, err := listenUnix(l); err == nil {
		t.Fatal("group-writable socket directory accepted")
	}
}
