// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

// inspectedConn records the first header block for headerCheck and releases
// its connection slot exactly once.
type inspectedConn struct {
	net.Conn
	check   *headerCheck
	mu      sync.Mutex
	release func()
	once    sync.Once
}

func (c *inspectedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.check.feed(p[:n])
		c.mu.Unlock()
	}
	return n, err
}

func (c *inspectedConn) verdict() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.check.verdict()
}

func (c *inspectedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// limitListener closes connections beyond max immediately instead of letting
// them queue, and wraps each accepted connection for header inspection.
type limitListener struct {
	net.Listener
	slots          chan struct{}
	maxHeaderBytes int
	maxHeaderCount int
	onAccept       func(accepted bool)
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			l.onAccept(true)
			return &inspectedConn{Conn: c, check: newHeaderCheck(l.maxHeaderBytes, l.maxHeaderCount),
				release: func() { <-l.slots }}, nil
		default:
			l.onAccept(false)
			c.Close()
		}
	}
}

// InterfaceAddrs lists one interface's addresses; tests substitute it.
type InterfaceAddrs func() ([]InterfaceAddr, error)

// InterfaceAddr is one address on one interface.
type InterfaceAddr struct {
	Interface string
	Loopback  bool
	Up        bool
	Prefix    netip.Prefix
}

func systemInterfaces() ([]InterfaceAddr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []InterfaceAddr
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(n.IP)
			if !ok {
				continue
			}
			bits, _ := n.Mask.Size()
			out = append(out, InterfaceAddr{Interface: iface.Name, Loopback: iface.Flags&net.FlagLoopback != 0,
				Up: iface.Flags&net.FlagUp != 0, Prefix: netip.PrefixFrom(ip.Unmap(), bits)})
		}
	}
	return out, nil
}

// errListen is returned when the configured endpoint is not the launch's
// private broker address.
var errListen = errors.New("broker listen address is not the launch's private broker address")

// checkListenInterface requires exactly one up, non-loopback interface that
// carries the configured address with exactly the configured subnet prefix.
func checkListenInterface(l Listen, list InterfaceAddrs) error {
	want := netip.MustParseAddr(l.Address)
	subnet := netip.MustParsePrefix(l.Subnet)
	addrs, err := list()
	if err != nil {
		return errListen
	}
	matches := 0
	for _, a := range addrs {
		if a.Prefix.Addr() != want {
			continue
		}
		if a.Loopback || !a.Up || a.Prefix.Bits() != subnet.Bits() {
			return errListen
		}
		matches++
	}
	if matches != 1 {
		return errListen
	}
	return nil
}

// listenTCP binds exactly address:port and never a wildcard.
func listenTCP(l Listen) (net.Listener, error) {
	want := netip.AddrPortFrom(netip.MustParseAddr(l.Address), uint16(l.Port))
	// checkListenInterface has already proven the address is local; binding the
	// exact address (never a wildcard) keeps the socket off every other network.
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp4", want.String())
	if err != nil {
		return nil, errListen
	}
	got, ok := ln.Addr().(*net.TCPAddr)
	if !ok || got.AddrPort().Addr().Unmap() != want.Addr() || got.AddrPort().Port() != want.Port() {
		ln.Close()
		return nil, errListen
	}
	return ln, nil
}

// listenUnix creates a fresh socket in an existing directory owned by the
// broker, then restricts it to the broker and one sandbox group.
func listenUnix(l Listen) (net.Listener, error) {
	dir := filepath.Dir(l.Path)
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR ||
		int(st.Uid) != os.Geteuid() || st.Mode&0o022 != 0 {
		return nil, fmt.Errorf("%w: socket directory custody", errListen)
	}
	if err := unix.Lstat(l.Path, &st); err == nil || !errors.Is(err, unix.ENOENT) {
		return nil, fmt.Errorf("%w: socket path already exists", errListen)
	}
	ln, err := net.Listen("unix", l.Path)
	if err != nil {
		return nil, errListen
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(true)
	if err := os.Chmod(l.Path, 0o660); err != nil {
		ln.Close()
		return nil, errListen
	}
	if err := os.Lchown(l.Path, os.Geteuid(), *l.SocketGID); err != nil {
		ln.Close()
		return nil, errListen
	}
	return ln, nil
}
