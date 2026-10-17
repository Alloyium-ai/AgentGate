// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/childwire"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"encoding/json"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"strings"
	"testing"
)

func TestQualificationStartRejectsUnsealedAndUnboundedInput(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root descriptor custody required")
	}
	f, err := os.CreateTemp(t.TempDir(), "unsealed")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, _ = f.WriteString("{}")
	if _, err = readQualificationStart(f); err == nil {
		t.Fatal("unsealed start accepted")
	}
	raw, _ := json.Marshal(QualificationStart{Protocol: QualificationStartProtocol})
	sealed, err := childwire.Seal("invalid-scope", raw)
	if err != nil {
		t.Fatal(err)
	}
	defer sealed.Close()
	if _, err = readQualificationStart(sealed); err == nil {
		t.Fatal("invalid sealed scope accepted")
	}
}

func TestQualificationConnectionRequiresExactRootCreator(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root descriptor custody required")
	}
	ticks, err := lifecycle.ProcessStartTime(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []int{unix.SOCK_STREAM, unix.SOCK_SEQPACKET} {
		pair, err := unix.Socketpair(unix.AF_UNIX, kind|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		f := os.NewFile(uintptr(pair[0]), "fixture")
		other := os.NewFile(uintptr(pair[1]), "parent")
		parent := lifecycle.DaemonIdentity{PID: os.Getpid(), StartTimeTicks: ticks, InstanceID: "test"}
		conn, err := inheritedQualificationConn(f, parent)
		if kind == unix.SOCK_STREAM {
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			parent.StartTimeTicks++
			if bad, e := inheritedQualificationConn(f, parent); e == nil {
				_ = bad.Close()
				t.Fatal("changed parent accepted")
			}
		} else if err == nil {
			_ = conn.Close()
			t.Fatal("packet transport accepted")
		}
		_ = f.Close()
		_ = other.Close()
	}
}

func TestQualificationListenerNeverAcceptsAnotherConnection(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	l := &qualificationListener{conn: a, done: make(chan struct{})}
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if _, err = l.Accept(); err == nil {
		t.Fatal("closed pair accepted another connection")
	}
	_ = l.Close()
}

func TestQualificationReplyRejectsAliasesAndOversize(t *testing.T) {
	var reply QualificationStateResponse
	if readQualificationReply(strings.NewReader(`{"Protocol":"bad"}`), &reply) == nil {
		t.Fatal("alias accepted")
	}
	if readQualificationReply(strings.NewReader(strings.Repeat(" ", 2<<20)+"{}"), &reply) == nil {
		t.Fatal("oversized reply accepted")
	}
}
