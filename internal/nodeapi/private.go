// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodeapi

import (
	"context"
	"errors"
	"net"
)

type UnixPeer struct {
	UID uint32
	GID uint32
	PID int32
}

// PeerFromContext exposes credentials obtained from the actual Unix connection.
func PeerFromContext(ctx context.Context) (UnixPeer, error) {
	caller, ok := ctx.Value(peerKey{}).(peer)
	if !ok || !caller.verified {
		return UnixPeer{}, errors.New("the Unix peer is unverified")
	}
	return UnixPeer{caller.uid, caller.gid, caller.pid}, nil
}
func PrivateConnContext(ctx context.Context, connection net.Conn) context.Context {
	return connectionContext(ctx, connection)
}
func ListenPrivate(path string, gid uint32) (*net.UnixListener, func(), error) {
	server := Server{config: Config{SocketPath: path, SocketGID: gid}}
	listener, owned, err := server.listener()
	if err != nil {
		return nil, nil, err
	}
	return listener, func() { listener.Close(); removeOwnedSocket(path, owned) }, nil
}
