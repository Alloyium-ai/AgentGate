// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package enforcement

import (
	"alloyium.local/kernel-poc/internal/childwire"
	"alloyium.local/kernel-poc/internal/heldprocess"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"encoding/binary"
	"errors"
	"os"
)

// Child retains both the held process and its exclusive exec listener custody.
type Child struct {
	Held        *heldprocess.Held
	Listener    *os.File
	declaration childwire.Declaration
}

func (c *Child) Declaration() childwire.Declaration {
	d := c.declaration
	d.Job = append([]byte{}, d.Job...)
	d.Filters = append([]byte{}, d.Filters...)
	return d
}

func (c *Child) Close() error {
	var err error
	if c.Held != nil {
		err = c.Held.Close()
	}
	if c.Listener != nil {
		if e := c.Listener.Close(); err == nil {
			err = e
		}
		c.Listener = nil
	}
	return err
}

// StartChild launches only the measured helper. Agent code waits for Release.
// Place, Install, independent watchdog custody, and BindBootstrap must follow.
func (g *Group) StartChild(ctx context.Context, p Plan, helper, helperDigest string, manifest lifecycle.Manifest, paths childwire.IOPaths) (out *Child, err error) {
	return g.startChild(ctx, p, helper, helperDigest, manifest, paths, nil, childwire.NamespaceIdentity{}, nil)
}
func (g *Group) StartChildNamespace(ctx context.Context, p Plan, helper, helperDigest string, manifest lifecycle.Manifest, paths childwire.IOPaths, namespace *os.File, identity childwire.NamespaceIdentity) (out *Child, err error) {
	if namespace == nil || !p.bootstrapCredentialNamespace {
		return nil, errors.New("the credential namespace requires explicit qualified bootstrap permission")
	}
	return g.startChild(ctx, p, helper, helperDigest, manifest, paths, namespace, identity, nil)
}
func (g *Group) StartChildDocker(ctx context.Context, p Plan, helper, helperDigest string, manifest lifecycle.Manifest, paths childwire.IOPaths, docker childwire.DockerDescriptors) (out *Child, err error) {
	if manifest.AgentKind != "ssh" {
		return nil, errors.New("the Docker target is reserved for signed SSH coding")
	}
	return g.startChild(ctx, p, helper, helperDigest, manifest, paths, nil, childwire.NamespaceIdentity{}, &docker)
}
func (g *Group) startChild(ctx context.Context, p Plan, helper, helperDigest string, manifest lifecycle.Manifest, paths childwire.IOPaths, namespace *os.File, identity childwire.NamespaceIdentity, docker *childwire.DockerDescriptors) (out *Child, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.Files == nil || p.domain != g.Files.ID || p.generation <= g.generation {
		return nil, errors.New("the child requires a fresh owned policy plan")
	}
	if err = p.ValidateChildBootstrap(helperDigest); err != nil {
		return nil, err
	}
	if p.bootstrapCredentialNamespace != (namespace != nil) || (docker != nil && namespace != nil) {
		return nil, errors.New("the declared credential namespace custody differs")
	}
	var transport *childwire.Transport
	if docker != nil {
		transport, err = childwire.NewDocker(manifest, paths, p.syscalls, *docker)
	} else if namespace != nil {
		transport, err = childwire.NewNamespace(manifest, paths, p.syscalls, namespace, identity)
	} else {
		transport, err = childwire.New(manifest, paths, p.syscalls)
	}
	if err != nil {
		return nil, err
	}
	defer transport.Close()
	child := &Child{}
	if child.declaration, err = transport.Declaration(); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if stopErr := child.Close(); stopErr != nil {
				out = child
				err = errors.Join(err, stopErr)
			}
		}
	}()
	spec := heldprocess.Spec{Executable: helper, SHA256: helperDigest, Arguments: []string{"--run"}, Environment: []string{}, ExtraFiles: transport.ExtraFiles(), RequireSeccomp: true, RequireFilterAcknowledgement: true, NamespaceDevice: identity.Device, NamespaceInode: identity.Inode}
	if docker != nil {
		id := docker.Identity
		spec.Docker = true
		spec.NamespaceDevice, spec.NamespaceInode = id.Mount.Device, id.Mount.Inode
		spec.NetworkDevice, spec.NetworkInode = id.Network.Device, id.Network.Inode
		spec.PIDDevice, spec.PIDInode = id.PID.Device, id.PID.Inode
		spec.RootDevice, spec.RootInode = id.Root.Device, id.Root.Inode
	}
	child.Held, err = heldprocess.Start(ctx, spec)
	if err != nil {
		return nil, err
	}
	ack, err := heldprocess.DecodeFilterAcknowledgement(child.Held.FilterAcknowledgement())
	frame := child.declaration.Filters
	if err != nil || len(frame) < 20 || ack.ListenerRequired != binary.LittleEndian.Uint32(frame[8:]) || ack.InitialCount != binary.LittleEndian.Uint32(frame[12:]) || ack.FinalCount != binary.LittleEndian.Uint32(frame[16:]) {
		return nil, errors.New("the measured helper filter installation differs from its sealed frame")
	}
	child.Listener, err = transport.Receive(ctx, child.Held.Process())
	if err != nil {
		return nil, err
	}
	return child, nil
}
