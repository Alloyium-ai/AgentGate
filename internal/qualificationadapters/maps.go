// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"errors"
	"fmt"
	"reflect"

	"alloyium.local/kernel-poc/internal/anonrules"
	"alloyium.local/kernel-poc/internal/enforcement"
	"alloyium.local/kernel-poc/internal/fsrules"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/netrules"
	"alloyium.local/kernel-poc/internal/openrules"
	"alloyium.local/kernel-poc/internal/processrules"
	"alloyium.local/kernel-poc/internal/qualification"
)

func snapshotMaps(g *enforcement.Group, p enforcement.Plan, document qualification.Request) (out mapSnapshot, err error) {
	out.Owned = map[string]uint32{}
	out.SharedMaps = map[string][2]uint32{}
	if out.ReadbackSHA256, err = g.VerifyInstalled(p); err != nil {
		return out, err
	}
	if err = anonrules.VerifyCoupling(g.Files, g.Anonymous); err != nil {
		return out, err
	}
	for _, item := range []struct {
		r    *kernel.Runtime
		name string
		out  any
	}{
		{g.Files, "policies", &out.Files}, {g.Peers, "net_policies", &out.Peers}, {g.Sockets, "sock_policies", &out.Sockets}, {g.Custody, "cust_bindings", &out.Custody}, {g.Process, "proc_policies", &out.Process},
	} {
		if err = item.r.Collection.Maps[item.name].Lookup(g.Files.ID, item.out); err != nil {
			return out, err
		}
	}
	for name, item := range map[string]struct {
		r   *kernel.Runtime
		key string
	}{"files": {g.Files, "owned"}, "sockets": {g.Sockets, "sock_managed"}, "custody": {g.Custody, "cust_managed"}, "process": {g.Process, "proc_managed"}} {
		var value uint32
		if err = item.r.Collection.Maps[item.key].Lookup(g.Files.ID, &value); err != nil {
			return out, err
		}
		out.Owned[name] = value
	}
	for _, name := range []string{"owned", "policies", "file_cookies", "events", "stats"} {
		var ids [2]uint32
		for i, r := range []*kernel.Runtime{g.Files, g.Anonymous} {
			info, e := r.Collection.Maps[name].Info()
			if e != nil {
				return out, e
			}
			id, ok := info.ID()
			if !ok {
				return out, errors.New("qualification map ID is unavailable")
			}
			ids[i] = uint32(id)
		}
		out.SharedMaps[name] = ids
	}
	filePlan, err := fsrules.CompileWithRuntime(*document.Document.Files, *document.Document.Programs, *document.Document.Runtime, g.Files.ID, out.Files.Generation, out.Files.ExpiresNS)
	if err != nil {
		return out, err
	}
	for _, entry := range filePlan.Entries() {
		var node openrules.Node
		if err = g.Files.Collection.Maps["nodes"].Lookup(entry.Key, &node); err != nil {
			return out, err
		}
		out.Nodes = append(out.Nodes, openrules.Entry{Key: entry.Key, Node: node})
	}
	return out, nil
}

func verifyMaps(request qualification.Request, r candidateReceipt) error {
	if !reflect.DeepEqual(r.Before, r.After) {
		return errors.New("qualification maps changed during the actor run")
	}
	filePlan, err := fsrules.CompileWithRuntime(*request.Document.Files, *request.Document.Programs, *request.Document.Runtime, r.DomainID, r.Generation, r.DeadlineNS)
	if err != nil {
		return err
	}
	expectedFiles := filePlan.WithAnonymousGuard().State()
	expectedFiles.SocketGeneration = r.Generation
	if r.Before.Files != expectedFiles || !reflect.DeepEqual(r.Before.Nodes, filePlan.Entries()) {
		return errors.New("qualification file map differs from the exact candidate")
	}
	peers, err := netrules.Compile(*request.Document.Network, r.Generation, r.HeldInstalled.MonoNS, r.DeadlineNS, nil)
	if err != nil {
		return err
	}
	sockets, err := netrules.CompileSockets(*request.Document.Sockets, r.Generation, r.HeldInstalled.MonoNS, r.DeadlineNS)
	if err != nil {
		return err
	}
	process, err := processrules.Compile(*request.Document.Runtime, r.DomainID, r.Generation, r.DeadlineNS)
	if err != nil {
		return err
	}
	if r.Before.Peers != peers.Policy || r.Before.Sockets != sockets.Plan || r.Before.Process != process.State() || r.Before.Custody != (custodyState{r.Generation, r.DeadlineNS}) {
		return errors.New("qualification resource map differs from the exact candidate")
	}
	if len(r.Before.Owned) != 4 || len(r.Before.SharedMaps) != 5 {
		return errors.New("qualification ownership or shared map count differs")
	}
	for _, name := range []string{"files", "sockets", "custody", "process"} {
		if r.Before.Owned[name] != 1 {
			return fmt.Errorf("qualification ownership marker differs: %s", name)
		}
	}
	for _, name := range []string{"owned", "policies", "file_cookies", "events", "stats"} {
		ids := r.Before.SharedMaps[name]
		if ids[0] == 0 || ids[0] != ids[1] {
			return errors.New("qualification anonymous coupling differs")
		}
	}
	return nil
}
