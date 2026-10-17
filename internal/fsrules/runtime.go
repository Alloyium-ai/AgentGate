// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package fsrules

import (
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/openrules"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// NewAccessRuntime loads the private access component only in the disposable VM.
// It does not qualify a complete runtime, mutation policy, or workload admission.
func NewAccessRuntime(object, domain string) (*kernel.Runtime, error) {
	return kernel.NewProfile(object, domain, AccessProfile())
}

// AccessProfile installs zero rights before any file hook attaches.
func AccessProfile() kernel.Profile {
	return kernel.Profile{
		Initialize: func(r *kernel.Runtime) error {
			for _, name := range []string{"owned", "policies", "nodes", "file_cookies", "file_grants", "file_grant_keys", "bootstrap", "events", "stats"} {
				if r.Collection.Maps[name] == nil {
					return fmt.Errorf("file access object lacks map %s", name)
				}
			}
			if err := r.Collection.Maps["owned"].Update(r.ID, uint32(1), ebpf.UpdateNoExist); err != nil {
				return err
			}
			return r.Collection.Maps["policies"].Update(r.ID, State{}, ebpf.UpdateNoExist)
		},
		LSMPrograms:    []string{"fs_alloc", "fs_free", "fs_open", "fs_use", "fs_receive", "fs_exec", "fs_mmap", "fs_mprotect", "fs_create", "fs_mkdir", "fs_mknod", "fs_unlink", "fs_rmdir", "fs_rename", "fs_link", "fs_symlink", "fs_chmod", "fs_chown", "fs_truncate", "fs_ioctl", "fs_getattr"},
		ProgramOptions: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats, LogSizeStart: 4 << 20},
	}
}

func validateAccessInstall(plan Plan, domain, now, current uint64) error {
	return validateAccessInstallCoupled(plan, domain, now, current, false)
}
func validateAccessInstallCoupled(plan Plan, domain, now, current uint64, anonymous bool) error {
	allowed := uint64(7)
	if anonymous {
		allowed = 63 | AnonymousDelegation
	}
	if plan.state.Pipes&^allowed != 0 || plan.state.Pipes&uint64(56) != 0 && plan.state.Pipes&AnonymousDelegation == 0 {
		return errors.New("explicit eventfd permissions require the qualified anonymous object guard")
	}
	if plan.domain != domain || plan.state.Generation <= current || plan.state.ExpiresNS <= now || plan.digest == "" || plan.digest != planDigest(plan) {
		return errors.New("file access binding, generation, digest, or deadline differs")
	}
	for _, operation := range plan.allowOperations {
		switch operation {
		case "read", "write", "execute", "mmap", "map_execute", "mprotect", "descriptor_receive":
		default:
			return fmt.Errorf("file access component does not implement allowance %s", operation)
		}
	}
	return nil
}

// CheckAccess rejects unsupported positive rights before job preparation. The
// generic forest compiler remains available for draft and reference evaluation.
func (plan Plan) CheckAccess(domain, now uint64) error {
	return validateAccessInstall(plan, domain, now, 0)
}
func (plan Plan) CheckAccessWithAnonymous(domain, now uint64) error {
	return validateAccessInstallCoupled(plan, domain, now, 0, true)
}

// InstallAccess serializes a complete staged forest and its active generation.
// This private component permits no namespace mutation allowance.
func InstallAccess(r *kernel.Runtime, plan Plan) error {
	return installAccess(r, plan, nil)
}

// InstallAccessCoupled verifies the guard, its shared maps and sole reader.
func InstallAccessCoupled(r *kernel.Runtime, plan Plan, anonymous *kernel.Runtime) error {
	if anonymous == nil {
		return errors.New("the mandatory anonymous runtime is absent")
	}
	return anonymous.WithPolicyUpdate(func() error {
		if err := verifyAnonymousCoupling(r, anonymous); err != nil {
			return err
		}
		return installAccess(r, plan, anonymous)
	})
}
func installAccess(r *kernel.Runtime, plan Plan, anonymous *kernel.Runtime) error {
	return r.WithPolicyUpdate(func() error {
		policies, nodes := r.Collection.Maps["policies"], r.Collection.Maps["nodes"]
		if policies == nil || nodes == nil {
			return errors.New("file access policy maps are unavailable")
		}
		var current State
		if err := policies.Lookup(r.ID, &current); err != nil {
			return err
		}
		now, err := kernel.MonotonicNS()
		if err != nil {
			return err
		}
		if err = validateAccessInstallCoupled(plan, r.ID, now, current.Generation, anonymous != nil); err != nil {
			return err
		}
		inserted := []openrules.Key{}
		rollback := func() {
			for _, key := range inserted {
				_ = nodes.Delete(key)
			}
		}
		for _, entry := range plan.entries {
			if err = nodes.Update(entry.Key, entry.Node, ebpf.UpdateNoExist); err != nil {
				rollback()
				return err
			}
			inserted = append(inserted, entry.Key)
		}
		if err = policies.Update(r.ID, plan.state, ebpf.UpdateExist); err != nil {
			rollback()
			return err
		}
		var installed State
		if err = policies.Lookup(r.ID, &installed); err != nil {
			return err
		}
		if installed != plan.state {
			return errors.New("file policy readback differs")
		}
		for _, entry := range plan.entries {
			var node openrules.Node
			if err = nodes.Lookup(entry.Key, &node); err != nil {
				return err
			}
			if node != entry.Node {
				return errors.New("file rule readback differs")
			}
		}
		return nil
	})
}

func verifyAnonymousCoupling(files, anonymous *kernel.Runtime) error {
	if files == nil || anonymous == nil || files.ID == 0 || files.ID != anonymous.ID || files.Collection == nil || anonymous.Collection == nil || files.Reader == nil || anonymous.Reader != nil {
		return errors.New("anonymous enforcement requires one owned file audit reader")
	}
	got := map[string]bool{}
	for _, name := range anonymous.Hooks() {
		got[name] = true
	}
	for _, name := range []string{"anonymous_alloc", "anonymous_use", "anonymous_receive", "anonymous_free"} {
		if !got[name] {
			return errors.New("a mandatory anonymous guard hook is absent")
		}
	}
	for _, name := range []string{"owned", "policies", "file_cookies", "events", "stats"} {
		a, b := files.Collection.Maps[name], anonymous.Collection.Maps[name]
		if a == nil || b == nil {
			return errors.New("an anonymous shared file map is absent")
		}
		ai, ae := a.Info()
		bi, be := b.Info()
		if ae != nil || be != nil {
			return errors.New("anonymous shared map identity is unavailable")
		}
		ida, oka := ai.ID()
		idb, okb := bi.ID()
		if !oka || !okb || ida != idb {
			return errors.New("an anonymous file map identity differs")
		}
	}
	return nil
}
