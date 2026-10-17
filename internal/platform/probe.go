// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func bytesDigest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// ProbeDisposable requires the dedicated fixture marker. It cannot run on a host node.
func ProbeDisposable() (Inventory, error) {
	var report Inventory
	marker, err := os.ReadFile("/etc/alloyium-disposable-vm")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(marker)), "kernel-poc-agentgate-g0-") || os.Geteuid() != 0 {
		return report, errors.New("target probes require the owned root disposable G0 fixture")
	}
	var uname unix.Utsname
	if err = unix.Uname(&uname); err != nil {
		return report, err
	}
	kernel := unix.ByteSliceToString(uname.Release[:])
	if kernel != "6.8.0-142-generic" || runtime.GOARCH != "amd64" {
		return report, errors.New("target probes require Ubuntu 6.8.0-142 x86-64")
	}
	if _, err = os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return report, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return report, err
	}
	lsm, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return report, err
	}
	if !strings.Contains(","+strings.TrimSpace(string(lsm))+",", ",bpf,") {
		return report, errors.New("target lacks active BPF LSM")
	}
	btfBytes, err := os.ReadFile("/sys/kernel/btf/vmlinux")
	if err != nil {
		return report, err
	}
	config, err := os.ReadFile("/boot/config-" + kernel)
	if err != nil {
		return report, err
	}
	self, err := os.Executable()
	if err != nil {
		return report, err
	}
	probeBytes, err := os.ReadFile(self)
	if err != nil {
		return report, err
	}
	report = Inventory{SchemaVersion: InventoryVersion, Purpose: "availability-and-attachment-probe", Kernel: kernel, Architecture: "x86_64", Boot: strings.TrimSpace(string(boot)), BTFDigest: bytesDigest(btfBytes), ProbeDigest: bytesDigest(probeBytes), LSM: strings.TrimSpace(string(lsm)), Hooks: []Hook{}, Seccomp: seccompAvailability()}
	report.ConfigDigest = bytesDigest(config)
	report.KernelConfig = kernelConfig(config)
	if err = rlimit.RemoveMemlock(); err != nil {
		return report, err
	}
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return report, err
	}
	definitions, err := LSMDefinitions(spec)
	if err != nil {
		return report, err
	}
	for _, definition := range definitions {
		fmt.Fprintln(os.Stderr, "G0_PROBE", definition.Name)
		report.Hooks = append(report.Hooks, probeLSM(definition))
	}
	cgroup := "/sys/fs/cgroup/agentgate-g0-probe-" + fmt.Sprint(os.Getpid())
	if err = os.Mkdir(cgroup, 0700); err != nil {
		return report, err
	}
	defer os.Remove(cgroup)
	hooks, err := probeCgroup(spec, cgroup)
	if err != nil {
		return report, err
	}
	report.Hooks = append(report.Hooks, hooks...)
	if err = os.Remove(cgroup); err != nil {
		return report, err
	}
	report.Seccomp["scalar-getppid-denial-probe-only"] = probeScalarProcess(self)
	return report, nil
}

func preservedReturn(proto *btf.FuncProto) asm.Instructions {
	if _, ok := btf.UnderlyingType(proto.Return).(*btf.Void); ok {
		return asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}
	}
	return asm.Instructions{asm.LoadMem(asm.R0, asm.R1, int16(len(proto.Params)*8), asm.DWord), asm.Return()}
}
func attachLSM(name string, proto *btf.FuncProto, sleepable bool, instructions asm.Instructions) Attachment {
	flags := uint32(0)
	if sleepable {
		flags = unix.BPF_F_SLEEPABLE
	}
	// Ubuntu constrains this hook to an errno return. Preserve every valid prior
	// result and bound the synthetic context value for the verifier.
	if name == "socket_getpeersec_stream" {
		instructions = append(instructions[:len(instructions)-1], asm.LSh.Imm(asm.R0, 32), asm.ArSh.Imm(asm.R0, 32), asm.JSGT.Imm(asm.R0, 0, "invalid_ret"), asm.JSLT.Imm(asm.R0, -4095, "invalid_ret"), asm.Return(), asm.Mov.Imm(asm.R0, 0).WithSymbol("invalid_ret"), asm.Return())
	}
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "ag_g0_probe", Type: ebpf.LSM, AttachType: ebpf.AttachLSMMac, AttachTo: name, License: "GPL", Flags: flags, Instructions: instructions})
	if err != nil {
		return Attachment{Error: fmt.Sprintf("%+v", err)}
	}
	defer program.Close()
	result := Attachment{Loaded: true}
	attachment, err := link.AttachLSM(link.LSMOptions{Program: program})
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Attached = true
	if err = attachment.Close(); err != nil {
		result.Error = "detach: " + err.Error()
	}
	return result
}

func probeLSM(definition HookDefinition) Hook {
	name, proto := definition.Name, definition.Proto
	hook := Hook{Name: name, Family: Family(name), Mechanism: "bpf-lsm", Available: true, ReturnType: btf.UnderlyingType(proto.Return).TypeName(), Classification: "unavailable", Reason: "Operation decision qualification remains required.", Helpers: []HelperProbe{}}
	_, isVoid := btf.UnderlyingType(proto.Return).(*btf.Void)
	if isVoid {
		hook.ReturnType = "void"
		hook.Classification = "audit-only"
		hook.Reason = "A void hook cannot veto the operation."
	}
	hook.Attachment = attachLSM(name, proto, false, preservedReturn(proto))
	hook.Sleepable = attachLSM(name, proto, true, preservedReturn(proto))
	if !hook.Attachment.Attached && !hook.Sleepable.Attached {
		hook.Classification = "unavailable"
		hook.Reason = "The target rejected both attachment modes."
	}
	if strings.Contains(hook.Attachment.Error, "points to wrong type name") {
		hook.Available = false
		hook.Classification = "not-applicable"
		hook.Mechanism = "bpf-lsm-internal-symbol"
		hook.Reason = "The target verifier excludes this BTF symbol from its LSM hook set."
	}
	for index, param := range proto.Params {
		instructions, ok := pathHelperInstructions(proto, index, param.Type)
		if !ok {
			continue
		}
		for _, sleepable := range []bool{false, true} {
			hook.Helpers = append(hook.Helpers, HelperProbe{Helper: "bpf_d_path", Parameter: param.Name, Sleepable: sleepable, Attachment: attachLSM(name, proto, sleepable, instructions)})
		}
	}
	return hook
}

func memberOffset(typ btf.Type, name string) (int32, btf.Type, bool) {
	structure, ok := btf.UnderlyingType(typ).(*btf.Struct)
	if !ok {
		return 0, nil, false
	}
	for _, member := range structure.Members {
		if member.Name == name && member.Offset%8 == 0 {
			return int32(member.Offset / 8), member.Type, true
		}
	}
	return 0, nil, false
}
func pointerTarget(typ btf.Type) btf.Type {
	pointer, ok := btf.UnderlyingType(typ).(*btf.Pointer)
	if !ok {
		return nil
	}
	return btf.UnderlyingType(pointer.Target)
}

func pathHelperInstructions(proto *btf.FuncProto, index int, typ btf.Type) (asm.Instructions, bool) {
	target := pointerTarget(typ)
	if target == nil {
		return nil, false
	}
	instructions := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R1, asm.R6, int16(index*8), asm.DWord), asm.JEq.Imm(asm.R1, 0, "return_previous")}
	switch target.TypeName() {
	case "path":
	case "linux_binprm", "vm_area_struct":
		member := "file"
		if target.TypeName() == "vm_area_struct" {
			member = "vm_file"
		}
		offset, fileType, ok := memberOffset(target, member)
		if !ok {
			return nil, false
		}
		instructions = append(instructions, asm.LoadMem(asm.R1, asm.R1, int16(offset), asm.DWord), asm.JEq.Imm(asm.R1, 0, "return_previous"))
		target = pointerTarget(fileType)
		if target == nil {
			return nil, false
		}
		fallthrough
	case "file":
		offset, _, ok := memberOffset(target, "f_path")
		if !ok {
			return nil, false
		}
		instructions = append(instructions, asm.Add.Imm(asm.R1, offset))
	default:
		return nil, false
	}
	instructions = append(instructions, asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -256), asm.Mov.Imm(asm.R3, 256), asm.FnDPath.Call())
	ret := preservedReturn(proto)
	ret[0] = ret[0].WithSymbol("return_previous")
	if _, isVoid := btf.UnderlyingType(proto.Return).(*btf.Void); !isVoid {
		ret[0] = asm.LoadMem(asm.R0, asm.R6, int16(len(proto.Params)*8), asm.DWord).WithSymbol("return_previous")
	}
	return append(instructions, ret...), true
}

func probeCgroup(spec *btf.Spec, path string) ([]Hook, error) {
	var enum *btf.Enum
	if err := spec.TypeByName("bpf_attach_type", &enum); err != nil {
		return nil, err
	}
	hooks := []Hook{}
	for _, value := range enum.Values {
		if value.Name == "BPF_LSM_CGROUP" {
			hooks = append(hooks, Hook{Name: value.Name, Family: "all-target-families", Mechanism: "cgroup-lsm", ReturnType: "int", Available: true, Classification: "unavailable", Reason: "Per-hook cgroup-LSM attachment and operation decisions remain unqualified.", Helpers: []HelperProbe{}})
			continue
		}
		if !strings.HasPrefix(value.Name, "BPF_CGROUP_") {
			continue
		}
		hook := Hook{Name: value.Name, Family: "network-sockets", Mechanism: "cgroup-bpf", ReturnType: "int", Available: true, Classification: "unavailable", Reason: "Operation decision qualification remains required.", Helpers: []HelperProbe{}}
		if value.Name == "BPF_CGROUP_DEVICE" {
			hook.Family = "host-kernel"
		}
		if value.Name == "BPF_CGROUP_SYSCTL" {
			hook.Family = "host-kernel"
		}
		typ, known := CgroupProgram(value.Name)
		if !known {
			hook.Reason = "The target attach type has no registered probe program."
			hooks = append(hooks, hook)
			continue
		}
		ret := int32(1)
		if typ == ebpf.SockOps {
			ret = 0
			hook.Classification = "audit-only"
			hook.Reason = "This probe observes socket operations; it does not authorize resources."
		}
		program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "ag_cg_probe", Type: typ, AttachType: ebpf.AttachType(value.Value), License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, ret), asm.Return()}})
		if err != nil {
			hook.Attachment.Error = fmt.Sprintf("%+v", err)
			hooks = append(hooks, hook)
			continue
		}
		hook.Attachment.Loaded = true
		attachment, err := link.AttachCgroup(link.CgroupOptions{Path: path, Attach: ebpf.AttachType(value.Value), Program: program})
		if err == nil {
			hook.Attachment.Attached = true
			err = attachment.Close()
		}
		if err != nil {
			hook.Attachment.Error = err.Error()
		}
		program.Close()
		hooks = append(hooks, hook)
	}
	return hooks, nil
}

func seccompAvailability() map[string]SeccompProbe {
	result := map[string]SeccompProbe{}
	for name, action := range map[string]uint32{"kill-process": unix.SECCOMP_RET_KILL_PROCESS, "errno": unix.SECCOMP_RET_ERRNO, "user-notify": unix.SECCOMP_RET_USER_NOTIF, "allow": unix.SECCOMP_RET_ALLOW} {
		_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_GET_ACTION_AVAIL, 0, uintptr(unsafe.Pointer(&action)))
		item := SeccompProbe{Available: errno == 0}
		if errno != 0 {
			item.Error = errno.Error()
		}
		result[name] = item
	}
	return result
}

func kernelConfig(raw []byte) map[string]string {
	result := map[string]string{}
	for _, name := range []string{"BPF", "BPF_SYSCALL", "BPF_LSM", "DEBUG_INFO_BTF", "SECURITY_PATH", "SECURITY_NETWORK", "SECURITY_INFINIBAND", "SECURITY_NETWORK_XFRM", "KEYS", "PERF_EVENTS", "IO_URING", "SECCOMP", "SECCOMP_FILTER", "CGROUPS", "CGROUP_BPF", "CGROUP_DEVICE", "USER_NS", "IPC_NS", "NET_NS", "SYSVIPC", "ANDROID_BINDER_IPC"} {
		result["CONFIG_"+name] = "unreported"
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			if _, wanted := result[key]; wanted {
				result[key] = value
			}
		}
		if strings.HasPrefix(line, "# CONFIG_") && strings.HasSuffix(line, " is not set") {
			key := strings.TrimSuffix(strings.TrimPrefix(line, "# "), " is not set")
			if _, wanted := result[key]; wanted {
				result[key] = "n"
			}
		}
	}
	return result
}
