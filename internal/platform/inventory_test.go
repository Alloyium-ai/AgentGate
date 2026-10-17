// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package platform

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func TestInventoryDoesNotTreatNewAttachTypesAsSupportedControls(t *testing.T) {
	for _, name := range []string{"BPF_CGROUP_FUTURE_CONTROL", "BPF_LSM_CGROUP", "BPF_TRACE_FENTRY"} {
		if _, known := CgroupProgram(name); known {
			t.Fatal("an unknown target mechanism received an implicit probe")
		}
	}
	for name, want := range map[string]ebpf.ProgramType{"BPF_CGROUP_INET_INGRESS": ebpf.CGroupSKB, "BPF_CGROUP_UNIX_CONNECT": ebpf.CGroupSockAddr, "BPF_CGROUP_DEVICE": ebpf.CGroupDevice, "BPF_CGROUP_SETSOCKOPT": ebpf.CGroupSockopt} {
		if got, ok := CgroupProgram(name); !ok || got != want {
			t.Fatalf("wrong mechanism for%s", name)
		}
	}
}
func TestHelperProbeRequiresActualBTFPathCustody(t *testing.T) {
	path := &btf.Struct{Name: "path"}
	file := &btf.Struct{Name: "file", Members: []btf.Member{{Name: "f_path", Type: path, Offset: 128}}}
	proto := &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4}, Params: []btf.FuncParam{{Name: "file", Type: &btf.Pointer{Target: file}}}}
	instructions, ok := pathHelperInstructions(proto, 0, proto.Params[0].Type)
	if !ok || len(instructions) < 8 {
		t.Fatal("actual file path custody did not produce a helper probe")
	}
	if _, ok = pathHelperInstructions(proto, 0, &btf.Pointer{Target: &btf.Struct{Name: "dentry"}}); ok {
		t.Fatal("a dentry became a fabricated path")
	}
	if _, ok = pathHelperInstructions(proto, 0, &btf.Pointer{Target: &btf.Struct{Name: "file"}}); ok {
		t.Fatal("a file without target path layout received a helper probe")
	}
	ret := preservedReturn(proto)
	if ret[0].Src != asm.R1 || ret[0].Offset != 8 {
		t.Fatal("the probe did not preserve the preceding LSM decision")
	}
}
func TestKernelConfigRetainsDisabledAndMissingStates(t *testing.T) {
	config := kernelConfig([]byte("CONFIG_BPF_LSM=y\n# CONFIG_ANDROID_BINDER_IPC is not set\n"))
	if config["CONFIG_BPF_LSM"] != "y" || config["CONFIG_ANDROID_BINDER_IPC"] != "n" || config["CONFIG_SECCOMP_FILTER"] != "unreported" {
		t.Fatal("the target config conflated missing and disabled features")
	}
}
