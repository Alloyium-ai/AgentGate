.PHONY: all test
all: build/agentgate build/agentgate-node build/enforce.bpf.o
build/agentgate:
	mkdir -p build
	CGO_ENABLED=0 go build -trimpath -o $@ ./cmd/community
build/agentgate-node:
	mkdir -p build
	CGO_ENABLED=0 go build -trimpath -o $@ ./cmd/poc
build/enforce.bpf.o:
	mkdir -p build
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c bpf/enforce.bpf.c -o $@
test:
	go test -race ./...

# Fixed diagnostic artifacts. This target does not load BPF or grant admission.
build/pilot-network-diagnostic:
	mkdir -p build
	CGO_ENABLED=0 go build -trimpath -ldflags "-X alloyium.local/kernel-poc/internal/buildinfo.SourceRevision=$(SOURCE_REVISION)" -o $@ ./cmd/pilot-network-diagnostic
build/network_policy.bpf.o:
	mkdir -p build
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c bpf/network_policy.bpf.c -o $@
build/fs_access.bpf.o:
	mkdir -p build
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c bpf/fs_access.bpf.c -o $@
build/process_guard.bpf.o:
	mkdir -p build
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c bpf/process_guard.bpf.c -o $@
