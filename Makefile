.PHONY: all test agentgate FORCE
all: build/community build/agentgate-node build/enforce.bpf.o
build/community: FORCE
	mkdir -p build
	CGO_ENABLED=0 go build -trimpath -o $@ ./cmd/community

# The AgentGate release set: the CLI, the host agent, the credential broker
# and the control service, with SHA256SUMS for deploy/install.sh. Static
# binaries; go build decides whether anything is stale.
AGENTGATE_BINARIES := build/agentgate build/agentgate-hostd build/agentgate-broker build/community
AGENTGATE_RELEASE := $(AGENTGATE_BINARIES) build/agentgate-broker@.service
agentgate: $(AGENTGATE_RELEASE) build/SHA256SUMS
build/agentgate build/agentgate-hostd build/agentgate-broker: FORCE
	mkdir -p build
	CGO_ENABLED=0 go build -trimpath -o $@ ./cmd/$(notdir $@)
build/agentgate-broker@.service: cmd/agentgate-broker/agentgate-broker@.service
	mkdir -p build
	cp $< $@
build/SHA256SUMS: $(AGENTGATE_RELEASE)
	cd build && sha256sum $(notdir $(AGENTGATE_RELEASE)) > SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS
FORCE:
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
