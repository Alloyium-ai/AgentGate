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
