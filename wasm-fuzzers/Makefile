PODMAN_BUILD := podman build --cache-ttl=72h
FUZZERS := libfuzzer-wasm2c aflpp-wasm2c libafl-libfuzzer-wasm2c wasmfuzz wafl fuzzm

.PHONY: all $(FUZZERS) wasm-fuzzers-wasm2c-base

all: $(addprefix wasm-fuzzers-,$(FUZZERS))

wasm-fuzzers-wasm2c-base:
	$(PODMAN_BUILD) -f Dockerfile.wasm2c-base . -t $@

wasm-fuzzers-%: wasm-fuzzers-wasm2c-base
	$(PODMAN_BUILD) -f Dockerfile.$* . -t $@

wasm-fuzzers-wasmfuzz:
	$(PODMAN_BUILD) -f Dockerfile.wasmfuzz . -t $@
