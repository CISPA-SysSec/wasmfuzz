PODMAN_BUILD ?= podman build --cache-ttl=72h
FUZZERS := libfuzzer-wasm2c libfuzzer-w2c2 aflpp-wasm2c aflpp-w2c2 libafl-libfuzzer-wasm2c wasmfuzz wasmfuzz-rel wafl
# fuzzm

.PHONY: all $(FUZZERS) wasm-fuzzers-wasm2c-base wasm-fuzzers-w2c2-base
# $(addprefix wasm-fuzzers-,$(FUZZERS))

all: $(addprefix wasm-fuzzers-,$(FUZZERS))

wasm-fuzzers-wasm2c-base:
	$(PODMAN_BUILD) -f Dockerfile.wasm2c-base . -t $@

wasm-fuzzers-w2c2-base:
	$(PODMAN_BUILD) -f Dockerfile.w2c2-base . -t $@

wasm-fuzzers-%: wasm-fuzzers-wasm2c-base wasm-fuzzers-w2c2-base
	$(PODMAN_BUILD) -f Dockerfile.$* . -t $@

wasm-fuzzers-wasmfuzz:
	$(PODMAN_BUILD) -f Dockerfile.wasmfuzz . -t $@
