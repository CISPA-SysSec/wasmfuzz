PODMAN_BUILD := podman build --cache-ttl=72h -f Dockerfile.
FUZZERS := libfuzzer-wasm2c aflpp-wasm2c libafl-libfuzzer-wasm2c wasmfuzz wafl fuzzm

.PHONY: all $(FUZZERS) wasm-fuzzers-wasm2c-base

all: $(addprefix wasm-fuzzers-,$(FUZZERS))

wasm-fuzzers-wasm2c-base:
	$(PODMAN_BUILD)wasm2c-base . -t $@

wasm-fuzzers-%: wasm-fuzzers-wasm2c-base
	$(PODMAN_BUILD)$* . -t $@

wasm-fuzzers-wasmfuzz:
	$(PODMAN_BUILD)wasmfuzz . -t $@
