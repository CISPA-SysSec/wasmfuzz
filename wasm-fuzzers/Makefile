FUZZERS := libfuzzer-wasm2c libfuzzer-w2c2 aflpp-wasm2c aflpp-w2c2 libafl-libfuzzer-wasm2c wasmfuzz wasmfuzz-rel-initial-commit wafl fuzzm

.PHONY: all $(FUZZERS) wasm-fuzzers-wasm2c-base wasm-fuzzers-w2c2-base
# $(addprefix wasm-fuzzers-,$(FUZZERS))

all: $(addprefix wasm-fuzzers-,$(FUZZERS))

wasm-fuzzers-wasm2c-base:
	./build-container.sh -f Dockerfile.wasm2c-base . -t $@

wasm-fuzzers-w2c2-base:
	./build-container.sh -f Dockerfile.w2c2-base . -t $@

wasm-fuzzers-%: wasm-fuzzers-wasm2c-base wasm-fuzzers-w2c2-base
	./build-container.sh -f Dockerfile.$* . -t $@

wasm-fuzzers-wasmfuzz:
	./build-container.sh -f Dockerfile.wasmfuzz . -t $@

# Allow building wasmfuzz at a specific commit hash or release
wasm-fuzzers-wasmfuzz-rel-%:
	./build-container.sh -f Dockerfile.wasmfuzz-rel . -t $@ --build-arg RELEASE=$(@:wasm-fuzzers-wasmfuzz-rel-%=%)
wasm-fuzzers-wasmfuzz-%:
	./build-container.sh -f Dockerfile.wasmfuzz . -t $@ --build-arg COMMIT=$(@:wasm-fuzzers-wasmfuzz-%=%)
