#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

export LDFLAGS="$FUZZ_LDFLAGS"
./config wasm32-wasi \
	enable-fuzz-libfuzzer \
	no-threads no-asm no-thread-pool \
	no-sock no-stdio no-shared no-secure-memory \
	no-module no-ktls no-egd no-async \
	no-ui-console no-weak-ssl-ciphers

make -j8

FUZZERS=$(find fuzz/ -executable -type f -regex "[^.]*" -printf "%f\n")
for F in $FUZZERS; do
    cp fuzz/$F /out/openssl-$F.wasm
done
