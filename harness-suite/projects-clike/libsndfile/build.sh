#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

autoreconf -vif
./configure --disable-shared --enable-ossfuzzers --host=wasm32-wasi
make V=1

# Copy the fuzzer to the output directory.
cp ossfuzz/sndfile_fuzzer /out/libsndfile_fuzzer.wasm
cp ossfuzz/sndfile_alt_fuzzer /out/libsndfile_alt_fuzzer.wasm