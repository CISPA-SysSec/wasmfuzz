#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo/ossfuzz"

# upstream ossfuzz/ossfuzz.sh, with wasi-sdk tools; LZ4_DEBUG=1 (asserts) as on oss-fuzz
make -j$(nproc) V=1 AR=llvm-ar CC="$CC" CXX="$CXX" \
    CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS" LIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE" all

for f in *_fuzzer; do
  cp $f /out/lz4-$f.wasm
done
