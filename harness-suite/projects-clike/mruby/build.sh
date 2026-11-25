#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

# rake builds a native host mrbc first; hand the wasm toolchain to the cross
# build through WASM_* and keep CC/CFLAGS out of the host build.
export WASM_CC="$CC" WASM_CXX="$CXX" WASM_CFLAGS="$CFLAGS" WASM_CXXFLAGS="$CXXFLAGS"
env -u CC -u CXX -u LD -u CFLAGS -u CXXFLAGS -u LDFLAGS \
    MRUBY_CONFIG="$PROJECT/wasmfuzz.rb" rake -m -j"$(nproc)" all

# FuzzBench mruby_fuzzer_8c8bbd = upstream oss-fuzz/mruby_fuzzer.c
$CC $CFLAGS -Iinclude -Ibuild/wasi/include -c oss-fuzz/mruby_fuzzer.c -o mruby_fuzzer.o
$CXX $CXXFLAGS mruby_fuzzer.o build/wasi/lib/libmruby.a \
    $LIB_FUZZING_ENGINE -lm -o /out/mruby-mruby_fuzzer.wasm
