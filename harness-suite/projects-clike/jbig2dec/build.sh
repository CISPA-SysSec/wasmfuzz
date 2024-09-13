#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

./autogen.sh --enable-shared=no --host=wasm32-wasi

make jbig2dec -j$(nproc)
$CXX $CXXFLAGS -std=c++11 -I. \
    ../jbig2_fuzzer.cc -o /out/jbig2dec-fuzzer.wasm \
    $LIB_FUZZING_ENGINE .libs/libjbig2dec.a