#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"


# Build the library.
cmake . -DBUILD_SHARED_LIBS=OFF \
  -DWASI_SDK_PREFIX="${WASI_SDK_PREFIX}"
make -j $(nproc) graphite2

# Build fuzzers here since out cmake scripts do a bit messing with the
# -fsanitize parameters
$CXX $CXXFLAGS -std=c++11 -Isrc -Iinclude \
    ./tests/fuzz-tests/gr-fuzzer-font.cpp ./src/TtfUtil.cpp \
    -o /out/graphite-fuzzer-font.wasm \
    $LIB_FUZZING_ENGINE src/libgraphite2.a

$CXX $CXXFLAGS -std=c++11 -Isrc -Iinclude \
    ./tests/fuzz-tests/gr-fuzzer-segment.cpp ./src/TtfUtil.cpp \
    -o /out/graphite-fuzzer-segment.wasm \
    $LIB_FUZZING_ENGINE src/libgraphite2.a

