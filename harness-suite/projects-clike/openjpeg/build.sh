#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"


# Build the library.
cmake . -DBUILD_SHARED_LIBS=OFF \
  -DOPJ_USE_THREAD=OFF \
  -DWASI_SDK_PREFIX="${WASI_SDK_PREFIX}"
make -j $(nproc)

# Build fuzzers here since out cmake scripts do a bit messing with the
# -fsanitize parameters
$CXX $CXXFLAGS -std=c++11 -Isrc/lib/openjp2 \
    ./tests/fuzzers/opj_decompress_fuzzer_J2K.cpp \
    -o /out/openjpeg-opj_decompress_fuzzer_J2K.wasm \
    $LIB_FUZZING_ENGINE bin/libopenjp2.a -lm

$CXX $CXXFLAGS -std=c++11 -Isrc/lib/openjp2 \
    ./tests/fuzzers/opj_decompress_fuzzer_JP2.cpp \
    -o /out/openjpeg-opj_decompress_fuzzer_JP2.wasm \
    $LIB_FUZZING_ENGINE bin/libopenjp2.a -lm
