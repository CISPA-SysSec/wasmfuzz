#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

# Mirrors oss-fuzz's libaom build: cap single allocations and frame dimensions
# to avoid spurious OOMs, clamp transform range checks to suppress integer
# overflow noise.
extra_c_flags="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1"

cmake -S . -B build -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$CMAKE_TOOLCHAIN_FILE" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS_RELEASE="" \
    -DCMAKE_CXX_FLAGS_RELEASE="" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DAOM_TARGET_CPU=generic \
    -DCONFIG_RUNTIME_CPU_DETECT=0 \
    -DCONFIG_MULTITHREAD=0 \
    -DCONFIG_AV1_ENCODER=0 \
    -DCONFIG_AV1_DECODER=1 \
    -DCONFIG_AV1_HIGHBITDEPTH=1 \
    -DCONFIG_PIC=0 \
    -DCONFIG_SIZE_LIMIT=1 \
    -DDECODE_HEIGHT_LIMIT=12288 \
    -DDECODE_WIDTH_LIMIT=12288 \
    -DAOM_EXTRA_C_FLAGS="$extra_c_flags" \
    -DAOM_EXTRA_CXX_FLAGS="$extra_c_flags" \
    -DENABLE_APPS=0 \
    -DENABLE_EXAMPLES=0 \
    -DENABLE_DOCS=0 \
    -DENABLE_TESTS=0 \
    -DENABLE_TOOLS=0

ninja -C build aom

$CXX $CXXFLAGS -std=c++17 \
    -I. -Ibuild \
    examples/av1_dec_fuzzer.cc \
    build/libaom.a \
    $LIB_FUZZING_ENGINE \
    -o /out/libaom-av1_dec_fuzzer.wasm
