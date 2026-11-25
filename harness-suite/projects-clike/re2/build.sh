#!/bin/bash
set -e +x
source set-buildflags.sh

# abseil's debugging/ code includes <csignal> and <sys/mman.h>
export CFLAGS="$CFLAGS -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_MMAN"
export CXXFLAGS="$CXXFLAGS -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_MMAN"

common=(
  -DCMAKE_TOOLCHAIN_FILE="$CMAKE_TOOLCHAIN_FILE"
  -DWASI_SDK_PREFIX="$WASI_SDK_PREFIX"
  -DCMAKE_BUILD_TYPE=None
  -DCMAKE_C_FLAGS="$CFLAGS"
  -DCMAKE_CXX_FLAGS="$CXXFLAGS"
  -DCMAKE_INSTALL_PREFIX="$PROJECT/install"
  -DBUILD_SHARED_LIBS=OFF
  -DBUILD_TESTING=OFF
)

cmake -S "$PROJECT/abseil" -B "$PROJECT/abseil/build" "${common[@]}" \
    -DCMAKE_CXX_STANDARD=17 -DABSL_PROPAGATE_CXX_STD=ON -DABSL_BUILD_TESTING=OFF
cmake --build "$PROJECT/abseil/build" -j"$(nproc)" --target install

cmake -S "$PROJECT/repo" -B "$PROJECT/repo/build" "${common[@]}" \
    -DCMAKE_PREFIX_PATH="$PROJECT/install" -DRE2_BUILD_TESTING=OFF
cmake --build "$PROJECT/repo/build" -j"$(nproc)" --target re2

# FuzzBench re2_fuzzer: its own target.cc (not upstream's re2/fuzzing/re2_fuzzer.cc)
$CXX $CXXFLAGS -std=c++17 -I"$PROJECT/repo" -I"$PROJECT/install/include" \
    "$PROJECT/fuzzbench_target.cc" "$PROJECT/repo/build/libre2.a" \
    $(ls "$PROJECT"/install/lib/libabsl_*.a | sort) \
    -lwasi-emulated-signal -lwasi-emulated-mman \
    $LIB_FUZZING_ENGINE -o /out/re2-fuzzer.wasm
