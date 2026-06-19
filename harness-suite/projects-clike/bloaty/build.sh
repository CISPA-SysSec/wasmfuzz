#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

export CFLAGS="$CFLAGS -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_MMAN"
export CXXFLAGS="${CXXFLAGS//-fno-exceptions/} -fexceptions -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_MMAN"
export LDFLAGS="$LDFLAGS -lwasi-emulated-signal -lwasi-emulated-mman"

cmake_args=(
  -DWASI_SDK_PREFIX="${WASI_SDK_PREFIX}"
  -DBUILD_SHARED_LIBS=OFF
  -DBUILD_TESTING=OFF
  -Dprotobuf_BUILD_PROTOC_BINARIES=OFF
  -DZLIB_BUILD_TESTING=OFF
  -DZLIB_BUILD_SHARED=OFF
  -DCMAKE_C_FLAGS="${CFLAGS}"
  -DCMAKE_CXX_FLAGS="${CXXFLAGS}"
  -DCMAKE_LD_FLAGS="${LDFLAGS}"
)

mkdir -p build
cd build
cmake ../ "${cmake_args[@]}"
make -j"$(nproc)" fuzz_target

cp fuzz_target /out/bloaty-fuzz_target.wasm
