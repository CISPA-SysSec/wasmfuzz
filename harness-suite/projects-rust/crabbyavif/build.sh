#!/bin/bash
set -e +x
source set-buildflags.sh

# dav1d (C), built like projects-clike/dav1d: no asm, no threads. Placed where
# sys/dav1d-sys/build.rs looks for a local build (dav1d/build/src/libdav1d.a).
cd "$PROJECT/repo/sys/dav1d-sys/dav1d"
meson setup build \
    --cross-file "$PROJECT/wasi-lime1.cross" \
    --buildtype release \
    -Ddefault_library=static \
    -Denable_asm=false \
    -Denable_tools=false \
    -Denable_examples=false \
    -Denable_tests=false \
    -Denable_docs=false \
    -Dtestdata_tests=false \
    -Dfuzzing_engine=none \
    -Dc_args="$CFLAGS" \
    -Dc_link_args="$CFLAGS"
ninja -C build

# libyuv (C++), placed where sys/libyuv-sys/build.rs looks (libyuv/build/libyuv.a).
cd "$PROJECT/repo/sys/libyuv-sys/libyuv"
cmake -G Ninja -B build \
    -DCMAKE_TOOLCHAIN_FILE="$CMAKE_TOOLCHAIN_FILE" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS"
ninja -C build yuv

# bindgen (dav1d-sys / libyuv-sys build scripts) parses the C headers for the
# wasm32-wasip1 target; point libclang at the wasi sysroot. clang defaults to
# hidden visibility on wasm, which makes bindgen silently drop all functions.
export LIBCLANG_PATH=/usr/lib/llvm-18/lib
export BINDGEN_EXTRA_CLANG_ARGS="--sysroot=/wasi-sdk/share/wasi-sysroot -fvisibility=default"

build-rust-harness.py
