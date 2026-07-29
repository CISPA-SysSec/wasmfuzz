#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

meson setup build \
    --cross-file "$PROJECT/wasi-lime1.cross" \
    -Ddefault_library=static \
    -Denable_asm=false \
    -Denable_tools=false \
    -Denable_examples=false \
    -Denable_tests=false \
    -Denable_docs=false \
    -Dtestdata_tests=false \
    -Dfuzzing_engine=none \
    -Dc_args="$CFLAGS" \
    -Dc_link_args="$CFLAGS" \
    -Dcpp_args="$CXXFLAGS" \
    -Dcpp_link_args="$CXXFLAGS"

ninja -C build

$CC $CFLAGS \
    -I. -Iinclude -Iinclude/dav2d -Ibuild \
    tests/libfuzzer/dav2d_fuzzer.c \
    build/src/libdav2d.a \
    $LIB_FUZZING_ENGINE \
    -o /out/dav2d-decode.wasm
