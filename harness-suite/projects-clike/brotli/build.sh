#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

cmake . \
    -DWASI_SDK_PREFIX="${WASI_SDK_PREFIX}" \
    -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF

make clean
make brotlicommon brotlidec

# build brotli_decode_fuzzer
$CC $CFLAGS -std=c99 -I. -I./c/include \
    c/fuzz/decode_fuzzer.c ./libbrotlidec.a ./libbrotlicommon.a \
    $LIB_FUZZING_ENGINE \
    -o /out/brotli_decode_fuzzer.wasm
