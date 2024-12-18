#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

$CC $CFLAGS -I. -DSTBI_ONLY_PNG  \
    ./tests/stbi_read_fuzzer.c \
    -o /out/stb-png_read_fuzzer.wasm $LIB_FUZZING_ENGINE

$CC $CFLAGS -I. \
    ./tests/stbi_read_fuzzer.c \
    -o /out/stb-stbi_read_fuzzer.wasm $LIB_FUZZING_ENGINE
