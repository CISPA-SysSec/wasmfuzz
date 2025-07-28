#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"
export SRC="$PROJECT/repo"


##################################################################


./configure $CONFIGUREFLAGS
make -j7

$CC $CFLAGS -I. ../zlib_uncompress_fuzzer.c \
    -o /out/zlib-uncompress.wasm \
    $LIB_FUZZING_ENGINE ./libz.a
