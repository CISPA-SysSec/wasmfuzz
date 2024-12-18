#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"
export SRC="$PROJECT/repo"


##################################################################


./configure \
	--enable-shared=no \
	--with-wasi-sdk="$WASI_SDK_PREFIX" \
	$CONFIGUREFLAGS

make -j"$(nproc)"

$CC $CFLAGS -I. ../zlib_uncompress_fuzzer.c \
    -o /out/zlib-uncompress.wasm \
    $LIB_FUZZING_ENGINE ./libz.a
