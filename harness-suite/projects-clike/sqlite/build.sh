#!/bin/bash
set -e +x
# source set-buildflags.sh

cd "$PROJECT/repo"
export SRC="$PROJECT/repo"


export CC=clang CXX=clang++
export CFLAGS="-g -gdwarf-5 -gembed-source -O2 -flto=thin -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"

# Limit max length of data blobs and sql queries to prevent irrelevant OOMs.
# Also limit max memory page count to avoid creating large databases.
export CFLAGS="$CFLAGS -DSQLITE_MAX_LENGTH=125000 \
               -DSQLITE_MAX_SQL_LENGTH=125000 \
               -DSQLITE_MAX_MEMORY=24414 \
               -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
               -DSQLITE_MAX_PAGE_COUNT=16"
# -DSQLITE_DEBUG=1 \

export WASI_SDK_PREFIX="/wasi-sdk/"
./configure \
        --disable-amalgamation \
	--with-wasi-sdk="$WASI_SDK_PREFIX" \
	$CONFIGUREFLAGS
	# --disable-shared \

make -j"$(nproc)"

source set-buildflags.sh
$CC $CFLAGS -I. test/ossfuzz.c \
    -o /out/sqlite-ossfuzz.wasm \
    $LIB_FUZZING_ENGINE libsqlite3.a
