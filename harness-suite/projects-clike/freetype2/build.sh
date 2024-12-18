#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/freetype"

./autogen.sh
./configure $CONFIGUREFLAGS --enable-static --disable-shared
make -j8

cd "$PROJECT/libarchive"

cmake . -DWASI_SDK_PREFIX="${WASI_SDK_PREFIX}" \
    -DBUILD_SHARED_LIBS=OFF \
    -DENABLE_WERROR=OFF \
    -DDONT_FAIL_ON_CRC_ERROR=1
make -j8 archive_static

cd "$PROJECT/freetype2-testing"

$CXX $CXXFLAGS -std=c++11 \
    -I "$PROJECT/libarchive/libarchive/" -I "$PROJECT/freetype/include/" \
    ./fuzzing/src/legacy/ftfuzzer.cc \
    -o /out/freetype2-ftfuzzer.wasm \
    $LIB_FUZZING_ENGINE -lz \
    "$PROJECT/freetype/objs/.libs/libfreetype.a" \
    "$PROJECT/libarchive/libarchive/libarchive.a"
