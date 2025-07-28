#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/zlib"
./configure $CONFIGUREFLAGS
make -j7 install prefix=/wasi-sdk/share/wasi-sysroot/ libdir=/wasi-sdk/share/wasi-sysroot/lib/wasm32-wasi/
echo "int main(void){return 0;}" > empty.c
$CC -lz empty.c

cd "$PROJECT/freetype"
./autogen.sh
./configure $CONFIGUREFLAGS --enable-static --disable-shared
make -j8

# Note: The configure step here is very slow. Is it building optimized binaries for every include test?
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
