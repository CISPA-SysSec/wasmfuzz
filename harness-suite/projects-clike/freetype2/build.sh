#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/zlib"
./configure $CONFIGUREFLAGS
make -j7 install prefix=/wasi-sdk/share/wasi-sysroot/ libdir=/wasi-sdk/share/wasi-sysroot/lib/wasm32-wasip1/
echo "int main(void){return 0;}" > empty.c
$CC -lz empty.c

cd "$PROJECT/freetype"
./autogen.sh
# Disable HarfBuzz (and other optional deps) so configure doesn't auto-enable
# FT_CONFIG_OPTION_USE_HARFBUZZ_DYNAMIC via wasi-libc's weak `dlopen` stub.
# Without this, af_autofitter_init() ends up calling dlopen()/dlsym() which
# resolve to wasi-libc's `undefined_stub` (an `unreachable` instruction) at
# runtime and crash the harness on the first input.
./configure $CONFIGUREFLAGS --enable-static --disable-shared \
    --with-harfbuzz=no --with-brotli=no --with-png=no --with-bzip2=no
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
