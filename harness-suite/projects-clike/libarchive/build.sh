#!/bin/bash
set -e +x
source set-buildflags.sh


# Note: LTO support is somewhat broken as of wasi-sdk 25. Linking fails with a
# missing __libc_calloc symbol error for this particular target.
export CFLAGS="${CFLAGS/-flto=thin /}"

cd "$PROJECT/libxml2"

export V=1

./autogen.sh \
    --disable-shared \
    --without-debug \
    --without-threads \
    --without-http \
    --without-python \
    --without-zlib --without-lzma \
    --host=wasm32-wasi
make -j$(nproc)
cp .libs/libxml2.a /tmp/


cd "$PROJECT/libarchive"


cmake . -DWASI_SDK_PREFIX="${WASI_SDK_PREFIX}" \
    -DBUILD_SHARED_LIBS=OFF \
    -DENABLE_WERROR=OFF \
    -DDONT_FAIL_ON_CRC_ERROR=1

make -j$(nproc) archive_static

$CXX $CXXFLAGS -Ilibarchive \
    ./contrib/oss-fuzz/libarchive_fuzzer.cc -o /out/libarchive-upstream.wasm \
    $LIB_FUZZING_ENGINE \
    ./libarchive/libarchive.a /tmp/libxml2.a


$CXX $CXXFLAGS -Ilibarchive \
    "$PROJECT/libarchive_fuzzer.cc" -o /out/libarchive-ossfuzz.wasm \
    $LIB_FUZZING_ENGINE \
    ./libarchive/libarchive.a /tmp/libxml2.a
