#!/bin/bash
set -e +x
source set-buildflags.sh

# NOTE: our wasi-sdk installation includes zlib

cd "$PROJECT/repo/jbigkit"
make lib CC="$CC" CFLAGS="$CFLAGS" -j

cd "$PROJECT/repo/libjpeg-turbo"
cmake . \
    -DWASI_SDK_PREFIX="${WASI_SDK_PREFIX}" \
    -DBUILD_SHARED_LIBS=OFF -DENABLE_SHARED=OFF \
    -DWITH_TURBOJPEG=OFF
make -j
make install

cd "$PROJECT/repo"

cmake . \
    -DWASI_SDK_PREFIX="${WASI_SDK_PREFIX}" \
    -DBUILD_SHARED_LIBS=OFF \
    -Dtiff-tools=OFF -Dtiff-tests=OFF -Dtiff-docs=OFF
make -j


$CXX $CXXFLAGS -std=c++11 -I./libtiff/ \
    contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc \
    libtiff/libtiff.a libtiff/libtiffxx.a \
    jbigkit/libjbig/libjbig.a ./libjpeg-turbo/libjpeg.a \
    $LIB_FUZZING_ENGINE -lz \
    -o /out/libtiff-read_rgba_fuzzer.wasm
