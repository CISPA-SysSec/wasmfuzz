#!/bin/bash
set -e +x
source set-buildflags.sh

# Replace <setjmp.h> with a shim that maps longjmp to wasmfuzz exit_testcase.
export CFLAGS="$CFLAGS -I$PROJECT/wasi-include"
export CXXFLAGS="$CXXFLAGS -I$PROJECT/wasi-include"

cd "$PROJECT/repo"
mkdir -p build && cd build

# Mirror browser configuration: no SIMD (wasm), arithmetic coding disabled
# (both Chromium and Firefox leave {C,D}_ARITH_CODING_SUPPORTED undefined).
cmake .. \
    -DCMAKE_TOOLCHAIN_FILE="$CMAKE_TOOLCHAIN_FILE" \
    -DWASI_SDK_PREFIX="$WASI_SDK_PREFIX" \
    -DCMAKE_BUILD_TYPE=None \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DENABLE_SHARED=0 -DENABLE_STATIC=1 \
    -DWITH_SIMD=0 -DREQUIRE_SIMD=0 \
    -DWITH_ARITH_DEC=0 -DWITH_ARITH_ENC=0 \
    -DWITH_TURBOJPEG=1 -DWITH_TOOLS=0 -DWITH_TESTS=0 -DWITH_FUZZ=0
make -j"$(nproc)" jpeg-static turbojpeg-static

INC="-I.. -I../src -I. -Isrc"

# TurboJPEG-API fuzzers (decompress first; browsers only decode)
for f in decompress decompress_yuv transform compress compress_yuv \
         compress_lossless compress12 compress12_lossless compress16_lossless; do
    $CXX $CXXFLAGS $INC ../fuzz/$f.cc libturbojpeg.a \
        $LIB_FUZZING_ENGINE -o /out/libjpeg-turbo-${f}_fuzzer.wasm
done

# libjpeg-API decompress fuzzer (closest to how Chromium/Firefox use the library)
$CXX $CXXFLAGS $INC ../fuzz/decompress_libjpeg.cc libjpeg.a \
    $LIB_FUZZING_ENGINE -o /out/libjpeg-turbo-decompress_libjpeg_fuzzer.wasm

# cjpeg (BMP/GIF/PPM/Targa readers + compressor)
CDJPEG_SRCS="../src/cdjpeg.c ../src/rdbmp.c ../src/rdgif.c ../src/wrapper/rdppm-8.c \
    ../src/wrapper/rdppm-12.c ../src/wrapper/rdppm-16.c ../src/rdswitch.c ../src/rdtarga.c"
CDJPEG_OBJS=""
for s in $CDJPEG_SRCS; do
    o=cdjpeg_$(basename "$s" .c).o
    $CC $CFLAGS $INC -DBMP_SUPPORTED -DGIF_SUPPORTED -DPPM_SUPPORTED -DTARGA_SUPPORTED \
        -c "$s" -o "$o"
    CDJPEG_OBJS="$CDJPEG_OBJS $o"
done
$CXX $CXXFLAGS $INC -DBMP_SUPPORTED -DGIF_SUPPORTED -DPPM_SUPPORTED -DTARGA_SUPPORTED \
    ../fuzz/cjpeg.cc $CDJPEG_OBJS libjpeg.a \
    $LIB_FUZZING_ENGINE -o /out/libjpeg-turbo-cjpeg_fuzzer.wasm
