#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

##################################################################
# Manual build mirroring BUILD.gn's "zlib" component as configured for
# x64/arm64 Chromium, minus the parts that need SIMD intrinsics:
#  - contrib/optimizations/{inflate.c,inffast_chunk.c} (Chromium's chunk-copy
#    inflate) instead of the stock inflate.c, using the portable
#    INFLATE_CHUNK_GENERIC chunk type (memcpy-based 16-byte chunks, the same
#    variant Chromium's CMake uses for RISC-V) instead of SSE2/NEON.
#  - INFLATE_CHUNK_READ_64LE, DEFLATE_CHUNK_WRITE_64LE, DEFLATE_COMPARE256_64LE:
#    plain-C 64-bit little-endian paths enabled on x64/arm64; wasm is LE and
#    has native i64, so they're enabled here too.
#  - CPU_NO_SIMD: adler32/crc32/slide_hash SIMD are compiled out; the generic
#    C fallbacks are what gets fuzzed.
#  - ZLIB_DEBUG: BUILD.gn enables zlib's internal asserts for fuzzer builds.
DEFS="-DZLIB_IMPLEMENTATION -DZLIB_DEBUG -DCPU_NO_SIMD \
  -DINFLATE_CHUNK_GENERIC -DINFLATE_CHUNK_READ_64LE \
  -DDEFLATE_CHUNK_WRITE_64LE -DDEFLATE_COMPARE256_64LE"
WARN="-Wno-incompatible-pointer-types -Wno-deprecated-non-prototype -Wno-parentheses-equality"

ZLIB_SRCS="adler32.c compress.c cpu_features.c crc32.c deflate.c gzclose.c \
  gzlib.c gzread.c gzwrite.c infback.c inffast.c inftrees.c trees.c uncompr.c \
  zutil.c contrib/optimizations/inflate.c contrib/optimizations/inffast_chunk.c"
# zip.c (writer) is omitted: its skipset.h uses setjmp/longjmp; the unzip fuzzer
# only needs the reader.
MINIZIP_SRCS="contrib/minizip/ioapi.c contrib/minizip/unzip.c"

mkdir -p build
OBJS=""
for src in $ZLIB_SRCS; do
  obj="build/$(echo "$src" | tr / _).o"
  $CC $CFLAGS -O3 $DEFS $WARN -I. -Icontrib/optimizations -c "$src" -o "$obj"
  OBJS="$OBJS $obj"
done
rm -f build/libchromium_zlib.a
llvm-ar rcs build/libchromium_zlib.a $OBJS

MZ_OBJS=""
for src in $MINIZIP_SRCS; do
  obj="build/$(echo "$src" | tr / _).o"
  $CC $CFLAGS -DUSE_FILE32API -DNOCRYPT $WARN -I. -Icontrib/minizip -c "$src" -o "$obj"
  MZ_OBJS="$MZ_OBJS $obj"
done
rm -f build/libminizip.a
llvm-ar rcs build/libminizip.a $MZ_OBJS

$CXX $CXXFLAGS -I"$PROJECT/include" -I. -c google/compression_utils_portable.cc -o build/compression_utils_portable.o

# FuzzedDataProvider.h is vendored in ../include (wasi-sdk does not ship it).
# Upstream in-tree fuzzers (contrib/tests/fuzzers/BUILD.gn).
for f in uncompress inflate inflate_with_header streaming_inflate \
         deflate_set_dictionary compress deflate; do
  $CXX $CXXFLAGS -I"$PROJECT/include" -I. contrib/tests/fuzzers/${f}_fuzzer.cc \
    -o /out/chromium-zlib-${f}_fuzzer.wasm \
    $LIB_FUZZING_ENGINE build/libchromium_zlib.a
done

$CXX $CXXFLAGS -I"$PROJECT/include" -I. -Icontrib/minizip contrib/tests/fuzzers/minizip_unzip_fuzzer.cc \
  -o /out/chromium-zlib-minizip_unzip_fuzzer.wasm \
  $LIB_FUZZING_ENGINE build/libminizip.a build/libchromium_zlib.a

# Extra harness for google/compression_utils_portable (the base-free core of
# compression::GzipUncompress / zlib_internal::UncompressHelper).
$CXX $CXXFLAGS -I"$PROJECT/include" -I. -Igoogle ../compression_utils_portable_fuzzer.cc \
  -o /out/chromium-zlib-compression_utils_portable_fuzzer.wasm \
  $LIB_FUZZING_ENGINE build/compression_utils_portable.o build/libchromium_zlib.a
