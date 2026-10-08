#!/bin/bash
set -e +x
source set-buildflags.sh

B="$PROJECT/build"
rm -rf "$B"; mkdir -p "$B"

# zlib (WOFF 1.0 decompression)
cd "$PROJECT/zlib"
for f in adler32 crc32 inffast inflate inftrees uncompr zutil; do
  $CC $CFLAGS -c $f.c -o "$B/z_$f.o"
done

# brotli decoder (needed by woff2)
cd "$PROJECT/brotli"
for f in c/common/*.c c/dec/*.c; do
  $CC $CFLAGS -Ic/include -c "$f" -o "$B/br_$(basename "${f%.c}")_$(basename "$(dirname "$f")").o"
done

# woff2 decoder
cd "$PROJECT/woff2"
for f in table_tags variable_length woff2_common woff2_dec woff2_out; do
  $CXX $CXXFLAGS -std=c++11 -Iinclude -I"$PROJECT/brotli/c/include" -c src/$f.cc -o "$B/woff2_$f.o"
done

# lz4 (Graphite table decompression)
$CC $CFLAGS -c "$PROJECT/lz4/lib/lz4.c" -o "$B/lz4.o"

# OTS, configured like Firefox gfx/ots/src/moz.build:
#   OTS_GRAPHITE, OTS_SYNTHESIZE_MISSING_GVAR; no OTS_COLR_CYCLE_CHECK.
cd "$PROJECT/repo"
OTS_FLAGS="-std=c++11 -Iinclude -Isrc -I$PROJECT/woff2/include -I$PROJECT/zlib -I$PROJECT/lz4/lib \
  -DOTS_GRAPHITE=1 -DOTS_SYNTHESIZE_MISSING_GVAR=1 -DOTS_FUZZER_NO_MAIN"
for f in src/*.cc; do
  $CXX $CXXFLAGS $OTS_FLAGS -c "$f" -o "$B/ots_$(basename "${f%.cc}").o"
done

# upstream libFuzzer entry point (util/ots-fuzzer.cc, same as oss-fuzz's ots-fuzzer)
$CXX $CXXFLAGS $OTS_FLAGS util/ots-fuzzer.cc "$B"/*.o \
    $LIB_FUZZING_ENGINE \
    -o /out/ots-sanitize_fuzzer.wasm
