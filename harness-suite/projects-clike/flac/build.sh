#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

# Configured like Chromium's third_party/flac/BUILD.gn: plain source build, no
# Ogg, overflow detection on. The source list is every src/libFLAC/*.c at HEAD
# except the ogg_* files; the intrinsics files compile to nothing on wasm32.
# -DNDEBUG like both Chromium release builds and upstream's configure (and so
# oss-fuzz): FLAC__ASSERTs are API-misuse checks the harness trips on purpose.
# HAVE_FSEEKO (wasi-libc has fseeko/ftello; configure/cmake detect it too):
# since bitreader.h's #include <stdio.h> sits after share/compat.h at HEAD,
# compat.h's "#define fseeko fseek" fallback would clash with stdio.h.
DEFS="-DNDEBUG -DHAVE_FSEEKO -DFLAC__NO_DLL -DFLAC__OVERFLOW_DETECT -DFLAC__HAS_OGG=0 -DPACKAGE_VERSION=\"1.5.0\" -DHAVE_LROUND -DHAVE_INTTYPES_H -DFLAC__NO_ASM"
INCS="-Iinclude -Isrc/libFLAC/include -Ioss-fuzz"

LIBFLAC_SRCS="bitmath bitreader bitwriter cpu crc fixed fixed_intrin_avx2 fixed_intrin_sse2
  fixed_intrin_sse42 fixed_intrin_ssse3
  float format lpc lpc_intrin_avx2 lpc_intrin_fma lpc_intrin_neon lpc_intrin_sse2
  lpc_intrin_sse41 md5 memory metadata_iterators metadata_object
  stream_decoder stream_encoder stream_encoder_framing stream_encoder_intrin_avx2
  stream_encoder_intrin_sse2 stream_encoder_intrin_ssse3 window"

mkdir -p build
objs=()
for s in $LIBFLAC_SRCS; do
  $CC $CFLAGS $DEFS $INCS -c src/libFLAC/$s.c -o build/$s.o
  objs+=(build/$s.o)
done
# libFLAC++ is only needed by the upstream C++ harness (Chromium uses the C API).
for s in metadata stream_decoder; do
  $CXX $CXXFLAGS $DEFS $INCS -c src/libFLAC++/$s.cpp -o build/pp_$s.o
  objs+=(build/pp_$s.o)
done
llvm-ar rcs build/libflac.a "${objs[@]}"

# common.h defines the alloc_check_* globals used by share/alloc.h.
$CXX $CXXFLAGS -std=c++17 $DEFS $INCS oss-fuzz/decoder.cc build/libflac.a \
  $LIB_FUZZING_ENGINE -o /out/flac-decoder.wasm
$CXX $CXXFLAGS -std=c++17 $DEFS $INCS oss-fuzz/seek.cc build/libflac.a \
  $LIB_FUZZING_ENGINE -o /out/flac-seek.wasm
