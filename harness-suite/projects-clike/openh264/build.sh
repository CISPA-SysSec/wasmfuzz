#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

# Generic C++ only (no X86_ASM/HAVE_NEON), mirroring the decoder source set in
# Chromium's third_party/openh264/BUILD.gn. Threaded decoding is never enabled
# by the harness (DECODER_OPTION_NUM_OF_THREADS stays 0); the thread library is
# only compiled against wasi-libc's single-threaded pthread stubs.
# No -DNDEBUG: like oss-fuzz (BUILDTYPE=Debug), assertions stay enabled.
INCS="-Icodec/api/wels -Icodec/common/inc -Icodec/decoder/core/inc -Icodec/decoder/plus/inc -Icodec/console/common/inc"
DEFS="-D_WASI_EMULATED_SIGNAL"

mkdir -p build
objs=()
for f in codec/common/src/*.cpp codec/decoder/core/src/*.cpp codec/decoder/plus/src/*.cpp; do
  o=build/$(basename "$f" .cpp).o
  $CXX $CXXFLAGS $DEFS $INCS -c "$f" -o "$o"
  objs+=("$o")
done
llvm-ar rcs build/libopenh264dec.a "${objs[@]}"

# Harness from oss-fuzz/projects/openh264/decoder_fuzzer.cpp
$CXX $CXXFLAGS $DEFS $INCS "$PROJECT/decoder_fuzzer.cpp" build/libopenh264dec.a \
  $LIB_FUZZING_ENGINE -o /out/openh264-decoder_fuzzer.wasm
