#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

# Chromium and Firefox build both float (desktop) and fixed-point (mobile)
# variants, neither enables QEXT/DRED/deep-PLC/OSCE.
for build in float fixed; do
  case "$build" in
    float) extra_args="" ;;
    fixed) extra_args="--enable-fixed-point" ;;
  esac
  rm -rf "build-$build" && mkdir "build-$build" && cd "build-$build"
  ../configure $CONFIGUREFLAGS $extra_args --enable-static --disable-shared \
    --disable-doc --disable-extra-programs --enable-assertions \
    --disable-asm --disable-rtcd --disable-intrinsics
  make -j$(nproc)
  cd ..

  $CC $CFLAGS -Iinclude tests/opus_decode_fuzzer.c \
    -o /out/opus-decode_fuzzer_$build.wasm \
    $LIB_FUZZING_ENGINE build-$build/.libs/libopus.a
  for fuzzer in opus_multistream_decode_fuzzer opus_projection_decoder_fuzzer; do
    $CXX $CXXFLAGS -Iinclude -I"$PROJECT/include" tests/$fuzzer.cc \
      -o /out/opus-${fuzzer#opus_}_$build.wasm \
      $LIB_FUZZING_ENGINE build-$build/.libs/libopus.a
  done
done

# The repacketizer does not depend on the sample type.
$CXX $CXXFLAGS -Iinclude -I"$PROJECT/include" tests/opus_repacketizer_fuzzer.cc \
  -o /out/opus-repacketizer_fuzzer.wasm \
  $LIB_FUZZING_ENGINE build-float/.libs/libopus.a
