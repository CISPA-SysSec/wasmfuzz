#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

# Mirrors oss-fuzz/projects/libvpx/build.sh (decoder only) with Chromium's
# feature set (vp9 highbitdepth, postproc). No asm, no threads for wasm.
# Per-allocation limit keeps us well inside the 4GB wasm32 address space.
extra_c_flags="-DVPX_MAX_ALLOCABLE_MEMORY=268435456 -DFUZZER_DISABLE_NALLOC"

mkdir -p build
cd build
CROSS= LD="$CXX" LDFLAGS="$CXXFLAGS" ../configure \
    --target=generic-gnu \
    --disable-multithread \
    --disable-runtime-cpu-detect \
    --enable-vp9-highbitdepth \
    --enable-postproc \
    --disable-vp8-encoder \
    --disable-vp9-encoder \
    --disable-unit-tests \
    --disable-examples \
    --disable-tools \
    --disable-docs \
    --disable-libyuv \
    --disable-webm-io \
    --disable-shared \
    --enable-static \
    --enable-debug \
    --size-limit=12288x12288 \
    --extra-cflags="$CFLAGS $extra_c_flags" \
    --extra-cxxflags="$CXXFLAGS $extra_c_flags"
make -j$(nproc) libvpx.a
cd ..

for decoder in vp8 vp9; do
  $CXX $CXXFLAGS -std=gnu++17 $extra_c_flags \
    -DDECODER=${decoder} \
    -I. -Ibuild \
    examples/vpx_dec_fuzzer.cc \
    build/libvpx.a \
    $LIB_FUZZING_ENGINE \
    -o /out/libvpx-dec-${decoder}.wasm
done
