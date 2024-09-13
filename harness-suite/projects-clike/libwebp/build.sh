#!/bin/bash
set -e +x
source set-buildflags.sh


cd "$PROJECT/repo"

# limit allocation size to reduce spurious OOMs
export CFLAGS="$CFLAGS -DWEBP_MAX_IMAGE_SIZE=131072" # 128kB
export CXXFLAGS="$CXXFLAGS -DWEBP_MAX_IMAGE_SIZE=131072" # 128kB

./autogen.sh
./configure \
  --enable-asserts \
  --enable-libwebpdemux \
  --enable-libwebpmux \
  --disable-shared \
  --disable-jpeg \
  --disable-tiff \
  --disable-gif \
  --disable-wic \
  --host=wasm32-wasi
make clean
make -j$(nproc)

webp_libs=(
  src/demux/.libs/libwebpdemux.a
  src/mux/.libs/libwebpmux.a
  src/.libs/libwebp.a
  imageio/.libs/libimageio_util.a
  imageio/.libs/libimagedec.a
  sharpyuv/.libs/libsharpyuv.a
)
webp_c_fuzzers=(
  advanced_api_fuzzer
  advanced_api_fuzzer2
  animation_api_fuzzer
  # NOTE: we're building libwebp before the huffman table oob fix
  # huffman_fuzzer
  mux_demux_api_fuzzer
  simple_api_fuzzer
  dwebp_fuzzer
)
webp_cxx_fuzzers=(
  animdecoder_fuzzer
  animencoder_fuzzer
  enc_dec_fuzzer
)

for fuzzer in "${webp_c_fuzzers[@]}"; do
  $CC $CFLAGS -Isrc -I. "tests/fuzzer/${fuzzer}.c" \
    "${webp_libs[@]}" \
    $LIB_FUZZING_ENGINE \
    -o "/out/libwebp_${fuzzer}.wasm"
done

for fuzzer in "${webp_cxx_fuzzers[@]}"; do
  $CXX $CXXFLAGS -Isrc -I. "tests/fuzzer/${fuzzer}.cc" \
    "${webp_libs[@]}" \
    $LIB_FUZZING_ENGINE \
    -o "/out/libwebp_${fuzzer}.wasm"
done
