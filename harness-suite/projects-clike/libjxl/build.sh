#!/bin/bash
set -e +x
source set-buildflags.sh

cd "$PROJECT/repo"

# libjxl uses C++ exceptions in some code paths.
saved_cxxflags="$CXXFLAGS"
export CXXFLAGS="${CXXFLAGS//-fno-exceptions/} -DJXL_IS_DEBUG_BUILD=1"

build_args=(
  -G Ninja
  -DCMAKE_TOOLCHAIN_FILE="${CMAKE_TOOLCHAIN_FILE}"
  -DWASI_SDK_PREFIX="${WASI_SDK_PREFIX}"
  -DBUILD_TESTING=OFF
  -DBUILD_SHARED_LIBS=OFF
  -DJPEGXL_ENABLE_BENCHMARK=OFF
  -DJPEGXL_ENABLE_DEVTOOLS=OFF
  -DJPEGXL_ENABLE_EXAMPLES=OFF
  -DJPEGXL_ENABLE_FUZZERS=ON
  -DJPEGXL_ENABLE_MANPAGES=OFF
  -DJPEGXL_ENABLE_SJPEG=OFF
  -DJPEGXL_ENABLE_VIEWERS=OFF
  -DJPEGXL_ENABLE_TOOLS=ON
  -DJPEGXL_ENABLE_OPENEXR=OFF
  -DJPEGXL_ENABLE_JNI=OFF
  -DJPEGXL_ENABLE_TCMALLOC=OFF
  -DJPEGXL_ENABLE_WASM_THREADS=OFF
  -DJPEGXL_ENABLE_LTO=OFF
  -DCMAKE_BUILD_TYPE=Release
)

# Disable native SIMD backends not available on WASI; keep portable targets.
for tgt in AVX2 AVX3 AVX3_DL AVX3_SPR AVX3_ZEN4 NEON NEON_BF16 NEON_WITHOUT_AES PPC10 PPC8 PPC9 RVV SSE2 SSE4 SSSE3 SVE SVE_256 SVE2 SVE2_128 Z14 Z15; do
  build_args+=(-DJPEGXL_ENABLE_HWY_${tgt}=OFF)
done

mkdir -p build
cd build
cmake .. "${build_args[@]}" \
  -DJPEGXL_FUZZER_LINK_FLAGS="${LIB_FUZZING_ENGINE}"

fuzzers=(
  cjxl_fuzzer
  color_encoding_fuzzer
  decode_basic_info_fuzzer
  djxl_fuzzer
  fields_fuzzer
  icc_codec_fuzzer
  rans_fuzzer
  set_from_bytes_fuzzer
  streaming_fuzzer
  transforms_fuzzer
)

ninja "${fuzzers[@]}"

for fuzzer in "${fuzzers[@]}"; do
  cp "tools/${fuzzer}" "/out/libjxl-${fuzzer}.wasm"
done

export CXXFLAGS="$saved_cxxflags"
