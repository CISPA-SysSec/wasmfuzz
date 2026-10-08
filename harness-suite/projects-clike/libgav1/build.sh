#!/bin/bash
set -e +x
source set-buildflags.sh

# Mirror Chromium's //third_party/libgav1:libgav1_public_config:
#  - LIBGAV1_MAX_BITDEPTH=10, std::mutex thread pool (no abseil), no logging
#  - CHROMIUM: downgrades the OBU extension flag check to a warning
GAV1_DEFINES="-DCHROMIUM -DLIBGAV1_ENABLE_LOGGING=0 -DLIBGAV1_EXAMPLES_ENABLE_LOGGING=0"
export CFLAGS="$CFLAGS $GAV1_DEFINES"
export CXXFLAGS="$CXXFLAGS $GAV1_DEFINES"

cd "$PROJECT/repo"
# Generic C++ dsp paths only (no SSE4.1/AVX2/NEON), like Chromium's fuzzer config.
cmake -S . -B build \
    -DCMAKE_TOOLCHAIN_FILE="${CMAKE_TOOLCHAIN_FILE}" \
    -DWASI_SDK_PREFIX="${WASI_SDK_PREFIX}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS_RELEASE="" \
    -DCMAKE_CXX_FLAGS_RELEASE="" \
    -DLIBGAV1_ENABLE_OPTIMIZATIONS=0 \
    -DLIBGAV1_ENABLE_EXAMPLES=0 \
    -DLIBGAV1_ENABLE_TESTS=0 \
    -DLIBGAV1_THREADPOOL_USE_STD_MUTEX=1 \
    -DLIBGAV1_MAX_BITDEPTH=10
make -C build -j"$(nproc)" libgav1_static

EXAMPLE_SRCS=(
    examples/file_reader.cc
    examples/file_reader_constants.cc
    examples/file_reader_factory.cc
    examples/ivf_parser.cc
)

# decoder_fuzzer_frame_parallel is skipped: it requires a frame thread pool
# (threads > 32), which cannot exist on wasm32-wasip1.
for fuzzer in obu_parser decoder; do
    $CXX $CXXFLAGS -std=c++17 -DLIBGAV1_MAX_BITDEPTH=10 -I. -Isrc \
        "tests/fuzzer/${fuzzer}_fuzzer.cc" \
        "${EXAMPLE_SRCS[@]}" \
        build/libgav1.a \
        $LIB_FUZZING_ENGINE \
        -o "/out/libgav1-${fuzzer}.wasm"
done
