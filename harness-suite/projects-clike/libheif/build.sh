#!/bin/bash
set -e +x
source set-buildflags.sh

# libde265 (and some other codec deps) include <signal.h>.
export CFLAGS="$CFLAGS -D_WASI_EMULATED_SIGNAL"
export CXXFLAGS="$CXXFLAGS -D_WASI_EMULATED_SIGNAL"

DEPS_PATH="$PROJECT/deps"
mkdir -p "$DEPS_PATH"

cd "$PROJECT/zlib"
./configure $CONFIGUREFLAGS
make -j"$(nproc)" install \
    prefix=/wasi-sdk/share/wasi-sysroot/ \
    libdir=/wasi-sdk/share/wasi-sysroot/lib/wasm32-wasip1/

echo "=== Building libde265 ==="
cd "$PROJECT/libde265"
cmake -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="${CMAKE_TOOLCHAIN_FILE}" \
    -DWASI_SDK_PREFIX="${WASI_SDK_PREFIX}" \
    -DCMAKE_INSTALL_PREFIX="$DEPS_PATH" \
    -DBUILD_SHARED_LIBS=OFF \
    -DENABLE_DECODER=OFF \
    -DENABLE_ENCODER=OFF \
    -DENABLE_SDL=OFF \
    -DENABLE_SHERLOCK265=OFF \
    .
ninja
ninja install

echo "=== Building libwebp sharpyuv ==="
mkdir -p "$PROJECT/libwebp/build"
cd "$PROJECT/libwebp/build"
cmake -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="${CMAKE_TOOLCHAIN_FILE}" \
    -DWASI_SDK_PREFIX="${WASI_SDK_PREFIX}" \
    -DCMAKE_INSTALL_PREFIX="$DEPS_PATH" \
    -DBUILD_SHARED_LIBS=OFF \
    ..
ninja sharpyuv
mkdir -p "$DEPS_PATH/lib/pkgconfig" "$DEPS_PATH/include"
cp libsharpyuv.a "$DEPS_PATH/lib/"
cp ../sharpyuv/sharpyuv.h "$DEPS_PATH/include/"
cat > "$DEPS_PATH/lib/pkgconfig/libsharpyuv.pc" <<EOF
prefix=$DEPS_PATH
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: libsharpyuv
Description: libwebp sharpyuv
Version: 1.0.0
Libs: -L\${libdir} -lsharpyuv
Cflags: -I\${includedir}
EOF

echo "=== Building libheif ==="
mkdir -p "$PROJECT/repo/build"
cd "$PROJECT/repo/build"
export PKG_CONFIG_PATH="$DEPS_PATH/lib/pkgconfig:$DEPS_PATH/lib/wasm32-wasip1/pkgconfig"
# libheif's C++ API uses exceptions; drop the harness-wide -fno-exceptions flag.
saved_cxxflags="$CXXFLAGS"
export CXXFLAGS="${CXXFLAGS//-fno-exceptions/}"
PKG_CONFIG="pkg-config --static" cmake -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="${CMAKE_TOOLCHAIN_FILE}" \
    -DWASI_SDK_PREFIX="${WASI_SDK_PREFIX}" \
    -DCMAKE_INSTALL_PREFIX="$DEPS_PATH" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTING=OFF \
    -DENABLE_PLUGIN_LOADING=OFF \
    -DENABLE_MULTITHREADING_SUPPORT=OFF \
    -DENABLE_EXPERIMENTAL_FEATURES=ON \
    -DCMAKE_COMPILE_WARNING_AS_ERROR=OFF \
    -DWITH_FUZZERS=OFF \
    -DWITH_EXAMPLES=OFF \
    -DWITH_LIBDE265=ON \
    -DWITH_AOM_DECODER=OFF \
    -DWITH_AOM_ENCODER=OFF \
    -DWITH_X265=OFF \
    -DWITH_DAV1D=OFF \
    -DWITH_RAV1E=OFF \
    -DWITH_SvtEnc=OFF \
    -DWITH_JPEG_DECODER=OFF \
    -DWITH_JPEG_ENCODER=OFF \
    -DWITH_KVAZAAR=OFF \
    -DWITH_OpenJPEG_DECODER=OFF \
    -DWITH_OpenJPEG_ENCODER=OFF \
    -DWITH_OPENJPH_ENCODER=OFF \
    -DWITH_FFMPEG_DECODER=OFF \
    -DWITH_OpenH264_DECODER=OFF \
    -DWITH_UVG266=OFF \
    -DWITH_VVDEC=OFF \
    -DWITH_VVENC=OFF \
    -DWITH_X264=OFF \
    -DWITH_LIBSHARPYUV=ON \
    -DWITH_UNCOMPRESSED_CODEC=ON \
    -DWITH_HEADER_COMPRESSION=ON \
    -DWITH_REDUCED_VISIBILITY=OFF \
    ..
ninja heif

HEIF_INCLUDES=(
    -I"$PROJECT/repo/libheif"
    -I"$PROJECT/repo/libheif/api"
    -I"$PROJECT/repo/build"
    -I"$DEPS_PATH/include"
)
HEIF_LIBS=(
    "$PROJECT/repo/build/libheif/libheif.a"
    "$DEPS_PATH/lib/libde265.a"
    "$DEPS_PATH/lib/libsharpyuv.a"
    -lz
    -lwasi-emulated-signal
)

libheif_fuzzers=(
    box
    file
    api
    color_conversion
    tile
)

for fuzzer in "${libheif_fuzzers[@]}"; do
    $CXX $CXXFLAGS -std=c++20 "${HEIF_INCLUDES[@]}" \
        "$PROJECT/repo/fuzzing/${fuzzer}_fuzzer.cc" \
        "${HEIF_LIBS[@]}" \
        $LIB_FUZZING_ENGINE \
        -o "/out/libheif-${fuzzer}.wasm"
done

export CXXFLAGS="$saved_cxxflags"
